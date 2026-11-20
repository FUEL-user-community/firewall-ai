"""
SharedStateStore — Cross-Generation ACID State Store (Stdlib SQLite WAL).

Lives outside `.slots/a` and `.slots/b` inside `<nucleus_root>/.state/shared/` so:
1. Daily API budget spend (`BudgetGuard`) cannot be reset to $0.00 by reincarnating.
2. Recent investigation traces survive Slot A <-> Slot B cutovers without 404s.
3. Stigmergic Drive board sync cursors remain idempotent across generations.
4. Generation lineage and crash AUTOPSY records form an unbroken audit chain.
"""

import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def resolve_shared_state_dir() -> Path:
    """Resolve `.state/shared` across root workspace or nested `.slots/<a|b>` worktrees."""
    env_dir = os.getenv("NEO_SHARED_STATE_DIR", "").strip()
    if env_dir:
        return Path(env_dir).resolve()

    repo_root = Path(__file__).resolve().parent.parent.parent
    # If running from <nucleus>/.slots/a or <nucleus>/.slots/b, anchor at <nucleus>/.state/shared
    if repo_root.parent.name == ".slots":
        return (repo_root.parent.parent / ".state" / "shared").resolve()
    return (repo_root / ".state" / "shared").resolve()


class SharedStateStore:
    """Thread-safe and process-safe SQLite WAL state store using Python stdlib only."""

    _instance: Optional["SharedStateStore"] = None
    _instance_lock = threading.Lock()

    def __init__(self, state_dir: Optional[Path] = None):
        self.state_dir = Path(state_dir).resolve() if state_dir else resolve_shared_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "nucleus_state.sqlite"
        self.hmac_seed_path = self.state_dir / ".hmac_seed"
        self._lock = threading.RLock()
        self._ensure_hmac_seed()
        self._init_schema()

    @classmethod
    def get_instance(cls) -> "SharedStateStore":
        current_dir = resolve_shared_state_dir()
        if cls._instance is None or cls._instance.state_dir != current_dir:
            with cls._instance_lock:
                if cls._instance is None or cls._instance.state_dir != current_dir:
                    cls._instance = cls(state_dir=current_dir)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        with cls._instance_lock:
            cls._instance = None

    def _ensure_hmac_seed(self) -> None:
        """Create a persistent 256-bit HMAC seed shared by Scrubber and ToxicXmlSanitizer."""
        if not self.hmac_seed_path.exists():
            try:
                self.hmac_seed_path.write_text(secrets.token_hex(32), encoding="utf-8")
            except Exception as e:
                logger.debug(f"[STATE] Could not persist .hmac_seed: {e}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS budget_ledger (
                        day_utc TEXT PRIMARY KEY,
                        daily_cost REAL NOT NULL DEFAULT 0.0,
                        updated_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS recent_investigations (
                        trace_id TEXT PRIMARY KEY,
                        query TEXT NOT NULL,
                        verdict TEXT NOT NULL,
                        receipts_json TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS board_cursor (
                        artifact_id TEXT PRIMARY KEY,
                        filename TEXT NOT NULL,
                        move_type TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        thread_id TEXT NOT NULL,
                        base_sha TEXT NOT NULL,
                        created_ts TEXT NOT NULL,
                        ingested_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS generation_lineage (
                        gen_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        slot TEXT NOT NULL,
                        commit_sha TEXT NOT NULL,
                        parent_sha TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        created_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS kv_state (
                        key TEXT PRIMARY KEY,
                        value_json TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """
                )
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # 1. Cross-Generation Daily Budget Persistence
    # ------------------------------------------------------------------
    @staticmethod
    def _today_utc() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def add_daily_spend(self, delta_cost: float, day_utc: Optional[str] = None) -> float:
        """Atomically increment daily spend across slots and return updated daily total."""
        day_key = day_utc or self._today_utc()
        now = time.time()
        safe_delta = max(0.0, float(delta_cost))
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    """
                    INSERT INTO budget_ledger (day_utc, daily_cost, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(day_utc) DO UPDATE SET
                        daily_cost = daily_cost + excluded.daily_cost,
                        updated_at = excluded.updated_at
                    """,
                    (day_key, safe_delta, now),
                )
                row = conn.execute(
                    "SELECT daily_cost FROM budget_ledger WHERE day_utc = ?", (day_key,)
                ).fetchone()
                conn.execute("COMMIT;")
                return float(row["daily_cost"]) if row else safe_delta
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def get_daily_spend(self, day_utc: Optional[str] = None) -> float:
        day_key = day_utc or self._today_utc()
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT daily_cost FROM budget_ledger WHERE day_utc = ?", (day_key,)
                ).fetchone()
                return float(row["daily_cost"]) if row else 0.0
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # 2. Cross-Slot Investigation Trace Cache
    # ------------------------------------------------------------------
    def save_investigation(
        self, trace_id: str, query: str, verdict: str, receipts: list, max_entries: int = 50
    ) -> None:
        now = time.time()
        payload = json.dumps(receipts or [], default=str)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    """
                    INSERT INTO recent_investigations (trace_id, query, verdict, receipts_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(trace_id) DO UPDATE SET
                        query = excluded.query,
                        verdict = excluded.verdict,
                        receipts_json = excluded.receipts_json,
                        created_at = excluded.created_at
                    """,
                    (trace_id, query, verdict, payload, now),
                )
                conn.execute(
                    """
                    DELETE FROM recent_investigations
                    WHERE trace_id NOT IN (
                        SELECT trace_id FROM recent_investigations
                        ORDER BY created_at DESC
                        LIMIT ?
                    )
                    """,
                    (max(1, int(max_entries)),),
                )
                conn.execute("COMMIT;")
            except Exception:
                conn.execute("ROLLBACK;")
                raise
            finally:
                conn.close()

    def get_investigation(self, trace_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if trace_id == "latest" or not trace_id:
                    row = conn.execute(
                        "SELECT * FROM recent_investigations ORDER BY created_at DESC LIMIT 1"
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT * FROM recent_investigations WHERE trace_id = ?", (trace_id,)
                    ).fetchone()
                if not row:
                    return None
                return {
                    "trace_id": row["trace_id"],
                    "query": row["query"],
                    "verdict": row["verdict"],
                    "receipts": json.loads(row["receipts_json"] or "[]"),
                    "timestamp": row["created_at"],
                }
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # 3. Stigmergic Board Sync Cursor
    # ------------------------------------------------------------------
    def is_artifact_seen(self, artifact_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT 1 FROM board_cursor WHERE artifact_id = ?", (artifact_id,)
                ).fetchone()
                return row is not None
            finally:
                conn.close()

    def mark_artifact_seen(
        self,
        artifact_id: str,
        filename: str,
        move_type: str,
        actor: str,
        thread_id: str,
        base_sha: str,
        created_ts: str,
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO board_cursor
                    (artifact_id, filename, move_type, actor, thread_id, base_sha, created_ts, ingested_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (artifact_id, filename, move_type, actor, thread_id, base_sha, created_ts, time.time()),
                )
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # 4. Generation Lineage & Key-Value Coordination
    # ------------------------------------------------------------------
    def record_generation(
        self, slot: str, commit_sha: str, parent_sha: str, status: str, reason: str = ""
    ) -> int:
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    INSERT INTO generation_lineage (slot, commit_sha, parent_sha, status, reason, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (slot, commit_sha, parent_sha, status, reason, time.time()),
                )
                return int(cur.lastrowid)
            finally:
                conn.close()

    def list_generations(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM generation_lineage ORDER BY gen_id DESC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def set_kv(self, key: str, value: Any) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO kv_state (key, value_json, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value_json = excluded.value_json,
                        updated_at = excluded.updated_at
                    """,
                    (key, json.dumps(value, default=str), time.time()),
                )
            finally:
                conn.close()

    def get_kv(self, key: str, default: Any = None) -> Any:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT value_json FROM kv_state WHERE key = ?", (key,)
                ).fetchone()
                if not row:
                    return default
                return json.loads(row["value_json"])
            finally:
                conn.close()


get_shared_store = SharedStateStore.get_instance
