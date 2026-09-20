"""
CardStore — SQLite Persistence for Card Results.

Handles: storage, deduplication, TTL expiration, approval tracking,
and mute management for the autonomous card engine.

Thread-safe singleton — accessed from both the scheduler daemon
and the FastAPI request handlers.
"""

import os
import json
import time
import hashlib
import sqlite3
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from pathlib import Path

__all__ = ["CardResult", "CardStore", "TTL_MAP"]

logger = logging.getLogger(__name__)

# Database lives alongside the project
_DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_DB_PATH = _DB_DIR / "cards.db"

# TTL defaults (seconds)
_TTL_CONTINUOUS = 86400       # 24 hours
_TTL_PERIODIC = 86400 * 3     # 3 days
_TTL_DAILY = 86400 * 7        # 7 days
_TTL_WEEKLY = 86400 * 14      # 14 days

TTL_MAP = {
    "continuous": _TTL_CONTINUOUS,
    "periodic": _TTL_PERIODIC,
    "daily": _TTL_DAILY,
    "weekly": _TTL_WEEKLY,
}

_VALID_SEVERITIES = {"critical", "caution", "normal"}
_VALID_STATUSES = {"pending", "approved", "denied", "muted", "expired"}
_SEVERITY_RANK = {"critical": 3, "caution": 2, "normal": 1}

_JSON_LIST_FIELDS = ("evidence", "actions", "reasoning_trace", "reasoning_embedding")
_JSON_DICT_FIELDS = ("metrics", "audit_result")

_ORDER_BY_SEVERITY_SQL = """
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'caution' THEN 2
        ELSE 3
    END, timestamp DESC
"""


@dataclass
class CardResult:
    """A single card execution result."""
    id: str = ""                    # Auto-generated row ID
    card_id: str = ""               # e.g., "FT-02"
    card_key: str = ""              # e.g., "sub_30_breakout"
    name: str = ""
    severity: str = "normal"        # critical | caution | normal
    title: str = ""
    finding: str = ""
    evidence: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)
    reasoning_trace: list = field(default_factory=list)   # Externalized chain-of-thought
    trust_score: float = 1.0       # Fabrication cross-validation (0.0=fabricated, 1.0=verified)
    confidence_margin: Optional[float] = None  # Logprob gap between top-2 severity tokens (0.0-1.0)
    audit_result: dict = field(default_factory=dict)   # Debate Protocol output from Gemini Flash
    reasoning_embedding: list = field(default_factory=list)  # Embedding vector (768 to 3072 dimensions)
    status: str = "pending"         # pending | approved | denied | muted | expired
    device: str = "default"
    timestamp: float = 0.0
    expires_at: float = 0.0
    schedule: str = "daily"
    finding_hash: str = ""


class CardStore:
    """
    SQLite-backed persistence for card results.
    Thread-safe singleton with connection-per-thread pattern.
    """

    _instance: Optional['CardStore'] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or _DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._open_conns: Set[sqlite3.Connection] = set()
        self._conns_lock = threading.Lock()
        self._last_expire_time: float = 0.0
        self._expire_interval: float = 60.0  # Debounce TTL expiration checks to 60s
        self._init_schema()
        logger.info(f"[CardStore] Initialized: {self._db_path}")

    @classmethod
    def get_instance(cls) -> 'CardStore':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local SQLite connection with WAL mode and busy timeout."""
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")  # 5000ms wait on lock contention
            self._local.conn = conn
            with self._conns_lock:
                self._open_conns.add(conn)
        return conn

    def _init_schema(self):
        """Create tables if they don't exist with constraints and composite indexes."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS card_results (
                id          TEXT PRIMARY KEY,
                card_id     TEXT NOT NULL,
                card_key    TEXT NOT NULL,
                name        TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'normal' CHECK(severity IN ('critical', 'caution', 'normal')),
                title       TEXT NOT NULL,
                finding     TEXT NOT NULL,
                evidence    TEXT NOT NULL DEFAULT '[]',
                metrics     TEXT NOT NULL DEFAULT '{}',
                actions     TEXT NOT NULL DEFAULT '[]',
                reasoning_trace TEXT NOT NULL DEFAULT '[]',
                trust_score REAL NOT NULL DEFAULT 1.0,
                confidence_margin REAL DEFAULT NULL,
                audit_result TEXT NOT NULL DEFAULT '{}',
                reasoning_embedding TEXT NOT NULL DEFAULT '[]',
                status      TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'denied', 'muted', 'expired')),
                device      TEXT NOT NULL DEFAULT 'default',
                timestamp   REAL NOT NULL,
                expires_at  REAL NOT NULL,
                schedule    TEXT NOT NULL DEFAULT 'daily',
                finding_hash TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_card_status ON card_results(status);
            CREATE INDEX IF NOT EXISTS idx_card_severity ON card_results(severity);
            CREATE INDEX IF NOT EXISTS idx_card_hash ON card_results(finding_hash);
            CREATE INDEX IF NOT EXISTS idx_card_expires ON card_results(expires_at);
            CREATE INDEX IF NOT EXISTS idx_card_timestamp ON card_results(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_card_pending_filter ON card_results(status, expires_at, severity);

            CREATE TABLE IF NOT EXISTS card_mutes (
                card_key    TEXT PRIMARY KEY,
                muted_until REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_actions (
                id              TEXT PRIMARY KEY,
                card_result_id  TEXT NOT NULL,
                tool_name       TEXT NOT NULL,
                tool_args       TEXT NOT NULL DEFAULT '{}',
                status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'executed', 'cancelled')),
                signature       TEXT NOT NULL,
                created_at      REAL NOT NULL,
                executed_at     REAL,
                FOREIGN KEY (card_result_id) REFERENCES card_results(id) ON DELETE CASCADE
            );
        """)
        conn.commit()

        # Migrate existing databases — add new columns if missing
        for migration in [
            "ALTER TABLE card_results ADD COLUMN reasoning_trace TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE card_results ADD COLUMN trust_score REAL NOT NULL DEFAULT 1.0",
            "ALTER TABLE card_results ADD COLUMN confidence_margin REAL DEFAULT NULL",
            "ALTER TABLE card_results ADD COLUMN audit_result TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE card_results ADD COLUMN reasoning_embedding TEXT NOT NULL DEFAULT '[]'",
        ]:
            try:
                conn.execute(migration)
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Column already exists

    # ─── WRITE OPERATIONS ─────────────────────────────────────────────

    def store_result(self, result: CardResult) -> Optional[str]:
        """
        Store a card result. Returns the result ID, or None if deduplicated.

        Dedup: SHA-256 of card_key + title prevents duplicate alerts
        for the same finding within the TTL window.
        Severity Escalation: If a duplicate finding has a higher severity
        than the existing pending record, the record is updated with escalated data.
        """
        now = result.timestamp if result.timestamp > 0 else time.time()
        result.timestamp = now

        # Normalize and validate severity defensively
        norm_severity = (result.severity or "normal").strip().lower()
        if norm_severity not in _VALID_SEVERITIES:
            logger.warning(
                f"[CardStore] Invalid severity '{result.severity}' for {result.card_key}; defaulting to 'normal'"
            )
            norm_severity = "normal"
        result.severity = norm_severity

        norm_device = (result.device or "default").strip()
        result.device = norm_device
        finding_hash = hashlib.sha256(
            f"{result.card_key}:{norm_device}:{result.title}".encode("utf-8")
        ).hexdigest()[:16]
        result.finding_hash = finding_hash

        # Check mute
        if self.is_muted(result.card_key):
            logger.info(f"[CardStore] Muted: {result.card_key} — skipped")
            return None

        conn = self._get_conn()
        existing = conn.execute(
            "SELECT id, severity FROM card_results WHERE finding_hash = ? AND status = 'pending' AND expires_at > ?",
            (finding_hash, now)
        ).fetchone()

        if result.expires_at > 0:
            expires_at = result.expires_at
        else:
            ttl = TTL_MAP.get(result.schedule, _TTL_DAILY)
            expires_at = now + ttl
            result.expires_at = expires_at

        if existing:
            existing_id = existing["id"]
            existing_severity = existing["severity"]
            existing_rank = _SEVERITY_RANK.get(existing_severity, 1)
            new_rank = _SEVERITY_RANK.get(result.severity, 1)

            if new_rank > existing_rank:
                # Severity Escalation (H2): update existing pending alert
                conn.execute(
                    """UPDATE card_results
                       SET severity = ?, finding = ?, evidence = ?, metrics = ?, actions = ?,
                           reasoning_trace = ?, trust_score = ?, confidence_margin = ?,
                           audit_result = ?, reasoning_embedding = ?, timestamp = ?, expires_at = ?
                       WHERE id = ?""",
                    (
                        result.severity, result.finding,
                        json.dumps(result.evidence), json.dumps(result.metrics),
                        json.dumps(result.actions), json.dumps(result.reasoning_trace),
                        result.trust_score, result.confidence_margin,
                        json.dumps(result.audit_result), json.dumps(result.reasoning_embedding),
                        now, expires_at, existing_id
                    )
                )
                conn.commit()
                logger.warning(
                    f"[CardStore] Escalation: {result.card_key} ({result.title}) "
                    f"escalated {existing_severity} -> {result.severity} on ID {existing_id}"
                )
                return existing_id

            logger.info(f"[CardStore] Dedup: {result.card_key} ({result.title}) — skipped")
            return None

        # Generate ID
        result_id = hashlib.sha256(
            f"{result.card_key}:{norm_device}:{now}:{result.title}".encode("utf-8")
        ).hexdigest()[:12]
        result.id = result_id

        conn.execute(
            """INSERT INTO card_results
               (id, card_id, card_key, name, severity, title, finding,
                evidence, metrics, actions, reasoning_trace, trust_score,
                confidence_margin, audit_result, reasoning_embedding,
                status, device, timestamp, expires_at, schedule, finding_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result_id, result.card_id, result.card_key, result.name,
                result.severity, result.title, result.finding,
                json.dumps(result.evidence), json.dumps(result.metrics),
                json.dumps(result.actions), json.dumps(result.reasoning_trace),
                result.trust_score, result.confidence_margin,
                json.dumps(result.audit_result), json.dumps(result.reasoning_embedding),
                "pending", result.device,
                now, expires_at, result.schedule, finding_hash
            )
        )
        conn.commit()
        logger.info(f"[CardStore] Stored: {result.card_id} ({result.title}) severity={result.severity}")
        return result_id

    def approve(self, result_id: str) -> bool:
        """Mark a card result as approved."""
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE card_results SET status = 'approved' WHERE id = ? AND status = 'pending'",
            (result_id,)
        )
        conn.commit()
        return cursor.rowcount > 0

    def deny(self, result_id: str) -> bool:
        """Mark a card result as denied/dismissed."""
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE card_results SET status = 'denied' WHERE id = ? AND status = 'pending'",
            (result_id,)
        )
        conn.commit()
        return cursor.rowcount > 0

    def mute(self, card_key: str, hours: int = 24) -> None:
        """Suppress a card type for N hours."""
        muted_until = time.time() + (hours * 3600)
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO card_mutes (card_key, muted_until) VALUES (?, ?)",
            (card_key, muted_until)
        )
        conn.commit()
        logger.info(f"[CardStore] Muted: {card_key} for {hours}h")

    def is_muted(self, card_key: str) -> bool:
        """Check if a card type is currently muted."""
        now = time.time()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT muted_until FROM card_mutes WHERE card_key = ?",
            (card_key,)
        ).fetchone()
        if row and row['muted_until'] > now:
            return True
        # Clean up expired mute
        if row:
            conn.execute("DELETE FROM card_mutes WHERE card_key = ?", (card_key,))
            conn.commit()
        return False

    def expire_old(self, force: bool = False) -> int:
        """Expire cards past their TTL. Debounced unless force=True."""
        now = time.time()
        if not force and (now - self._last_expire_time < self._expire_interval):
            return 0

        self._last_expire_time = now
        conn = self._get_conn()
        cursor = conn.execute(
            "UPDATE card_results SET status = 'expired' WHERE expires_at < ? AND status = 'pending'",
            (now,)
        )
        conn.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info(f"[CardStore] Expired {count} cards")
        return count

    # ─── PENDING ACTION MANAGEMENT ────────────────────────────────────

    def create_pending_action(self, card_result_id: str, tool_name: str,
                              tool_args: dict, signature: str) -> str:
        """Create a pending action awaiting admin approval."""
        now = time.time()
        action_id = hashlib.sha256(
            f"{card_result_id}:{tool_name}:{now}".encode("utf-8")
        ).hexdigest()[:12]

        conn = self._get_conn()
        conn.execute(
            """INSERT INTO pending_actions
               (id, card_result_id, tool_name, tool_args, status, signature, created_at)
               VALUES (?, ?, ?, ?, 'pending', ?, ?)""",
            (action_id, card_result_id, tool_name, json.dumps(tool_args), signature, now)
        )
        conn.commit()
        return action_id

    def execute_pending_action(self, action_id: str) -> Optional[Dict]:
        """Mark a pending action as executed. Returns the action details."""
        now = time.time()
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM pending_actions WHERE id = ? AND status = 'pending'",
            (action_id,)
        ).fetchone()
        if not row:
            return None

        conn.execute(
            "UPDATE pending_actions SET status = 'executed', executed_at = ? WHERE id = ?",
            (now, action_id)
        )
        conn.commit()
        d = dict(row)
        if isinstance(d.get("tool_args"), str):
            try:
                d["tool_args"] = json.loads(d["tool_args"])
            except (json.JSONDecodeError, TypeError):
                d["tool_args"] = {}
        d["status"] = "executed"
        d["executed_at"] = now
        return d

    # ─── READ OPERATIONS ──────────────────────────────────────────────

    def get_pending(self, limit: int = 50) -> List[Dict]:
        """Get all pending card results, ordered by severity then timestamp."""
        self.expire_old(force=False)
        conn = self._get_conn()
        rows = conn.execute(
            f"""SELECT * FROM card_results
                WHERE status = 'pending' AND expires_at > ?
                ORDER BY {_ORDER_BY_SEVERITY_SQL}
                LIMIT ?""",
            (time.time(), limit)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_by_severity(self, severity: str, limit: int = 50) -> List[Dict]:
        """Get pending cards filtered by severity."""
        norm_severity = (severity or "normal").strip().lower()
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM card_results
               WHERE severity = ? AND status = 'pending' AND expires_at > ?
               ORDER BY timestamp DESC LIMIT ?""",
            (norm_severity, time.time(), limit)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_all(self, limit: int = 100) -> List[Dict]:
        """Get all cards (including non-pending) for history view."""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM card_results ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_by_id(self, result_id: str) -> Optional[Dict]:
        """Get a single card result by ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM card_results WHERE id = ?", (result_id,)
        ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_counts(self) -> Dict[str, int]:
        """Get counts of pending cards by severity."""
        conn = self._get_conn()
        now = time.time()
        rows = conn.execute(
            """SELECT severity, COUNT(*) as cnt FROM card_results
               WHERE status = 'pending' AND expires_at > ?
               GROUP BY severity""",
            (now,)
        ).fetchall()
        counts = {"critical": 0, "caution": 0, "normal": 0}
        for row in rows:
            sev = row['severity']
            counts[sev] = row['cnt']
        return counts

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert a SQLite Row to a dict with parsed JSON fields and resilient fallbacks."""
        d = dict(row)
        for field_name in _JSON_LIST_FIELDS:
            val = d.get(field_name)
            if isinstance(val, str):
                try:
                    parsed = json.loads(val)
                    d[field_name] = parsed if isinstance(parsed, list) else []
                except (json.JSONDecodeError, TypeError) as err:
                    logger.warning(f"[CardStore] Corrupt JSON list in field '{field_name}': {err}")
                    d[field_name] = []

        for field_name in _JSON_DICT_FIELDS:
            val = d.get(field_name)
            if isinstance(val, str):
                try:
                    parsed = json.loads(val)
                    d[field_name] = parsed if isinstance(parsed, dict) else {}
                except (json.JSONDecodeError, TypeError) as err:
                    logger.warning(f"[CardStore] Corrupt JSON dict in field '{field_name}': {err}")
                    d[field_name] = {}

        return d

    def close(self):
        """Close all open SQLite connections owned by this instance."""
        with self._conns_lock:
            for conn in list(self._open_conns):
                try:
                    conn.close()
                except Exception as e:
                    logger.debug(f"[CardStore] Error closing connection: {e}")
            self._open_conns.clear()
        if hasattr(self._local, 'conn'):
            self._local.conn = None

    @classmethod
    def reset(cls):
        """Reset singleton and close all open connections — for testing and clean teardown."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None
