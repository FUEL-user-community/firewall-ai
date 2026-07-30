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
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# Database lives alongside the project
_DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_DB_PATH = _DB_DIR / "cards.db"

# TTL defaults (seconds)
_TTL_CONTINUOUS = 86400       # 24 hours
_TTL_PERIODIC = 86400 * 3    # 3 days
_TTL_DAILY = 86400 * 7       # 7 days
_TTL_WEEKLY = 86400 * 14     # 14 days

TTL_MAP = {
    "continuous": _TTL_CONTINUOUS,
    "periodic": _TTL_PERIODIC,
    "daily": _TTL_DAILY,
    "weekly": _TTL_WEEKLY,
}


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
    confidence_margin: float = None  # Logprob gap between top-2 severity tokens (0.0-1.0)
    audit_result: dict = field(default_factory=dict)   # Debate Protocol output from Gemini Flash
    reasoning_embedding: list = field(default_factory=list)  # 768-dim vector for semantic drift
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

    def __init__(self):
        _DB_DIR.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()
        logger.info(f"[CardStore] Initialized: {_DB_PATH}")

    @classmethod
    def get_instance(cls) -> 'CardStore':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local SQLite connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA foreign_keys=ON")
        return self._local.conn

    def _init_schema(self):
        """Create tables if they don't exist."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS card_results (
                id          TEXT PRIMARY KEY,
                card_id     TEXT NOT NULL,
                card_key    TEXT NOT NULL,
                name        TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'normal',
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
                status      TEXT NOT NULL DEFAULT 'pending',
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

            CREATE TABLE IF NOT EXISTS card_mutes (
                card_key    TEXT PRIMARY KEY,
                muted_until REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_actions (
                id              TEXT PRIMARY KEY,
                card_result_id  TEXT NOT NULL,
                tool_name       TEXT NOT NULL,
                tool_args       TEXT NOT NULL DEFAULT '{}',
                status          TEXT NOT NULL DEFAULT 'pending',
                signature       TEXT NOT NULL,
                created_at      REAL NOT NULL,
                executed_at     REAL,
                FOREIGN KEY (card_result_id) REFERENCES card_results(id)
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
        """
        now = time.time()
        finding_hash = hashlib.sha256(
            f"{result.card_key}:{result.title}".encode()
        ).hexdigest()[:16]

        # Check dedup — skip if same hash exists and is still pending
        conn = self._get_conn()
        existing = conn.execute(
            "SELECT id FROM card_results WHERE finding_hash = ? AND status = 'pending' AND expires_at > ?",
            (finding_hash, now)
        ).fetchone()

        if existing:
            logger.info(f"[CardStore] Dedup: {result.card_key} ({result.title}) — skipped")
            return None

        # Check mute
        if self.is_muted(result.card_key):
            logger.info(f"[CardStore] Muted: {result.card_key} — skipped")
            return None

        # Generate ID
        result_id = hashlib.sha256(
            f"{result.card_key}:{now}:{result.title}".encode()
        ).hexdigest()[:12]

        ttl = TTL_MAP.get(result.schedule, _TTL_DAILY)
        expires_at = now + ttl

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
        conn = self._get_conn()
        row = conn.execute(
            "SELECT muted_until FROM card_mutes WHERE card_key = ?",
            (card_key,)
        ).fetchone()
        if row and row['muted_until'] > time.time():
            return True
        # Clean up expired mute
        if row:
            conn.execute("DELETE FROM card_mutes WHERE card_key = ?", (card_key,))
            conn.commit()
        return False

    def expire_old(self) -> int:
        """Expire cards past their TTL. Returns count of expired cards."""
        now = time.time()
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
        action_id = hashlib.sha256(
            f"{card_result_id}:{tool_name}:{time.time()}".encode()
        ).hexdigest()[:12]

        conn = self._get_conn()
        conn.execute(
            """INSERT INTO pending_actions
               (id, card_result_id, tool_name, tool_args, status, signature, created_at)
               VALUES (?, ?, ?, ?, 'pending', ?, ?)""",
            (action_id, card_result_id, tool_name, json.dumps(tool_args), signature, time.time())
        )
        conn.commit()
        return action_id

    def execute_pending_action(self, action_id: str) -> Optional[Dict]:
        """Mark a pending action as executed. Returns the action details."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM pending_actions WHERE id = ? AND status = 'pending'",
            (action_id,)
        ).fetchone()
        if not row:
            return None

        conn.execute(
            "UPDATE pending_actions SET status = 'executed', executed_at = ? WHERE id = ?",
            (time.time(), action_id)
        )
        conn.commit()
        return dict(row)

    # ─── READ OPERATIONS ──────────────────────────────────────────────

    def get_pending(self, limit: int = 50) -> List[Dict]:
        """Get all pending card results, ordered by severity then timestamp."""
        self.expire_old()
        conn = self._get_conn()
        severity_order = "CASE severity WHEN 'critical' THEN 1 WHEN 'caution' THEN 2 ELSE 3 END"
        rows = conn.execute(
            f"""SELECT * FROM card_results
                WHERE status = 'pending' AND expires_at > ?
                ORDER BY {severity_order}, timestamp DESC
                LIMIT ?""",
            (time.time(), limit)
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_by_severity(self, severity: str, limit: int = 50) -> List[Dict]:
        """Get pending cards filtered by severity."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM card_results
               WHERE severity = ? AND status = 'pending' AND expires_at > ?
               ORDER BY timestamp DESC LIMIT ?""",
            (severity, time.time(), limit)
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
            counts[row['severity']] = row['cnt']
        return counts

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert a SQLite Row to a dict with parsed JSON fields."""
        d = dict(row)
        for field_name in ('evidence', 'metrics', 'actions', 'reasoning_trace', 'audit_result', 'reasoning_embedding'):
            if field_name in d and isinstance(d[field_name], str):
                try:
                    d[field_name] = json.loads(d[field_name])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    @classmethod
    def reset(cls):
        """Reset singleton — for testing."""
        cls._instance = None
