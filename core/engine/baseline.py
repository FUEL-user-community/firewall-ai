"""
Baseline Learning Engine — Statistical Drift Detection for Card Metrics.

Stores structured metrics from scheduled card runs over time.
After N readings (default 5), auto-generates a rolling baseline (μ ± σ).
Drift detection: >2σ = CAUTION, >3σ = CRITICAL.

Key design rule: The baseline can only ESCALATE severity, never downgrade.
If the LLM says CRITICAL, the baseline can't override it to NORMAL.
"""

import os
import json
import time
import math
import sqlite3
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set
from pathlib import Path

__all__ = ["BaselineEngine", "DriftResult"]

logger = logging.getLogger(__name__)

_DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_DB_PATH = _DB_DIR / "baselines.db"

# Minimum readings before baseline comparison activates (warm-up threshold)
_MIN_READINGS = 5

# Rolling window size for historical metrics (decoupled from warm-up)
_WINDOW_SIZE = 14

# Number of historical embeddings to average for semantic drift detection
_EMBEDDING_WINDOW = 10

# Severity thresholds (in standard deviations)
_CAUTION_SIGMA = 2.0
_CRITICAL_SIGMA = 3.0

# Semantic drift cosine similarity thresholds
_SIMILARITY_NORMAL = 0.85
_SIMILARITY_CAUTION = 0.70

# Severity ranking for escalation comparison
_SEVERITY_RANK = {"normal": 0, "caution": 1, "critical": 2}


@dataclass
class DriftResult:
    """Result of a baseline comparison."""
    has_drift: bool = False
    drift_severity: str = "normal"
    drift_summary: str = ""
    drifted_metrics: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.drifted_metrics is None:
            self.drifted_metrics = {}


class BaselineEngine:
    """
    Rolling statistical baseline engine for card metrics.
    Thread-safe singleton with connection-per-thread pattern.
    """

    _instance: Optional['BaselineEngine'] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or _DB_PATH
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._open_conns: Set[sqlite3.Connection] = set()
        self._conns_lock = threading.Lock()
        self._init_schema()
        logger.info(f"[Baseline] Engine initialized: {self._db_path}")

    @classmethod
    def get_instance(cls) -> 'BaselineEngine':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
            with self._conns_lock:
                self._open_conns.add(conn)
        return conn

    def _init_schema(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS card_baselines (
                card_id     TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                timestamp   REAL NOT NULL,
                value       REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_baseline_card_metric
                ON card_baselines(card_id, metric_name);

            CREATE INDEX IF NOT EXISTS idx_baseline_timestamp
                ON card_baselines(timestamp);

            CREATE INDEX IF NOT EXISTS idx_baseline_card_metric_ts
                ON card_baselines(card_id, metric_name, timestamp DESC);

            CREATE TABLE IF NOT EXISTS card_embeddings (
                card_id     TEXT NOT NULL,
                timestamp   REAL NOT NULL,
                embedding   TEXT NOT NULL,
                dimension   INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_embeddings_lookup
                ON card_embeddings(card_id, timestamp DESC);
        """)
        conn.commit()

    def record(self, card_id: str, metrics: Dict[str, float]) -> None:
        """
        Store current metric readings for a card.
        Only stores valid finite numeric values — non-numeric or NaN/Inf metrics are safely skipped.
        """
        if not metrics:
            return

        now = time.time()
        conn = self._get_conn()
        recorded_count = 0

        for metric_name, value in metrics.items():
            # Reserve internal __embedding__ sentinel
            if metric_name == "__embedding__":
                continue

            # Only store numeric values
            if isinstance(value, bool):
                value = 1.0 if value else 0.0
            elif not isinstance(value, (int, float)):
                continue

            # Defensive NaN / Inf check (Self-Audit 2)
            try:
                f_val = float(value)
            except (ValueError, TypeError):
                continue

            if math.isnan(f_val) or math.isinf(f_val):
                logger.warning(f"[Baseline] Non-finite metric skipped: {card_id}:{metric_name}={f_val}")
                continue

            conn.execute(
                "INSERT INTO card_baselines (card_id, metric_name, timestamp, value) VALUES (?, ?, ?, ?)",
                (card_id, metric_name, now, f_val)
            )
            recorded_count += 1

        conn.commit()
        logger.debug(f"[Baseline] Recorded {recorded_count} metrics for {card_id}")

    def compare(self, card_id: str, current_metrics: Dict[str, float]) -> DriftResult:
        """
        Compare current metrics against the rolling baseline.
        Returns a DriftResult with escalation info.

        Only compares metrics that have >= _MIN_READINGS historical data points.
        Uses sample variance (Bessel's correction) for unbiased drift estimation.
        """
        if not current_metrics:
            return DriftResult()

        conn = self._get_conn()
        drifted = {}
        max_severity = "normal"

        for metric_name, current_value in current_metrics.items():
            if metric_name == "__embedding__":
                continue

            # Skip non-numeric or NaN/Inf
            if isinstance(current_value, bool):
                current_value = 1.0 if current_value else 0.0
            elif not isinstance(current_value, (int, float)):
                continue

            try:
                f_current = float(current_value)
            except (ValueError, TypeError):
                continue

            if math.isnan(f_current) or math.isinf(f_current):
                continue

            # Fetch last N readings
            rows = conn.execute(
                """SELECT value FROM card_baselines
                   WHERE card_id = ? AND metric_name = ?
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (card_id, metric_name, _WINDOW_SIZE)
            ).fetchall()

            if len(rows) < _MIN_READINGS:
                continue  # Not enough data for baseline

            values = []
            for r in rows:
                try:
                    v = float(r['value'])
                    if not (math.isnan(v) or math.isinf(v)):
                        values.append(v)
                except (ValueError, TypeError):
                    continue

            n = len(values)
            if n < _MIN_READINGS:
                continue

            mean = sum(values) / n
            # Bessel's correction for sample variance (M3)
            variance = sum((v - mean) ** 2 for v in values) / (n - 1) if n > 1 else 0.0
            std_dev = math.sqrt(variance) if variance > 0 else 0.0

            if std_dev == 0.0:
                # All historical values identical — any change is significant
                if f_current != mean:
                    drifted[metric_name] = {
                        "current": f_current,
                        "mean": mean,
                        "std_dev": 0.0,
                        "sigma": float('inf'),
                        "severity": "caution"
                    }
                    if _SEVERITY_RANK["caution"] > _SEVERITY_RANK[max_severity]:
                        max_severity = "caution"
                continue

            # Calculate how many sigma away
            deviation = abs(f_current - mean)
            sigma = deviation / std_dev

            if sigma >= _CRITICAL_SIGMA:
                drift_severity = "critical"
            elif sigma >= _CAUTION_SIGMA:
                drift_severity = "caution"
            else:
                continue  # Within normal range

            drifted[metric_name] = {
                "current": round(f_current, 2),
                "mean": round(mean, 2),
                "std_dev": round(std_dev, 2),
                "sigma": round(sigma, 1),
                "severity": drift_severity
            }

            if _SEVERITY_RANK[drift_severity] > _SEVERITY_RANK[max_severity]:
                max_severity = drift_severity

        if not drifted:
            return DriftResult()

        # Build summary
        summaries = []
        for metric, info in drifted.items():
            summaries.append(
                f"{metric}: {info['current']} (baseline μ={info['mean']}, "
                f"σ={info['std_dev']}, deviation={info['sigma']}σ → {info['severity'].upper()})"
            )

        return DriftResult(
            has_drift=True,
            drift_severity=max_severity,
            drift_summary="; ".join(summaries),
            drifted_metrics=drifted
        )

    def get_baseline_stats(self, card_id: str) -> Dict[str, Dict]:
        """Get current baseline statistics for a card (for display/debugging)."""
        conn = self._get_conn()

        # Filter out internal embedding markers to prevent TypeError crash (Self-Audit 1)
        metrics = conn.execute(
            "SELECT DISTINCT metric_name FROM card_baselines WHERE card_id = ? AND metric_name != '__embedding__'",
            (card_id,)
        ).fetchall()

        stats = {}
        for m in metrics:
            name = m['metric_name']
            rows = conn.execute(
                """SELECT value FROM card_baselines
                   WHERE card_id = ? AND metric_name = ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (card_id, name, _WINDOW_SIZE)
            ).fetchall()

            values = []
            for r in rows:
                try:
                    val = float(r['value'])
                    if not (math.isnan(val) or math.isinf(val)):
                        values.append(val)
                except (ValueError, TypeError):
                    continue

            if values:
                n = len(values)
                mean = sum(values) / n
                variance = sum((v - mean) ** 2 for v in values) / (n - 1) if n > 1 else 0.0
                stats[name] = {
                    "readings": n,
                    "mean": round(mean, 2),
                    "std_dev": round(math.sqrt(variance), 2) if variance > 0 else 0.0,
                    "min": round(min(values), 2),
                    "max": round(max(values), 2),
                    "latest": round(values[0], 2)
                }

        return stats

    def cleanup_old(self, days: int = 30) -> int:
        """Remove baseline data older than N days from all baseline tables."""
        cutoff = time.time() - (days * 86400)
        conn = self._get_conn()
        c1 = conn.execute(
            "DELETE FROM card_baselines WHERE timestamp < ?", (cutoff,)
        ).rowcount
        c2 = conn.execute(
            "DELETE FROM card_embeddings WHERE timestamp < ?", (cutoff,)
        ).rowcount
        conn.commit()
        count = c1 + c2
        if count > 0:
            logger.info(f"[Baseline] Cleaned {count} readings ({c1} metrics, {c2} embeddings) older than {days} days")
        return count

    # ─── SEMANTIC DRIFT (EMBEDDING COMPARISON) ───────────────────────

    def record_embedding(self, card_id: str, embedding: List[float]) -> None:
        """Store a reasoning trace embedding in dedicated table and update timeline marker."""
        if not embedding or not isinstance(embedding, (list, tuple)):
            return
        now = time.time()
        conn = self._get_conn()
        # Store in dedicated card_embeddings table (H1)
        conn.execute(
            """INSERT INTO card_embeddings (card_id, timestamp, embedding, dimension)
               VALUES (?, ?, ?, ?)""",
            (card_id, now, json.dumps(embedding), len(embedding))
        )
        # Store backward-compatible marker for server.py /api/drift/timeline
        conn.execute(
            """INSERT INTO card_baselines (card_id, metric_name, timestamp, value)
               VALUES (?, '__embedding__', ?, 1.0)""",
            (card_id, now)
        )
        conn.commit()

    def compare_embedding(self, card_id: str, current_embedding: List[float]) -> DriftResult:
        """
        Compare the current reasoning embedding against historical embeddings.

        Computes cosine similarity against the rolling average of the last
        N embeddings. If similarity drops below threshold, flags semantic drift.

        Thresholds:
            > 0.85 = Normal (agent behavior is consistent)
            0.70 - 0.85 = CAUTION (behavioral shift detected)
            < 0.70 = CRITICAL (severe behavioral anomaly)
        """
        if not current_embedding or not isinstance(current_embedding, (list, tuple)):
            return DriftResult()

        dim = len(current_embedding)
        if dim == 0:
            return DriftResult()

        conn = self._get_conn()

        # Query dedicated card_embeddings table (or fallback to card_baselines for legacy DBs)
        rows = conn.execute(
            """SELECT embedding FROM card_embeddings
               WHERE card_id = ? AND dimension = ?
               ORDER BY timestamp DESC
               LIMIT ?""",
            (card_id, dim, _EMBEDDING_WINDOW)
        ).fetchall()

        # Fallback for historical databases where card_embeddings has fewer than 3 records
        if len(rows) < 3:
            legacy_rows = conn.execute(
                """SELECT value FROM card_baselines
                   WHERE card_id = ? AND metric_name = '__embedding__'
                   ORDER BY timestamp DESC
                   LIMIT ?""",
                (card_id, _EMBEDDING_WINDOW)
            ).fetchall()
            combined_raw = [r['embedding'] for r in rows] + [
                r['value'] for r in legacy_rows if isinstance(r['value'], str) and r['value'].startswith('[')
            ]
        else:
            combined_raw = [r['embedding'] for r in rows]

        # Compute average embedding from historical data
        historical_embeddings = []
        for raw in combined_raw:
            try:
                hist_emb = json.loads(raw) if isinstance(raw, str) else raw
                # Dimension safety check (M4)
                if isinstance(hist_emb, list) and len(hist_emb) == dim:
                    historical_embeddings.append(hist_emb)
            except (json.JSONDecodeError, TypeError):
                continue

        if len(historical_embeddings) < 3:
            # Not enough valid historical embeddings for comparison
            return DriftResult()

        # Average the historical embeddings (Centroid)
        avg_embedding = [0.0] * dim
        num_hist = len(historical_embeddings)
        for emb in historical_embeddings:
            for j in range(dim):
                avg_embedding[j] += emb[j]
        avg_embedding = [v / num_hist for v in avg_embedding]

        # Cosine similarity
        similarity = self._cosine_similarity(current_embedding, avg_embedding)

        if similarity < _SIMILARITY_CAUTION:
            return DriftResult(
                has_drift=True,
                drift_severity="critical",
                drift_summary=f"SEVERE SEMANTIC DRIFT: cosine similarity {similarity:.3f} (threshold: {_SIMILARITY_CAUTION}). "
                              f"Agent reasoning has fundamentally shifted from baseline.",
                drifted_metrics={"cosine_similarity": round(similarity, 4)}
            )
        elif similarity < _SIMILARITY_NORMAL:
            return DriftResult(
                has_drift=True,
                drift_severity="caution",
                drift_summary=f"SEMANTIC DRIFT: cosine similarity {similarity:.3f} (threshold: {_SIMILARITY_NORMAL}). "
                              f"Agent reasoning is diverging from historical baseline.",
                drifted_metrics={"cosine_similarity": round(similarity, 4)}
            )

        return DriftResult(
            has_drift=False,
            drift_severity="normal",
            drifted_metrics={"cosine_similarity": round(similarity, 4)}
        )

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors with dimension validation (M2)."""
        if len(a) != len(b):
            logger.warning(f"[Baseline] Dimension mismatch in cosine similarity: {len(a)} vs {len(b)}")
            return 0.0

        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        # Clamped to [-1.0, 1.0] to prevent floating point imprecision
        return max(-1.0, min(1.0, dot / (norm_a * norm_b)))

    def close(self):
        """Close all open SQLite connections owned by this instance."""
        with self._conns_lock:
            for conn in list(self._open_conns):
                try:
                    conn.close()
                except Exception as e:
                    logger.debug(f"[Baseline] Error closing connection: {e}")
            self._open_conns.clear()
        if hasattr(self._local, 'conn'):
            self._local.conn = None

    @classmethod
    def reset(cls):
        """Reset singleton and close open connections — for clean test isolation."""
        with cls._lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None
