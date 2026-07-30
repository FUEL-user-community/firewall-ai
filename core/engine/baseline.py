"""
Baseline Learning Engine — Statistical Drift Detection for Card Metrics.

Stores structured metrics from scheduled card runs over time.
After N readings (default 7), auto-generates a rolling baseline (μ ± σ).
Drift detection: >2σ = CAUTION, >3σ = CRITICAL.

Key design rule: The baseline can only ESCALATE severity, never downgrade.
If the LLM says CRITICAL, the baseline can't override it to NORMAL.
"""

import time
import math
import sqlite3
import logging
import threading
from dataclasses import dataclass
from typing import Optional, Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)

_DB_DIR = Path(__file__).resolve().parent.parent.parent / "data"
_DB_PATH = _DB_DIR / "baselines.db"

# Minimum readings before baseline comparison activates
_MIN_READINGS = 7

# Rolling window size
_WINDOW_SIZE = 7

# Severity thresholds (in standard deviations)
_CAUTION_SIGMA = 2.0
_CRITICAL_SIGMA = 3.0

# Severity ranking for escalation comparison
_SEVERITY_RANK = {"normal": 0, "caution": 1, "critical": 2}


@dataclass
class DriftResult:
    """Result of a baseline comparison."""
    has_drift: bool = False
    drift_severity: str = "normal"
    drift_summary: str = ""
    drifted_metrics: dict = None

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

    def __init__(self):
        _DB_DIR.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()
        logger.info(f"[Baseline] Engine initialized: {_DB_PATH}")

    @classmethod
    def get_instance(cls) -> 'BaselineEngine':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

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
        """)
        conn.commit()

    def record(self, card_id: str, metrics: Dict[str, float]) -> None:
        """
        Store current metric readings for a card.
        Only stores numeric values — non-numeric metrics are silently skipped.
        """
        if not metrics:
            return

        now = time.time()
        conn = self._get_conn()

        for metric_name, value in metrics.items():
            # Only store numeric values
            if isinstance(value, bool):
                value = 1.0 if value else 0.0
            elif not isinstance(value, (int, float)):
                continue

            conn.execute(
                "INSERT INTO card_baselines (card_id, metric_name, timestamp, value) VALUES (?, ?, ?, ?)",
                (card_id, metric_name, now, float(value))
            )

        conn.commit()
        logger.debug(f"[Baseline] Recorded {len(metrics)} metrics for {card_id}")

    def compare(self, card_id: str, current_metrics: Dict[str, float]) -> DriftResult:
        """
        Compare current metrics against the rolling baseline.
        Returns a DriftResult with escalation info.

        Only compares metrics that have >= _MIN_READINGS historical data points.
        """
        if not current_metrics:
            return DriftResult()

        conn = self._get_conn()
        drifted = {}
        max_severity = "normal"

        for metric_name, current_value in current_metrics.items():
            # Skip non-numeric
            if isinstance(current_value, bool):
                current_value = 1.0 if current_value else 0.0
            elif not isinstance(current_value, (int, float)):
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

            values = [r['value'] for r in rows]
            mean = sum(values) / len(values)
            variance = sum((v - mean) ** 2 for v in values) / len(values)
            std_dev = math.sqrt(variance) if variance > 0 else 0

            if std_dev == 0:
                # All historical values identical — any change is significant
                if current_value != mean:
                    drifted[metric_name] = {
                        "current": current_value,
                        "mean": mean,
                        "std_dev": 0,
                        "sigma": float('inf'),
                        "severity": "caution"
                    }
                    if _SEVERITY_RANK["caution"] > _SEVERITY_RANK[max_severity]:
                        max_severity = "caution"
                continue

            # Calculate how many sigma away
            deviation = abs(current_value - mean)
            sigma = deviation / std_dev

            if sigma >= _CRITICAL_SIGMA:
                drift_severity = "critical"
            elif sigma >= _CAUTION_SIGMA:
                drift_severity = "caution"
            else:
                continue  # Within normal range

            drifted[metric_name] = {
                "current": round(current_value, 2),
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

        # Get distinct metrics for this card
        metrics = conn.execute(
            "SELECT DISTINCT metric_name FROM card_baselines WHERE card_id = ?",
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

            values = [r['value'] for r in rows]
            if values:
                mean = sum(values) / len(values)
                variance = sum((v - mean) ** 2 for v in values) / len(values)
                stats[name] = {
                    "readings": len(values),
                    "mean": round(mean, 2),
                    "std_dev": round(math.sqrt(variance), 2) if variance > 0 else 0,
                    "min": round(min(values), 2),
                    "max": round(max(values), 2),
                    "latest": round(values[0], 2)
                }

        return stats

    def cleanup_old(self, days: int = 30) -> int:
        """Remove baseline data older than N days."""
        cutoff = time.time() - (days * 86400)
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM card_baselines WHERE timestamp < ?", (cutoff,)
        )
        conn.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info(f"[Baseline] Cleaned {count} readings older than {days} days")
        return count

    # ─── SEMANTIC DRIFT (EMBEDDING COMPARISON) ───────────────────────

    def record_embedding(self, card_id: str, embedding: List[float]) -> None:
        """Store a reasoning trace embedding for drift tracking."""
        if not embedding:
            return
        conn = self._get_conn()
        import json
        conn.execute(
            """INSERT INTO card_baselines (card_id, metric_name, value, timestamp)
               VALUES (?, ?, ?, ?)""",
            (card_id, "__embedding__", json.dumps(embedding), time.time())
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
        if not current_embedding:
            return DriftResult()

        conn = self._get_conn()
        import json
        rows = conn.execute(
            """SELECT value FROM card_baselines
               WHERE card_id = ? AND metric_name = ?
               ORDER BY timestamp DESC
               LIMIT ?""",
            (card_id, "__embedding__", 50)
        ).fetchall()

        if len(rows) < 3:
            # Not enough history for meaningful comparison
            return DriftResult()

        # Compute average embedding from historical data
        historical_embeddings = []
        for row in rows:
            try:
                hist_emb = json.loads(row['value'])
                if isinstance(hist_emb, list) and len(hist_emb) > 0:
                    historical_embeddings.append(hist_emb)
            except (json.JSONDecodeError, TypeError):
                continue

        if not historical_embeddings:
            return DriftResult()

        # Average the historical embeddings
        dim = len(current_embedding)
        avg_embedding = [0.0] * dim
        for emb in historical_embeddings:
            for j in range(dim):
                avg_embedding[j] += emb[j]
        avg_embedding = [v / len(historical_embeddings) for v in avg_embedding]

        # Cosine similarity
        similarity = self._cosine_similarity(current_embedding, avg_embedding)

        if similarity < 0.70:
            return DriftResult(
                has_drift=True,
                drift_severity="critical",
                drift_summary=f"SEVERE SEMANTIC DRIFT: cosine similarity {similarity:.3f} (threshold: 0.70). "
                              f"Agent reasoning has fundamentally shifted from baseline.",
                drifted_metrics={"cosine_similarity": round(similarity, 4)}
            )
        elif similarity < 0.85:
            return DriftResult(
                has_drift=True,
                drift_severity="caution",
                drift_summary=f"SEMANTIC DRIFT: cosine similarity {similarity:.3f} (threshold: 0.85). "
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
        """Compute cosine similarity between two vectors."""
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    @classmethod
    def reset(cls):
        """Reset singleton — for testing."""
        cls._instance = None

