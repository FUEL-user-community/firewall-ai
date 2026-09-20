"""
Conversion Metrics — XML to YAML transformation stats.

Logs conversion statistics to console for debugging.
"""

import logging
from typing import Optional
import threading

logger = logging.getLogger(__name__)


class MetricsLogger:
    """Logs XML→YAML conversion stats to console."""

    _instance: Optional['MetricsLogger'] = None
    _initialized = False
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if MetricsLogger._initialized:
            return
        MetricsLogger._initialized = True

    @classmethod
    def get_instance(cls) -> 'MetricsLogger':
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton instance for clean test isolation."""
        with cls._lock:
            cls._instance = None
            cls._initialized = False

    def log(self, command: str, stats: dict):
        """Log conversion metrics to console defensively (L2)."""
        stats_dict = stats if isinstance(stats, dict) else {}
        try:
            reduction = float(stats_dict.get('reduction_pct', 0))
        except (ValueError, TypeError):
            reduction = 0.0
        logger.debug(f"[METRICS] {command}: {reduction:.1f}% reduction")
