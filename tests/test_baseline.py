"""
Unit tests for core.engine.baseline.
Tests statistical drift detection, sample variance with Bessel's correction,
cosine similarity dimension safety, dedicated embedding storage, and NaN defense.
"""

import math
import pytest
import threading
from pathlib import Path
from core.engine.baseline import BaselineEngine, DriftResult


@pytest.fixture(autouse=True)
def clean_baseline_engine(tmp_path):
    """Ensure clean BaselineEngine singleton state before and after each test."""
    BaselineEngine.reset()
    test_db = tmp_path / "test_baselines.db"
    engine = BaselineEngine(db_path=test_db)
    BaselineEngine._instance = engine
    yield engine
    BaselineEngine.reset()


def test_singleton_pattern_and_reset(tmp_path):
    """Verify singleton returns same instance and reset closes connections."""
    b1 = BaselineEngine.get_instance()
    b2 = BaselineEngine.get_instance()
    assert b1 is b2

    BaselineEngine.reset()
    assert BaselineEngine._instance is None


def test_record_skips_non_numeric_and_nan(clean_baseline_engine):
    """Verify record ignores non-numeric, NaN, and Inf metrics."""
    engine = clean_baseline_engine
    metrics = {
        "valid_cpu": 45.0,
        "bool_val": True,
        "string_val": "ignored",
        "nan_val": float("nan"),
        "inf_val": float("inf"),
        "__embedding__": 999.0,  # Reserved sentinel must be ignored
    }
    engine.record("CARD-01", metrics)

    conn = engine._get_conn()
    rows = conn.execute("SELECT metric_name, value FROM card_baselines WHERE card_id = 'CARD-01'").fetchall()
    recorded_names = {r["metric_name"] for r in rows}
    assert "valid_cpu" in recorded_names
    assert "bool_val" in recorded_names
    assert "string_val" not in recorded_names
    assert "nan_val" not in recorded_names
    assert "inf_val" not in recorded_names
    assert "__embedding__" not in recorded_names


def test_compare_warmup_threshold(clean_baseline_engine):
    """Verify comparison requires at least 5 readings before activating."""
    engine = clean_baseline_engine
    # Record 4 readings (< _MIN_READINGS = 5)
    for i in range(4):
        engine.record("CARD-02", {"latency": 50.0})

    res = engine.compare("CARD-02", {"latency": 150.0})
    assert res.has_drift is False

    # Record 5th reading
    engine.record("CARD-02", {"latency": 50.0})
    res2 = engine.compare("CARD-02", {"latency": 150.0})
    assert res2.has_drift is True
    assert res2.drift_severity in ("caution", "critical")


def test_sample_variance_bessels_correction(clean_baseline_engine):
    """Verify sample variance (N - 1) calculation accuracy."""
    engine = clean_baseline_engine
    readings = [10.0, 12.0, 14.0, 16.0, 18.0]
    for r in readings:
        engine.record("CARD-03", {"metric": r})

    stats = engine.get_baseline_stats("CARD-03")
    assert stats["metric"]["readings"] == 5
    assert stats["metric"]["mean"] == 14.0
    # Sample standard deviation for [10, 12, 14, 16, 18] is sqrt(10) ≈ 3.16
    assert stats["metric"]["std_dev"] == round(math.sqrt(10.0), 2)


def test_get_baseline_stats_does_not_crash_on_embeddings(clean_baseline_engine):
    """Verify Self-Audit 1: get_baseline_stats does not crash with TypeError on embeddings."""
    engine = clean_baseline_engine
    engine.record("CARD-04", {"temperature": 75.0})
    engine.record_embedding("CARD-04", [0.1, 0.2, 0.3])

    # Must not raise TypeError: unsupported operand type(s) for +: 'int' and 'str'
    stats = engine.get_baseline_stats("CARD-04")
    assert "temperature" in stats
    assert "__embedding__" not in stats


def test_semantic_drift_detection_and_thresholds(clean_baseline_engine):
    """Verify cosine similarity detects normal, caution, and critical semantic drift."""
    engine = clean_baseline_engine
    base_emb = [1.0, 0.0, 0.0]
    for _ in range(5):
        engine.record_embedding("CARD-05", base_emb)

    # Identical vector -> similarity 1.0 -> Normal
    res_normal = engine.compare_embedding("CARD-05", [1.0, 0.0, 0.0])
    assert res_normal.has_drift is False
    assert res_normal.drift_severity == "normal"

    # Mild divergence (cos ≈ 0.8) -> Caution
    res_caution = engine.compare_embedding("CARD-05", [0.8, 0.6, 0.0])
    assert res_caution.has_drift is True
    assert res_caution.drift_severity == "caution"

    # Orthogonal vector (cos = 0.0 < 0.70) -> Critical
    res_critical = engine.compare_embedding("CARD-05", [0.0, 1.0, 0.0])
    assert res_critical.has_drift is True
    assert res_critical.drift_severity == "critical"


def test_cosine_similarity_dimension_mismatch_safety(clean_baseline_engine):
    """Verify M2: dimension mismatch returns 0.0 without throwing exceptions."""
    engine = clean_baseline_engine
    sim = engine._cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0])
    assert sim == 0.0


def test_cleanup_old_purges_both_tables(clean_baseline_engine):
    """Verify cleanup_old removes records from both card_baselines and card_embeddings."""
    import time
    engine = clean_baseline_engine
    engine.record("CARD-06", {"cpu": 30.0})
    engine.record_embedding("CARD-06", [0.5, 0.5])

    time.sleep(0.02)
    cleaned = engine.cleanup_old(days=0)
    assert cleaned >= 2
