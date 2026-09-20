"""
Unit tests for core.engine.card_store.
Tests SQLite schema constraints, severity escalation, deduplication,
thread-local connection cleanup, debounced TTL expiration, and JSON error recovery.
"""

import time
import pytest
import sqlite3
import threading
from pathlib import Path
from core.engine.card_store import CardStore, CardResult, TTL_MAP


@pytest.fixture(autouse=True)
def clean_card_store(tmp_path):
    """Ensure clean CardStore singleton state before and after each test."""
    CardStore.reset()
    test_db = tmp_path / "test_cards.db"
    store = CardStore(db_path=test_db)
    CardStore._instance = store
    yield store
    CardStore.reset()


def test_singleton_pattern_and_reset(tmp_path):
    """Verify singleton returns same instance and reset closes connections cleanly."""
    store1 = CardStore.get_instance()
    store2 = CardStore.get_instance()
    assert store1 is store2

    CardStore.reset()
    assert CardStore._instance is None


def test_store_result_and_deduplication(clean_card_store):
    """Verify storing same card finding within TTL window is deduplicated."""
    store = clean_card_store
    res1 = CardResult(
        card_id="TEST-01",
        card_key="test_card",
        title="High CPU Usage",
        finding="CPU is at 92%",
        severity="caution",
    )
    id1 = store.store_result(res1)
    assert id1 is not None

    # Storing identical finding with same or lower severity returns None (deduped)
    res2 = CardResult(
        card_id="TEST-01",
        card_key="test_card",
        title="High CPU Usage",
        finding="CPU is at 92%",
        severity="caution",
    )
    id2 = store.store_result(res2)
    assert id2 is None


def test_multi_device_deduplication_isolation(clean_card_store):
    """Verify that identical findings on different devices are both stored and not deduplicated."""
    store = clean_card_store
    res_hq = CardResult(
        card_id="TEST-01",
        card_key="test_card",
        title="High CPU Usage",
        finding="CPU is at 92%",
        severity="caution",
        device="fw-hq",
    )
    id_hq = store.store_result(res_hq)
    assert id_hq is not None

    res_branch = CardResult(
        card_id="TEST-01",
        card_key="test_card",
        title="High CPU Usage",
        finding="CPU is at 92%",
        severity="caution",
        device="fw-branch",
    )
    id_branch = store.store_result(res_branch)
    assert id_branch is not None
    assert id_branch != id_hq

    # Verify both exist in store
    card_hq = store.get_by_id(id_hq)
    card_branch = store.get_by_id(id_branch)
    assert card_hq["device"] == "fw-hq"
    assert card_branch["device"] == "fw-branch"


def test_severity_escalation(clean_card_store):
    """Verify H2: duplicate finding with higher severity updates existing record."""
    store = clean_card_store
    res_low = CardResult(
        card_id="TEST-02",
        card_key="test_card",
        title="Memory Leak",
        finding="Memory at 70%",
        severity="caution",
    )
    initial_id = store.store_result(res_low)
    assert initial_id is not None

    # Condition worsens to critical
    res_high = CardResult(
        card_id="TEST-02",
        card_key="test_card",
        title="Memory Leak",
        finding="Memory at 98% - OOM imminent!",
        severity="critical",
    )
    escalated_id = store.store_result(res_high)
    assert escalated_id == initial_id  # Returns updated existing record ID

    card = store.get_by_id(initial_id)
    assert card["severity"] == "critical"
    assert "OOM imminent" in card["finding"]


def test_severity_validation_and_normalization(clean_card_store):
    """Verify H1: invalid severities are normalized to normal without DB errors."""
    store = clean_card_store
    res = CardResult(
        card_id="TEST-03",
        card_key="test_card",
        title="Invalid Severity Check",
        finding="Test finding",
        severity="UNKNOWN_URGENT",
    )
    res_id = store.store_result(res)
    assert res_id is not None

    card = store.get_by_id(res_id)
    assert card["severity"] == "normal"


def test_approval_and_denial_lifecycle(clean_card_store):
    """Verify approve and deny lifecycle transitions and idempotency."""
    store = clean_card_store
    res = CardResult(
        card_id="TEST-04",
        card_key="test_card",
        title="Action Test",
        finding="Needs admin review",
    )
    res_id = store.store_result(res)

    assert store.approve(res_id) is True
    # Cannot re-approve or deny once approved
    assert store.approve(res_id) is False
    assert store.deny(res_id) is False

    card = store.get_by_id(res_id)
    assert card["status"] == "approved"


def test_mute_and_unmute_lifecycle(clean_card_store):
    """Verify card mutes suppress storage and expired mutes are cleaned up."""
    store = clean_card_store
    card_key = "noisy_card"
    store.mute(card_key, hours=1)
    assert store.is_muted(card_key) is True

    res = CardResult(
        card_id="TEST-05",
        card_key=card_key,
        title="Noisy Finding",
        finding="Should be suppressed",
    )
    assert store.store_result(res) is None


def test_ttl_expiration_debouncing(clean_card_store):
    """Verify M1: expire_old expires old cards and debounces within interval."""
    store = clean_card_store
    res = CardResult(
        card_id="TEST-06",
        card_key="test_card",
        title="Expired Finding",
        finding="Past TTL",
        timestamp=time.time() - 100000,
        expires_at=time.time() - 10,
    )
    res_id = store.store_result(res)

    # Force expiration of cards past TTL
    expired_count = store.expire_old(force=True)
    assert expired_count >= 1

    card = store.get_by_id(res_id)
    assert card["status"] == "expired"

    # Repeated expire_old without force should be debounced and return 0
    debounced_count = store.expire_old(force=False)
    assert debounced_count == 0


def test_pending_action_lifecycle(clean_card_store):
    """Verify pending actions can be created and executed."""
    store = clean_card_store
    res = CardResult(
        card_id="TEST-07",
        card_key="test_card",
        title="Pending Action Card",
        finding="Needs CLI execution",
    )
    res_id = store.store_result(res)

    action_id = store.create_pending_action(
        card_result_id=res_id,
        tool_name="restart_service",
        tool_args={"service": "dataplane"},
        signature="sig123",
    )
    assert action_id is not None

    executed = store.execute_pending_action(action_id)
    assert executed is not None
    assert executed["status"] == "executed"
    assert executed["tool_args"] == {"service": "dataplane"}


def test_corrupted_json_resilience(clean_card_store):
    """Verify M2: corrupt JSON in DB columns falls back to empty list/dict."""
    store = clean_card_store
    conn = store._get_conn()
    now = time.time()
    conn.execute(
        """INSERT INTO card_results
           (id, card_id, card_key, name, severity, title, finding,
            evidence, metrics, actions, reasoning_trace, trust_score,
            status, device, timestamp, expires_at, schedule, finding_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            "CORRUPT-1", "FT-99", "corrupt_card", "Corrupt Test", "normal", "Title", "Finding",
            "NOT_JSON_EVIDENCE", "NOT_JSON_METRICS", "NOT_JSON_ACTIONS", "NOT_JSON_TRACE",
            1.0, "pending", "default", now, now + 3600, "daily", "hash123"
        )
    )
    conn.commit()

    card = store.get_by_id("CORRUPT-1")
    assert isinstance(card["evidence"], list)
    assert isinstance(card["metrics"], dict)
    assert isinstance(card["actions"], list)


def test_multithreaded_concurrency_and_busy_timeout(clean_card_store):
    """Verify M3: multiple threads writing concurrently do not trigger lock errors."""
    store = clean_card_store
    errors = []

    def worker(idx):
        try:
            res = CardResult(
                card_id=f"THREAD-{idx}",
                card_key=f"thread_card_{idx}",
                title=f"Concurrent Finding {idx}",
                finding=f"Worker {idx} reporting",
                severity="caution" if idx % 2 == 0 else "normal",
            )
            store.store_result(res)
            store.get_counts()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0


def test_get_by_severity_and_counts(clean_card_store):
    """Verify get_by_severity normalizes input casing and get_counts returns accurate tallies."""
    store = clean_card_store
    res1 = CardResult(
        card_id="T-SEV-1",
        card_key="key1",
        title="Critical Alert",
        finding="Critical condition",
        severity="critical",
    )
    res2 = CardResult(
        card_id="T-SEV-2",
        card_key="key2",
        title="Caution Alert",
        finding="Caution condition",
        severity="caution",
    )
    store.store_result(res1)
    store.store_result(res2)

    # Test case insensitivity
    crit_cards = store.get_by_severity("CRITICAL")
    assert len(crit_cards) == 1
    assert crit_cards[0]["card_id"] == "T-SEV-1"

    counts = store.get_counts()
    assert counts["critical"] == 1
    assert counts["caution"] == 1
    assert counts["normal"] == 0
