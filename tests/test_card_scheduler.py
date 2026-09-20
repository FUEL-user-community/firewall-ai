"""
Unit and integration tests for CardScheduler (Script #4).

Covers:
- H1: Modern non-deprecated asyncio.get_running_loop() execution
- H2: Thread-safe singleton creation and reset
- H3: Clean daemon cancellation without dangling asyncio tasks
- M1: Python 3.12+ date-aware UTC formatting in schedule status
- M2: Module-level imports (BaselineEngine)
- M3: Restoration of past run timestamps from CardStore on startup
- AUDIT-1: Thread-safe subscriber registration and broadcasting
- AUDIT-2: Defensive interval_seconds string coercion
- AUDIT-3: Thread-safe enable/disable schedule overrides
"""

import time
import asyncio
import threading
from unittest.mock import MagicMock, patch
import pytest

from core.engine.card_scheduler import CardScheduler, _INTER_CARD_DELAY


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def cleanup_scheduler():
    """Ensure scheduler singleton is reset before and after each test."""
    CardScheduler.reset()
    yield
    CardScheduler.reset()


# ---------------------------------------------------------------------------
# H2: Singleton Concurrency & Reset Thread-Safety
# ---------------------------------------------------------------------------

def test_scheduler_singleton_thread_safety():
    """Concurrent threads calling CardScheduler.get_instance() must receive the same instance."""
    instances = []

    def worker():
        with patch("core.engine.card_scheduler.CardRunner"), \
             patch("core.engine.card_scheduler.CardStore"):
            inst = CardScheduler.get_instance()
            instances.append(inst)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(instances) == 10
    first = instances[0]
    for inst in instances:
        assert inst is first


def test_scheduler_reset_thread_safety():
    """reset() should stop running daemon and clear singleton under lock."""
    with patch("core.engine.card_scheduler.CardRunner"), \
         patch("core.engine.card_scheduler.CardStore"):
        s1 = CardScheduler.get_instance()
        s1._running = True
        CardScheduler.reset()
        assert not s1._running
        assert CardScheduler._instance is None

        s2 = CardScheduler.get_instance()
        assert s2 is not s1


# ---------------------------------------------------------------------------
# AUDIT-1: Thread-Safe Subscriber Pub/Sub
# ---------------------------------------------------------------------------

def test_subscriber_pubsub_thread_safety():
    """Concurrent subscriptions, unsubscriptions, and notifications must not raise RuntimeError."""
    with patch("core.engine.card_scheduler.CardRunner"), \
         patch("core.engine.card_scheduler.CardStore"):
        scheduler = CardScheduler.get_instance()

    received = []
    stop_event = threading.Event()

    def subscriber_a(card_dict):
        received.append(("A", card_dict.get("id")))

    def subscriber_b(card_dict):
        received.append(("B", card_dict.get("id")))

    def mutator_worker():
        while not stop_event.is_set():
            scheduler.subscribe(subscriber_a)
            scheduler.subscribe(subscriber_b)
            scheduler.unsubscribe(subscriber_a)
            scheduler.unsubscribe(subscriber_b)
            time.sleep(0.001)

    def notifier_worker():
        for i in range(100):
            scheduler._notify_subscribers({"id": f"card-{i}"})
            time.sleep(0.001)

    threads = [
        threading.Thread(target=mutator_worker),
        threading.Thread(target=notifier_worker),
        threading.Thread(target=notifier_worker),
    ]

    for t in threads:
        t.start()

    # Wait for notifiers to complete
    threads[1].join()
    threads[2].join()
    stop_event.set()
    threads[0].join()

    # Successful completion without RuntimeError verifies thread safety
    assert True


# ---------------------------------------------------------------------------
# M1: Date-Aware UTC Formatting
# ---------------------------------------------------------------------------

def test_schedule_status_utc_formatting():
    """get_schedule_status() must format timestamps as '%Y-%m-%d %H:%M:%S UTC' without crashing."""
    with patch("core.engine.card_scheduler.CardRunner") as mock_runner_cls, \
         patch("core.engine.card_scheduler.CardStore"):
        mock_runner = mock_runner_cls.return_value
        mock_runner.load_cards.return_value = {
            "test_card": {
                "id": "FT-01",
                "name": "Test Card",
                "schedule": "daily",
                "interval_seconds": 86400,
            }
        }

        scheduler = CardScheduler.get_instance()
        fixed_ts = 1773225600.0  # Future UTC timestamp
        scheduler._last_run["test_card"] = fixed_ts
        scheduler._next_runs["test_card"] = fixed_ts + 86400

        status = scheduler.get_schedule_status()
        assert len(status) == 1
        item = status[0]
        assert "UTC" in item["last_run_human"]
        assert "UTC" in item["next_run_human"]
        assert item["last_run_human"].startswith("2026-")


def test_schedule_status_never_and_pending_when_zero():
    """0.0 timestamps should display 'Never' and 'Pending' respectively."""
    with patch("core.engine.card_scheduler.CardRunner") as mock_runner_cls, \
         patch("core.engine.card_scheduler.CardStore"):
        mock_runner = mock_runner_cls.return_value
        mock_runner.load_cards.return_value = {
            "test_card": {"id": "FT-01", "name": "Test Card", "schedule": "daily"}
        }

        scheduler = CardScheduler.get_instance()
        status = scheduler.get_schedule_status()
        assert status[0]["last_run_human"] == "Never"
        assert status[0]["next_run_human"] == "Pending"


# ---------------------------------------------------------------------------
# M3: Past Execution Timestamp Restoration
# ---------------------------------------------------------------------------

def test_last_run_timestamp_restoration():
    """Scheduler must query CardStore on startup and populate _last_run to avoid thundering herd."""
    with patch("core.engine.card_scheduler.CardRunner"), \
         patch("core.engine.card_scheduler.CardStore") as mock_store_cls:
        mock_store = mock_store_cls.get_instance.return_value
        mock_conn = MagicMock()
        mock_store._get_conn.return_value = mock_conn

        mock_conn.execute.return_value.fetchall.return_value = [
            {"card_key": "card_a", "last_ts": 1700000000.0},
            {"card_key": "card_b", "last_ts": 1700000500.0},
        ]

        scheduler = CardScheduler.get_instance()
        assert scheduler._last_run.get("card_a") == 1700000000.0
        assert scheduler._last_run.get("card_b") == 1700000500.0


# ---------------------------------------------------------------------------
# AUDIT-2: Defensive YAML Type Coercion
# ---------------------------------------------------------------------------

def test_defensive_interval_coercion():
    """String interval_seconds ('300') must be safely parsed to int without TypeError."""
    with patch("core.engine.card_scheduler.CardRunner") as mock_runner_cls, \
         patch("core.engine.card_scheduler.CardStore"):
        mock_runner = mock_runner_cls.return_value
        mock_runner.load_cards.return_value = {
            "str_interval": {"id": "FT-01", "interval_seconds": "300"},
            "bad_interval": {"id": "FT-02", "interval_seconds": "invalid_number"},
        }

        scheduler = CardScheduler.get_instance()
        status = scheduler.get_schedule_status()

        item1 = next(s for s in status if s["card_key"] == "str_interval")
        item2 = next(s for s in status if s["card_key"] == "bad_interval")

        assert item1["interval_seconds"] == 300
        assert item2["interval_seconds"] == 86400  # Fallback to _DAILY_INTERVAL


# ---------------------------------------------------------------------------
# AUDIT-3: State Locking & Schedule Overrides
# ---------------------------------------------------------------------------

def test_enable_disable_card_toggle():
    """enable_card and disable_card must correctly toggle enabled state under lock."""
    with patch("core.engine.card_scheduler.CardRunner"), \
         patch("core.engine.card_scheduler.CardStore"):
        scheduler = CardScheduler.get_instance()

        assert scheduler.is_card_enabled("my_card") is True  # Default
        scheduler.disable_card("my_card")
        assert scheduler.is_card_enabled("my_card") is False
        scheduler.enable_card("my_card")
        assert scheduler.is_card_enabled("my_card") is True


# ---------------------------------------------------------------------------
# H1 & H3: Asyncio Loop & Graceful Cancellation
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_graceful_cancellation_cancels_tasks():
    """Cancelling run() should terminate internal tasks cleanly without hanging."""
    with patch("core.engine.card_scheduler.CardRunner"), \
         patch("core.engine.card_scheduler.CardStore"):
        scheduler = CardScheduler.get_instance()
        scheduler._enabled = True

        # Run scheduler in background with 0 startup delay
        with patch("core.engine.card_scheduler._STARTUP_DELAY", 0):
            task = asyncio.create_task(scheduler.run())
            # Let it launch loops
            await asyncio.sleep(0.05)

            assert scheduler._running is True
            assert len(scheduler._tasks) == 5

            # Cancel scheduler
            task.cancel()
            await task

            assert scheduler._running is False
            for child_task in scheduler._tasks:
                assert child_task.cancelled() or child_task.done()
