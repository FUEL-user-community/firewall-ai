"""
CardScheduler — Async Daemon for Autonomous Card Execution.

Manages all card schedules: continuous (5m), periodic (30m), daily, weekly.
Runs as a FastAPI background task via asyncio.create_task().

Design:
  - Round-robin execution within each schedule tier
  - Non-blocking: runs tool chains in thread executor
  - Independent BudgetGuard (won't consume chat budget)
  - SSE broadcast on new card results
"""

import os
import time
import asyncio
import logging
import threading
from typing import Optional, Dict, List, Callable
from datetime import datetime, timezone

from core.engine.card_runner import CardRunner
from core.engine.card_store import CardStore
from core.engine.baseline import BaselineEngine

logger = logging.getLogger(__name__)

# Schedule intervals (seconds)
_CONTINUOUS_INTERVAL = 300     # 5 minutes
_PERIODIC_INTERVAL = 1800      # 30 minutes
_DAILY_INTERVAL = 86400        # 24 hours
_WEEKLY_INTERVAL = 604800      # 7 days

# Pause between consecutive card runs in the same tier to prevent resource spikes (L1)
_INTER_CARD_DELAY = 2

# Startup delay — let the server fully initialize before first card run (L2 safe parsing)
try:
    _STARTUP_DELAY = max(0, int(os.getenv("CARD_STARTUP_DELAY", "30")))
except ValueError:
    _STARTUP_DELAY = 30


class CardScheduler:
    """
    Async daemon that manages all card schedules.
    Singleton — one scheduler per process.
    """

    _instance: Optional['CardScheduler'] = None
    _lock = threading.Lock()

    def __init__(self):
        self.runner = CardRunner()
        self.store = CardStore.get_instance()
        self._running = False
        self._enabled = os.getenv("CARD_ENGINE_ENABLED", "false").lower() == "true"
        self._card_subscribers: List[Callable] = []
        self._subscriber_lock = threading.Lock()        # Thread-safe pub/sub (AUDIT-1)
        self._state_lock = threading.Lock()             # Thread-safe override mutation (AUDIT-3)
        self._schedule_overrides: Dict[str, bool] = {}  # card_key → enabled/disabled
        self._last_run: Dict[str, float] = {}           # card_key → last execution timestamp
        self._tasks: List[asyncio.Task] = []            # Active daemon tasks for clean cancellation (H3)

        # Restore past execution timestamps from DB to prevent startup thundering herd (M3)
        self._init_last_run_timestamps()

        # Track next scheduled run for API display
        self._next_runs: Dict[str, float] = {}

        logger.info(f"[Scheduler] Initialized (enabled={self._enabled})")

    @classmethod
    def get_instance(cls) -> 'CardScheduler':
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _init_last_run_timestamps(self):
        """
        Loads the most recent execution timestamp for each card from CardStore (M3).
        Prevents all daily and weekly cards from firing simultaneously upon reboot.
        """
        try:
            conn = self.store._get_conn()
            cursor = conn.execute(
                "SELECT card_key, MAX(timestamp) as last_ts FROM card_results GROUP BY card_key"
            )
            for row in cursor.fetchall():
                if row["card_key"] and row["last_ts"] is not None:
                    self._last_run[row["card_key"]] = float(row["last_ts"])
            if self._last_run:
                logger.info(f"[Scheduler] Restored execution timestamps for {len(self._last_run)} card(s) from DB")
        except Exception as e:
            logger.warning(f"[Scheduler] Could not restore card timestamps from DB: {e}")

    def subscribe(self, callback: Callable):
        """Register a callback for new card results (SSE broadcasting) (AUDIT-1)."""
        with self._subscriber_lock:
            if callback not in self._card_subscribers:
                self._card_subscribers.append(callback)

    def unsubscribe(self, callback: Callable):
        """Unregister a callback safely (AUDIT-1)."""
        with self._subscriber_lock:
            if callback in self._card_subscribers:
                self._card_subscribers.remove(callback)

    def _notify_subscribers(self, card_result_dict: Dict):
        """Notify all subscribers using a thread-safe snapshot to prevent mutation during iteration (AUDIT-1)."""
        with self._subscriber_lock:
            subscribers = list(self._card_subscribers)
        for cb in subscribers:
            try:
                cb(card_result_dict)
            except Exception as e:
                logger.debug(f"[Scheduler] Subscriber notification error: {e}")

    # ─── SCHEDULE MANAGEMENT ──────────────────────────────────────────

    def enable_card(self, card_key: str):
        """Enable a specific card."""
        if card_key == "all":
            self.set_all_cards(True)
            return
        with self._state_lock:
            self._schedule_overrides[card_key] = True
        logger.info(f"[Scheduler] Enabled: {card_key}")

    def disable_card(self, card_key: str):
        """Disable a specific card."""
        if card_key == "all":
            self.set_all_cards(False)
            return
        with self._state_lock:
            self._schedule_overrides[card_key] = False
        logger.info(f"[Scheduler] Disabled: {card_key}")

    def set_all_cards(self, enabled: bool):
        """Enable or disable all registered cards."""
        cards = self.runner.load_cards()
        with self._state_lock:
            self._all_cards_default = enabled
            for card_key in cards:
                self._schedule_overrides[card_key] = enabled
        logger.info(f"[Scheduler] Set all cards enabled={enabled} (total: {len(cards)})")

    def is_card_enabled(self, card_key: str) -> bool:
        """Check if a card is enabled (default: True or _all_cards_default)."""
        with self._state_lock:
            return self._schedule_overrides.get(card_key, getattr(self, '_all_cards_default', True))

    def get_schedule_status(self) -> List[Dict]:
        """Get the current schedule status for all cards."""
        cards = self.runner.load_cards()
        status = []

        for card_key, card_def in cards.items():
            card_id = card_def.get("id", card_key)
            schedule = card_def.get("schedule", "daily")
            try:
                interval = int(card_def.get("interval_seconds") or _DAILY_INTERVAL)
            except (ValueError, TypeError):
                interval = _DAILY_INTERVAL

            enabled = self.is_card_enabled(card_key)
            last_run = self._last_run.get(card_key, 0.0)
            next_run = self._next_runs.get(card_key, 0.0)

            status.append({
                "card_key": card_key,
                "card_id": card_id,
                "name": card_def.get("name", card_key),
                "description": card_def.get("description", ""),
                "severity": card_def.get("severity", "normal"),
                "schedule": schedule,
                "interval_seconds": interval,
                "tool_count": len(card_def.get("tool_chain") or []),
                "enabled": enabled,
                "last_run": last_run,
                "last_run_human": datetime.fromtimestamp(last_run, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if (last_run and last_run > 0) else "Never",
                "next_run": next_run,
                "next_run_human": datetime.fromtimestamp(next_run, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if (next_run and next_run > 0) else "Pending",
            })

        return status

    # ─── MAIN DAEMON LOOP ─────────────────────────────────────────────

    async def run(self):
        """
        Main daemon loop. Launched as asyncio.create_task() from server startup.
        Runs continuously until stopped.
        """
        if not self._enabled:
            logger.info("[Scheduler] Card engine is disabled (CARD_ENGINE_ENABLED=false)")
            return

        self._running = True
        logger.info(f"[Scheduler] ▶ Starting card engine (delay={_STARTUP_DELAY}s)")

        # Startup delay — let server and connections initialize
        try:
            await asyncio.sleep(_STARTUP_DELAY)
        except asyncio.CancelledError:
            self._running = False
            logger.info("[Scheduler] Card engine cancelled during startup delay")
            return

        logger.info("[Scheduler] ▶ Card engine active — beginning schedule loops")

        # Launch concurrent schedule loops as explicit tasks (H3)
        self._tasks = [
            asyncio.create_task(self._schedule_loop("continuous", _CONTINUOUS_INTERVAL)),
            asyncio.create_task(self._schedule_loop("periodic", _PERIODIC_INTERVAL)),
            asyncio.create_task(self._schedule_loop("daily", _DAILY_INTERVAL)),
            asyncio.create_task(self._schedule_loop("weekly", _WEEKLY_INTERVAL)),
            asyncio.create_task(self._maintenance_loop()),
        ]

        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            logger.info("[Scheduler] Card engine cancellation received — terminating schedule loops")
            for t in self._tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._running = False
        except Exception as e:
            logger.error(f"[Scheduler] Fatal error: {e}")
            self._running = False

    async def _schedule_loop(self, schedule_type: str, default_interval: int):
        """
        Run all cards matching a schedule type in round-robin.
        Each card respects its own interval_seconds.
        """
        logger.info(f"[Scheduler] [{schedule_type}] Loop started (default interval: {default_interval}s)")

        while self._running:
            try:
                cards = self.runner.get_cards_by_schedule(schedule_type)

                if not cards:
                    await asyncio.sleep(60)  # No cards — check again in a minute
                    continue

                for card_key, card_def in cards.items():
                    if not self._running:
                        return

                    if not self.is_card_enabled(card_key):
                        continue

                    # Check if enough time has passed since last run with defensive int coercion (AUDIT-2)
                    try:
                        interval = int(card_def.get("interval_seconds") or default_interval)
                    except (ValueError, TypeError):
                        interval = default_interval

                    last_run = self._last_run.get(card_key, 0.0)
                    now = time.time()

                    if now - last_run < interval:
                        # Not time yet — update next_run and skip
                        self._next_runs[card_key] = last_run + interval
                        continue

                    # Execute card in thread executor (non-blocking)
                    logger.info(f"[Scheduler] [{schedule_type}] Running: {card_key}")
                    self._next_runs[card_key] = now + interval
                    target_device = card_def.get("device", "default")

                    try:
                        loop = asyncio.get_running_loop()  # Python 3.10+ / 3.12+ non-deprecated (H1)
                        result = await loop.run_in_executor(
                            None,
                            lambda ck=card_key, dev=target_device: self.runner.execute(ck, device=dev)
                        )

                        self._last_run[card_key] = time.time()

                        if result and hasattr(result, 'id') and result.id:
                            # Notify subscribers (SSE broadcast) (M4 safe lookup)
                            result_dict = self.store.get_by_id(result.id)
                            if result_dict:
                                self._notify_subscribers(result_dict)

                    except Exception as e:
                        logger.error(f"[Scheduler] [{schedule_type}] {card_key} execution error: {e}")
                        self._last_run[card_key] = time.time()  # Prevent retry storm

                    # Brief pause between cards in the same tier (L1)
                    await asyncio.sleep(_INTER_CARD_DELAY)

                # After running through all cards, sleep for a fraction of the interval
                # to allow for timely execution of newly due cards
                await asyncio.sleep(min(30, default_interval // 10))

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"[Scheduler] [{schedule_type}] Loop error: {e}")
                await asyncio.sleep(60)  # Backoff on error

    async def _maintenance_loop(self):
        """Periodic maintenance: expire old cards by TTL, clean historical baselines."""
        while self._running:
            try:
                # Expire old cards based on TTL_MAP (24h continuous, 3d periodic, 7d daily, 14d weekly) (L3)
                expired = self.store.expire_old()

                # Clean old baseline data older than 30 days (M2 module-level import)
                baseline = BaselineEngine.get_instance()
                baseline.cleanup_old(days=30)

            except Exception as e:
                logger.debug(f"[Scheduler] Maintenance error: {e}")

            await asyncio.sleep(3600)  # Run maintenance every hour

    def stop(self):
        """Signal the daemon to stop and cancel active task loops (H3)."""
        self._running = False
        for t in getattr(self, '_tasks', []):
            if not t.done():
                t.cancel()
        logger.info("[Scheduler] Stop signal sent and child loops cancelled")

    @classmethod
    def reset(cls):
        """Reset singleton with thread synchronization — for testing (H2)."""
        with cls._lock:
            if cls._instance:
                cls._instance.stop()
            cls._instance = None
