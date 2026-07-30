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
from typing import Optional, Dict, List, Callable, Any
from datetime import datetime

from core.engine.card_runner import CardRunner
from core.engine.card_store import CardStore

logger = logging.getLogger(__name__)

# Schedule intervals (seconds)
_CONTINUOUS_INTERVAL = 300     # 5 minutes
_PERIODIC_INTERVAL = 1800      # 30 minutes
_DAILY_INTERVAL = 86400        # 24 hours
_WEEKLY_INTERVAL = 604800      # 7 days

# Startup delay — let the server fully initialize before first card run
_STARTUP_DELAY = int(os.getenv("CARD_STARTUP_DELAY", "30"))


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
        self._schedule_overrides: Dict[str, bool] = {}  # card_key → enabled/disabled
        self._last_run: Dict[str, float] = {}  # card_key → last execution timestamp

        # Track next scheduled run for API display
        self._next_runs: Dict[str, float] = {}

        logger.info(f"[Scheduler] Initialized (enabled={self._enabled})")

    @classmethod
    def get_instance(cls) -> 'CardScheduler':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def subscribe(self, callback: Callable):
        """Register a callback for new card results (SSE broadcasting)."""
        self._card_subscribers.append(callback)

    def _notify_subscribers(self, card_result_dict: Dict):
        """Notify all subscribers of a new card result."""
        for cb in self._card_subscribers:
            try:
                cb(card_result_dict)
            except Exception as e:
                logger.debug(f"[Scheduler] Subscriber notification error: {e}")

    # ─── SCHEDULE MANAGEMENT ──────────────────────────────────────────

    def enable_card(self, card_key: str):
        """Enable a specific card."""
        self._schedule_overrides[card_key] = True
        logger.info(f"[Scheduler] Enabled: {card_key}")

    def disable_card(self, card_key: str):
        """Disable a specific card."""
        self._schedule_overrides[card_key] = False
        logger.info(f"[Scheduler] Disabled: {card_key}")

    def is_card_enabled(self, card_key: str) -> bool:
        """Check if a card is enabled (default: True)."""
        return self._schedule_overrides.get(card_key, True)

    def get_schedule_status(self) -> List[Dict]:
        """Get the current schedule status for all cards."""
        cards = self.runner.load_cards()
        status = []

        for card_key, card_def in cards.items():
            card_id = card_def.get("id", card_key)
            schedule = card_def.get("schedule", "daily")
            interval = card_def.get("interval_seconds", _DAILY_INTERVAL)
            enabled = self.is_card_enabled(card_key)
            last_run = self._last_run.get(card_key, 0)
            next_run = self._next_runs.get(card_key, 0)

            status.append({
                "card_key": card_key,
                "card_id": card_id,
                "name": card_def.get("name", card_key),
                "schedule": schedule,
                "interval_seconds": interval,
                "enabled": enabled,
                "last_run": last_run,
                "last_run_human": datetime.fromtimestamp(last_run).strftime("%H:%M:%S") if last_run else "Never",
                "next_run": next_run,
                "next_run_human": datetime.fromtimestamp(next_run).strftime("%H:%M:%S") if next_run else "Pending",
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
        await asyncio.sleep(_STARTUP_DELAY)
        logger.info("[Scheduler] ▶ Card engine active — beginning schedule loops")

        # Launch concurrent schedule loops
        try:
            await asyncio.gather(
                self._schedule_loop("continuous", _CONTINUOUS_INTERVAL),
                self._schedule_loop("periodic", _PERIODIC_INTERVAL),
                self._schedule_loop("daily", _DAILY_INTERVAL),
                self._schedule_loop("weekly", _WEEKLY_INTERVAL),
                self._maintenance_loop(),
            )
        except asyncio.CancelledError:
            logger.info("[Scheduler] Card engine stopped")
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

                    # Check if enough time has passed since last run
                    interval = card_def.get("interval_seconds", default_interval)
                    last_run = self._last_run.get(card_key, 0)
                    now = time.time()

                    if now - last_run < interval:
                        # Not time yet — update next_run and skip
                        self._next_runs[card_key] = last_run + interval
                        continue

                    # Execute card in thread executor (non-blocking)
                    logger.info(f"[Scheduler] [{schedule_type}] Running: {card_key}")
                    self._next_runs[card_key] = now + interval

                    try:
                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(
                            None,
                            lambda ck=card_key: self.runner.execute(ck)
                        )

                        self._last_run[card_key] = time.time()

                        if result:
                            # Notify subscribers (SSE broadcast)
                            result_dict = self.store.get_by_id(result.id)
                            if result_dict:
                                self._notify_subscribers(result_dict)

                    except Exception as e:
                        logger.error(f"[Scheduler] [{schedule_type}] {card_key} execution error: {e}")
                        self._last_run[card_key] = time.time()  # Prevent retry storm

                    # Brief pause between cards in the same tier
                    await asyncio.sleep(2)

                # After running through all cards, sleep for a fraction of the interval
                # to allow for timely execution of newly due cards
                await asyncio.sleep(min(30, default_interval // 10))

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"[Scheduler] [{schedule_type}] Loop error: {e}")
                await asyncio.sleep(60)  # Backoff on error

    async def _maintenance_loop(self):
        """Periodic maintenance: expire old cards, clean baselines."""
        while self._running:
            try:
                # Expire old cards
                expired = self.store.expire_old()

                # Clean old baseline data (monthly)
                from core.engine.baseline import BaselineEngine
                baseline = BaselineEngine.get_instance()
                baseline.cleanup_old(days=30)

            except Exception as e:
                logger.debug(f"[Scheduler] Maintenance error: {e}")

            await asyncio.sleep(3600)  # Run maintenance every hour

    def stop(self):
        """Signal the daemon to stop."""
        self._running = False
        logger.info("[Scheduler] Stop signal sent")

    @classmethod
    def reset(cls):
        """Reset singleton — for testing."""
        if cls._instance:
            cls._instance.stop()
        cls._instance = None
