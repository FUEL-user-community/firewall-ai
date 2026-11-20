"""
Budget Guard — Per-Investigation and Daily Cost Limiter.
Tracks token consumption and enforces spending caps with trace-level isolation (H4).
"""
import os
import time
import logging
import threading
from typing import Optional, Dict
from dataclasses import dataclass, field

from core.pipeline.model_config import PRICE_PER_M_INPUT, PRICE_PER_M_OUTPUT

logger = logging.getLogger(__name__)

__all__ = ["BudgetGuard", "BudgetExceededError"]


class BudgetExceededError(Exception):
    """Raised when a spending limit is reached."""
    pass


@dataclass
class BudgetGuard:
    """
    Tracks token costs and enforces spending caps.
    Thread-safe and trace-isolated to prevent multi-user budget interference (H4).
    """
    max_per_investigation: float = field(default_factory=lambda: float(
        os.getenv("BUDGET_PER_INVESTIGATION", "2.00")
    ))
    max_per_day: float = field(default_factory=lambda: float(
        os.getenv("BUDGET_PER_DAY", "20.00")
    ))
    price_input: float = PRICE_PER_M_INPUT
    price_output: float = PRICE_PER_M_OUTPUT
    persist_shared: bool = field(default_factory=lambda: os.getenv("NEO_PERSIST_BUDGET", "0").strip() in ("1", "true", "yes"))

    # RLock: public methods call each other while holding the lock (e.g. get_status).
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _investigation_costs: Dict[str, float] = field(default_factory=dict, init=False, repr=False)
    _default_cost: float = field(default=0.0, init=False)
    _daily_cost: float = field(default=0.0, init=False)
    _daily_reset_time: float = field(default_factory=time.time, init=False)
    _SECONDS_PER_DAY: float = field(default=86400.0, init=False, repr=False)

    def __post_init__(self):
        if self.persist_shared:
            try:
                from core.forge.state_store import get_shared_store
                self._daily_cost = get_shared_store().get_daily_spend()
            except Exception as e:
                logger.debug(f"[BUDGET] Shared state load skipped: {e}")

    def reset_investigation(self, trace_id: Optional[str] = None):
        """Reset expenditure counter for a specific trace_id without wiping other sessions (H4)."""
        with self._lock:
            if trace_id:
                self._investigation_costs[trace_id] = 0.0
            else:
                self._default_cost = 0.0
                self._investigation_costs.clear()
            self._maybe_reset_daily()

    def _maybe_reset_daily(self):
        """Reset daily counter if 24h have elapsed since last reset."""
        now = time.time()
        if now - self._daily_reset_time >= self._SECONDS_PER_DAY:
            logger.info(f"[BUDGET] Daily counter reset (previous: ${self._daily_cost:.4f})")
            self._daily_cost = 0.0
            self._daily_reset_time = now

    @staticmethod
    def _safe_tokens(value) -> int:
        """Coerce a token count to a non-negative int (None/garbage -> 0)."""
        try:
            return max(0, int(value or 0))
        except (ValueError, TypeError):
            return 0

    def _compute_cost(self, prompt_tokens: int, response_tokens: int, thoughts_tokens: int = 0) -> float:
        """
        Calculate cost from token counts using model pricing.

        cost = p/1e6 * price_in + (r + t)/1e6 * price_out
        Thinking tokens (t) are billed at the output rate but reported separately
        by Gemini (usage_metadata.thoughts_token_count), so they must be added explicitly.
        """
        safe_p = self._safe_tokens(prompt_tokens)
        safe_out = self._safe_tokens(response_tokens) + self._safe_tokens(thoughts_tokens)
        input_cost = (safe_p / 1_000_000) * self.price_input
        output_cost = (safe_out / 1_000_000) * self.price_output
        return input_cost + output_cost

    # Bounded trace map: prune to _TRACE_PRUNE_TO when _TRACE_MAX is reached.
    _TRACE_MAX: int = field(default=1000, init=False, repr=False)
    _TRACE_PRUNE_TO: int = field(default=800, init=False, repr=False)

    def record_usage(
        self,
        prompt_tokens: int,
        response_tokens: int,
        trace_id: Optional[str] = None,
        thoughts_tokens: int = 0,
    ) -> float:
        """Record token usage and check against limits with thread synchronization."""
        with self._lock:
            self._maybe_reset_daily()
            cost = self._compute_cost(prompt_tokens, response_tokens, thoughts_tokens)

            if trace_id:
                # LRU order: pop + reinsert moves the active trace to the end,
                # so pruning evicts least-recently-updated traces, never the live one.
                prev = self._investigation_costs.pop(trace_id, 0.0)
                if len(self._investigation_costs) >= self._TRACE_MAX:
                    excess = len(self._investigation_costs) - self._TRACE_PRUNE_TO
                    for k in list(self._investigation_costs.keys())[:excess]:
                        del self._investigation_costs[k]
                current_inv = prev + cost
                self._investigation_costs[trace_id] = current_inv
            else:
                self._default_cost += cost
                current_inv = self._default_cost

            if self.persist_shared:
                try:
                    from core.forge.state_store import get_shared_store
                    self._daily_cost = get_shared_store().add_daily_spend(cost)
                except Exception as e:
                    logger.debug(f"[BUDGET] Shared state persist fallback: {e}")
                    self._daily_cost += cost
            else:
                self._daily_cost += cost

            # Check per-investigation limit
            if current_inv > self.max_per_investigation:
                raise BudgetExceededError(
                    f"Investigation budget exceeded: ${current_inv:.4f} "
                    f"(limit: ${self.max_per_investigation:.2f}). "
                    "Partial results will be synthesized."
                )

            # Check daily limit
            if self._daily_cost > self.max_per_day:
                raise BudgetExceededError(
                    f"Daily budget exceeded: ${self._daily_cost:.4f} "
                    f"(limit: ${self.max_per_day:.2f}). "
                    "Agent throttled until daily reset."
                )

            return cost

    def get_investigation_cost(self, trace_id: Optional[str] = None) -> float:
        with self._lock:
            if trace_id:
                return self._investigation_costs.get(trace_id, 0.0)
            return self._default_cost

    @property
    def daily_cost(self) -> float:
        with self._lock:
            self._maybe_reset_daily()
            return self._daily_cost

    def get_status(self, trace_id: Optional[str] = None) -> str:
        with self._lock:
            inv_cost = (
                self._investigation_costs.get(trace_id, 0.0) if trace_id else self._default_cost
            )
            return (
                f"Investigation: ${inv_cost:.4f}/${self.max_per_investigation:.2f} | "
                f"Daily: ${self._daily_cost:.4f}/${self.max_per_day:.2f}"
            )
