"""
Budget Guard — Per-Investigation and Daily Cost Limiter.

Prevents runaway API costs by tracking token consumption and enforcing
configurable spending caps. Integrates with brain.py's investigation loop.

Configuration via environment variables:
    BUDGET_PER_INVESTIGATION  — Max cost per single investigation (default: $2.00)
    BUDGET_PER_DAY            — Max daily aggregate cost (default: $20.00)
"""

import os
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Pricing imported from model_config at runtime to stay in sync
from core.pipeline.model_config import PRICE_PER_M_INPUT, PRICE_PER_M_OUTPUT
_DEFAULT_PRICE_INPUT = PRICE_PER_M_INPUT
_DEFAULT_PRICE_OUTPUT = PRICE_PER_M_OUTPUT


class BudgetExceededError(Exception):
    """Raised when a spending limit is reached."""
    pass


@dataclass
class BudgetGuard:
    """
    Tracks token costs and enforces per-investigation + daily caps.
    
    Usage:
        guard = BudgetGuard()
        guard.reset_investigation()
        guard.record_usage(prompt_tokens=500, response_tokens=200)
        # Raises BudgetExceededError if limit is hit
    """
    max_per_investigation: float = field(default_factory=lambda: float(
        os.getenv("BUDGET_PER_INVESTIGATION", "2.00")
    ))
    max_per_day: float = field(default_factory=lambda: float(
        os.getenv("BUDGET_PER_DAY", "20.00")
    ))
    price_input: float = _DEFAULT_PRICE_INPUT
    price_output: float = _DEFAULT_PRICE_OUTPUT

    # Internal state
    _investigation_cost: float = field(default=0.0, init=False)
    _daily_cost: float = field(default=0.0, init=False)
    _daily_reset_time: float = field(default_factory=time.time, init=False)
    _SECONDS_PER_DAY: float = field(default=86400.0, init=False, repr=False)

    def reset_investigation(self):
        """Reset per-investigation counter. Call at start of each investigate()."""
        self._investigation_cost = 0.0
        self._maybe_reset_daily()

    def _maybe_reset_daily(self):
        """Reset daily counter if 24h have elapsed since last reset."""
        now = time.time()
        if now - self._daily_reset_time >= self._SECONDS_PER_DAY:
            logger.info(f"[BUDGET] Daily counter reset (previous: ${self._daily_cost:.4f})")
            self._daily_cost = 0.0
            self._daily_reset_time = now

    def _compute_cost(self, prompt_tokens: int, response_tokens: int) -> float:
        """Calculate cost from token counts using model pricing."""
        input_cost = (prompt_tokens / 1_000_000) * self.price_input
        output_cost = (response_tokens / 1_000_000) * self.price_output
        return input_cost + output_cost

    def record_usage(self, prompt_tokens: int, response_tokens: int) -> float:
        """
        Record token usage and check against limits.
        
        Args:
            prompt_tokens: Number of input tokens consumed
            response_tokens: Number of output tokens consumed
            
        Returns:
            Total cost of this call.
            
        Raises:
            BudgetExceededError if either limit is exceeded.
        """
        self._maybe_reset_daily()
        cost = self._compute_cost(prompt_tokens, response_tokens)
        self._investigation_cost += cost
        self._daily_cost += cost

        # Check per-investigation limit
        if self._investigation_cost > self.max_per_investigation:
            raise BudgetExceededError(
                f"Investigation budget exceeded: ${self._investigation_cost:.4f} "
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

    @property
    def investigation_cost(self) -> float:
        return self._investigation_cost

    @property
    def daily_cost(self) -> float:
        self._maybe_reset_daily()
        return self._daily_cost

    def get_status(self) -> str:
        """Human-readable budget status for logging/debugging."""
        return (
            f"Investigation: ${self._investigation_cost:.4f}/${self.max_per_investigation:.2f} | "
            f"Daily: ${self._daily_cost:.4f}/${self.max_per_day:.2f}"
        )
