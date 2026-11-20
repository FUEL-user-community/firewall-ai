"""
Circuit Breaker — Safety Governor
Detects infinite loops and runaway tool execution to prevent resource exhaustion.
Includes periodic 2-cycle alternating loop detection (M1).
"""
import json
import hashlib
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

__all__ = ["CircuitBreaker", "CircuitBreakerError"]


class CircuitBreakerError(Exception):
    """Raised when the Circuit Breaker trips."""
    pass


class CircuitBreaker:
    """
    Safety governor for the agentic tool loop.
    Prevents runaway scenarios, infinite loops, and alternating cycle ping-ponging (M1).
    """

    def __init__(self, max_steps: int = 30, max_loops: int = 4):
        self.max_steps = max_steps
        self.max_loops = max_loops
        self.step_count = 0
        self.tool_history: List[Tuple[str, str]] = []

    def reset(self):
        """Reset breaker state for reuse."""
        self.step_count = 0
        self.tool_history.clear()

    def tick(self):
        """Increments the step counter and trips if max_steps is exceeded."""
        self.step_count += 1
        if self.step_count > self.max_steps:
            logger.error(f"[BREAKER] MAX STEPS EXCEEDED ({self.max_steps}). Terminating agent loop.")
            raise CircuitBreakerError(
                f"CRITICAL: Agent exceeded maximum step count ({self.max_steps}). "
                "Terminating to prevent runaway resource usage."
            )

    def track_tool(self, tool_name: str, tool_args: Any):
        """
        Records a tool execution.
        Raises CircuitBreakerError on consecutive identical calls or alternating 2-cycles.
        """
        try:
            args_str = json.dumps(tool_args, sort_keys=True)
            args_hash = hashlib.sha256(args_str.encode()).hexdigest()
        except Exception:
            args_hash = str(tool_args)

        entry = (tool_name, args_hash)
        self.tool_history.append(entry)

        # 1. Consecutive identical call detection
        consecutive_count = 0
        for historic_name, historic_hash in reversed(self.tool_history):
            if historic_name == tool_name and historic_hash == args_hash:
                consecutive_count += 1
            else:
                break

        if consecutive_count >= self.max_loops:
            logger.error(f"[BREAKER] INFINITE LOOP DETECTED on tool '{tool_name}'.")
            raise CircuitBreakerError(
                f"LOOP DETECTED: Agent called '{tool_name}' with identical arguments {consecutive_count} times in a row."
            )

        # 2. Periodic cycle detection for period p in [2, MAX_CYCLE_PERIOD]:
        #    trip when the last p*max_loops calls are one block of length p repeated
        #    max_loops times. p=2 is the A->B->A->B case (M1); p=3 catches A->B->C and
        #    A->A->B, which previously ran until the step cap. Cost: O(P * p * k) per call.
        period = self._detect_cycle_period()
        if period == 2:
            pattern_a, pattern_b = self.tool_history[-2], self.tool_history[-1]
            logger.error(f"[BREAKER] ALTERNATING LOOP DETECTED between '{pattern_a[0]}' and '{pattern_b[0]}'.")
            raise CircuitBreakerError(
                f"ALTERNATING LOOP DETECTED: Agent oscillating between '{pattern_a[0]}' and '{pattern_b[0]}' repeatedly."
            )
        if period:
            names = " -> ".join(n for n, _ in self.tool_history[-period:])
            logger.error(f"[BREAKER] CYCLIC LOOP DETECTED (period {period}): {names}.")
            raise CircuitBreakerError(
                f"CYCLIC LOOP DETECTED: Agent repeated the cycle [{names}] {self.max_loops} times with identical arguments."
            )

    MAX_CYCLE_PERIOD = 4

    def _detect_cycle_period(self) -> int:
        """
        Return the smallest period p in [2, MAX_CYCLE_PERIOD] such that the tail of
        tool_history is the same length-p block repeated max_loops times, else 0.
        Blocks that are a single repeated call (period 1) are left to the
        consecutive-call check above.
        """
        h = self.tool_history
        k = self.max_loops
        for p in range(2, self.MAX_CYCLE_PERIOD + 1):
            span = p * k
            if len(h) < span:
                break
            tail = h[-span:]
            block = tail[:p]
            if len(set(block)) == 1:
                continue
            if all(tail[i] == block[i % p] for i in range(span)):
                return p
        return 0

    def status(self) -> Dict[str, Any]:
        return {
            "steps": self.step_count,
            "max": self.max_steps,
            "health": "OK" if self.step_count < self.max_steps else "CRITICAL"
        }
