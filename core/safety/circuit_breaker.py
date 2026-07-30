"""
Circuit Breaker — Safety Governor
Detects infinite loops and runaway tool execution to prevent resource exhaustion.
"""
import hashlib
import json
import logging

logger = logging.getLogger(__name__)

class CircuitBreakerError(Exception):
    """Raised when the Circuit Breaker trips."""
    pass

class CircuitBreaker:
    """
    Safety governor for the agentic tool loop.
    Prevents runaway scenarios, infinite loops, and token waste.
    """
    def __init__(self, max_steps=15, max_loops=3):
        self.max_steps = max_steps
        self.max_loops = max_loops
        self.step_count = 0
        self.tool_history = [] # List of (tool_name, tool_args_hash)

    def tick(self):
        """
        Increments the step counter.
        Raises CircuitBreakerError if MAX_STEPS is exceeded.
        """
        self.step_count += 1
        if self.step_count > self.max_steps:
            logger.error(f"[BREAKER] MAX STEPS EXCEEDED ({self.max_steps}). Terminating agent loop.")
            raise CircuitBreakerError(f"CRITICAL: Agent exceeded maximum step count ({self.max_steps}). Terminating to prevent runaway resource usage.")

    def track_tool(self, tool_name, tool_args):
        """
        Records a tool execution.
        Raises CircuitBreakerError if the EXACT same tool+args is called 'max_loops' times in a row.
        """
        # Create a stable hash of the arguments
        try:
            # Sort keys to ensure {"a": 1, "b": 2} == {"b": 2, "a": 1}
            args_str = json.dumps(tool_args, sort_keys=True)
            args_hash = hashlib.sha256(args_str.encode()).hexdigest()
        except Exception:
            # Fallback for non-serializable args (unlikely in JSON tool calling)
            args_hash = str(tool_args)

        entry = (tool_name, args_hash)
        self.tool_history.append(entry)

        # Check for Loop
        # We look at the last N items. If they are ALL identical to the current one, we trip.
        # Note: We check 'max_loops' previous items + current one (so max_loops history check)
        # Actually simplest logic: count backwards how many match current.
        
        loop_count = 0
        for historic_name, historic_hash in reversed(self.tool_history):
            if historic_name == tool_name and historic_hash == args_hash:
                loop_count += 1
            else:
                break # Sequence broken
        
        if loop_count >= self.max_loops:
             logger.error(f"[BREAKER] INFINITE LOOP DETECTED on tool '{tool_name}'.")
             raise CircuitBreakerError(f"LOOP DETECTED: Agent called '{tool_name}' with identical arguments {loop_count} times in a row.")

    def status(self):
        return {
            "steps": self.step_count,
            "max": self.max_steps,
            "health": "OK" if self.step_count < self.max_steps else "CRITICAL"
        }
