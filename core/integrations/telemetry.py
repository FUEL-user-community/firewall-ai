"""
Usage Tracking — Token costs and investigation metrics.

Logs token usage and estimated cost to console after each investigation turn.
"""

import logging
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class UsageTracker:
    """Tracks token usage and cost per investigation."""

    def __init__(self, model_name, price_input, price_output):
        self.model_name = model_name
        try:
            self.price_input = float(price_input or 0.0)
        except (ValueError, TypeError):
            self.price_input = 0.0
        try:
            self.price_output = float(price_output or 0.0)
        except (ValueError, TypeError):
            self.price_output = 0.0
        self.callback = None

    def set_callback(self, callback):
        self.callback = callback

    def track(self, response, latency_ms=0, success=True, tray="#core",
              ops_count=0, trace_id="", tool_summary=""):
        """Extract token usage from response and log to console."""
        p_tok, c_tok = 0, 0
        if response:
            usage = None
            if hasattr(response, 'usage_metadata'):
                usage = response.usage_metadata
            elif isinstance(response, dict) and 'usage_metadata' in response:
                usage = response['usage_metadata']

            if usage:
                if isinstance(usage, dict):
                    p_tok = int(usage.get('prompt_token_count', 0) or 0)
                    c_tok = int(usage.get('candidates_token_count', 0) or 0)
                else:
                    p_tok = int(getattr(usage, 'prompt_token_count', 0) or 0)
                    c_tok = int(getattr(usage, 'candidates_token_count', 0) or 0)

        if p_tok == 0 and c_tok == 0:
            return

        cost = (p_tok / 1_000_000 * self.price_input) + \
               (c_tok / 1_000_000 * self.price_output)

        logger.info(
            f"[USAGE] [{trace_id}] in={p_tok} out={c_tok} "
            f"cost=${cost:.4f} tools=[{tool_summary}]"
        )

        if self.callback:
            try:
                self.callback(self.model_name, p_tok, c_tok)
            except Exception as e:
                logger.warning(f"Usage callback failed: {e}")


@contextmanager
def _noop_trace_tool(tool_name: str, trace_id: str = "", user_id: str = "", **extra_attrs):
    """No-op context manager. Kept for compatibility with tool_executor.py."""
    yield type('Span', (), {
        'set_attribute': lambda self, k, v: None,
        'set_status': lambda self, s: None,
        'add_event': lambda self, n, **kw: None,
        'record_exception': lambda self, e: None,
    })()
