"""
Usage Tracking — Token costs and investigation metrics.

Logs token usage and estimated cost to console after each investigation turn.
"""

import logging

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
        def _to_int(val) -> int:
            if isinstance(val, bool) or not isinstance(val, (int, float, str)):
                return 0
            try:
                return max(0, int(val))
            except (ValueError, TypeError):
                return 0

        p_tok, c_tok, t_tok = 0, 0, 0
        if response:
            usage = None
            if hasattr(response, 'usage_metadata'):
                usage = response.usage_metadata
            elif isinstance(response, dict) and 'usage_metadata' in response:
                usage = response['usage_metadata']

            if usage:
                if isinstance(usage, dict):
                    p_tok = _to_int(usage.get('prompt_token_count', 0))
                    c_tok = _to_int(usage.get('candidates_token_count', 0))
                    t_tok = _to_int(usage.get('thoughts_token_count', 0))
                else:
                    p_tok = _to_int(getattr(usage, 'prompt_token_count', 0))
                    c_tok = _to_int(getattr(usage, 'candidates_token_count', 0))
                    t_tok = _to_int(getattr(usage, 'thoughts_token_count', 0))

        if p_tok == 0 and c_tok == 0 and t_tok == 0:
            return

        # Thinking tokens are billed at the output rate.
        cost = (p_tok / 1_000_000 * self.price_input) + \
               ((c_tok + t_tok) / 1_000_000 * self.price_output)

        logger.info(
            f"[USAGE] [{trace_id}] in={p_tok} out={c_tok} think={t_tok} "
            f"cost=${cost:.4f} tools=[{tool_summary}]"
        )

        if self.callback:
            try:
                import inspect
                sig = inspect.signature(self.callback)
                params = list(sig.parameters.values())
                has_var = any(
                    p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
                    for p in params
                )
                if has_var or len(params) >= 4:
                    self.callback(self.model_name, p_tok, c_tok, t_tok)
                else:
                    self.callback(self.model_name, p_tok, c_tok + t_tok)
            except Exception as e:
                logger.warning(f"Usage callback failed: {e}")


