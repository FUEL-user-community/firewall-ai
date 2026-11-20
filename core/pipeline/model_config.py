"""
ModelConfig — Gemini Model Constants, Mode Classification, and Generation Config.

Single responsibility: centralize all model-specific configuration so brain.py
doesn't need to know about model strings, pricing, temperature constraints,
or thinking level semantics.
"""

import os
import re
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import google.generativeai as genai


# =============================================================================
# Model Identity
# =============================================================================

# Gemini 3.1 Pro — frontier reasoning with dynamic thinking.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-pro-preview")

# Gemini Flash — lightweight fast tier.
FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-2.5-flash")

# =============================================================================
# Financial Telemetry (Pricing per 1M tokens)
# =============================================================================

PRICE_PER_M_INPUT = 1.25
PRICE_PER_M_OUTPUT = 10.00

# =============================================================================
# Thinking Level Configuration
# =============================================================================

# Dynamic thinking handles reasoning and determinism natively per Gemini 3 specs.
# Manual sampling parameters (temperature, top_p, top_k) are stripped.

# Thinking level configuration
# "high" = maximum reasoning depth (reserved for deep forensic investigations)
# "medium" = balanced speed/depth (default for health checks and Range simulations)
# "low" = minimal reasoning (for latency-critical simple lookups)
THINKING_LEVEL_INVESTIGATE = "high"
THINKING_LEVEL_DIAGNOSTIC = "medium"
THINKING_LEVEL_RANGE = "medium"
THINKING_LEVEL_ADVISORY = "high"

# Investigation keyword triggers — word boundaries (\b) prevent false positives
# (e.g. 'fiber' matching 'fib', 'download' matching 'down', 'history' matching 'to').
_INVESTIGATION_WORDS = [
    # Failure & packet drop triggers
    r"drop", r"dropped", r"block", r"blocked", r"deny", r"denied", r"reject", r"rejected",
    r"down", r"fail", r"failing", r"failed", r"unreachable", r"timeout", r"reset",
    # Root cause & path inquiry terms
    r"why", r"how\s+come", r"path", r"packet", r"flow", r"trace", r"route\s+to", r"fib",
    r"pbf", r"nat\s+match", r"policy\s+match", r"root\s+cause",
    # Threat & deep forensic triggers
    r"threat", r"audit", r"compromise", r"exploit", r"anomaly", r"investigate",
]

_INVESTIGATION_PATTERN = re.compile(
    r'\b(?:' + '|'.join(_INVESTIGATION_WORDS) + r')\b',
    re.IGNORECASE
)

_DIRECTIONAL_PATTERN = re.compile(
    r'\b(?:to|reach|dest|destination|from|blocked)\b',
    re.IGNORECASE
)

_IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Max turns for the agentic loop
MAX_TURNS = 14


def classify_mode(query: str, target_mode: str = "default") -> str:
    """
    Returns 'advisory', 'investigate', or 'diagnostic' based on target_mode and query intent.
    Explicit caller target_mode ('diagnostic', 'resident', 'investigate', 'advisory') always wins;
    keyword regexes run ONLY when target_mode is 'default' or unset.
    """
    explicit = (target_mode or "default").strip().lower()
    if explicit == "resident":
        return "diagnostic"
    if explicit in ("diagnostic", "investigate", "advisory"):
        return explicit
    if not query or not isinstance(query, str):
        return "diagnostic"

    if _INVESTIGATION_PATTERN.search(query):
        return "investigate"

    if _IP_PATTERN.search(query) and _DIRECTIONAL_PATTERN.search(query):
        return "investigate"

    return "diagnostic"


def get_thinking_level(mode: str) -> str:
    """Returns the thinking_level for the given mode."""
    if mode in ("investigate", "advisory"):
        return THINKING_LEVEL_INVESTIGATE
    return THINKING_LEVEL_DIAGNOSTIC


def get_generation_config(target_mode: str = "default") -> genai.types.GenerationConfig:
    """Returns GenerationConfig with full output token budget."""
    return genai.types.GenerationConfig(max_output_tokens=16384)



