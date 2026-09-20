"""
ModelConfig — Gemini Model Constants, Mode Classification, and Generation Config.

Single responsibility: centralize all model-specific configuration so brain.py
doesn't need to know about model strings, pricing, temperature constraints,
or thinking level semantics.
"""

import os
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import google.generativeai as genai


# =============================================================================
# Model Identity
# =============================================================================

# Gemini 3.1 Pro — frontier reasoning with dynamic thinking.
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.1-pro-preview")

# Gemini Flash — fast, cheap model for the Debate Protocol auditor.
FLASH_MODEL = os.getenv("FLASH_MODEL", "gemini-3.6-flash")

# Embedding model — for Semantic Drift Tracking.
# text-embedding-004 supports Matryoshka (flexible dimensionality).
EMBEDDING_MODEL = "gemini-embedding-001"
EMBEDDING_DIMENSIONS = int(os.getenv("EMBEDDING_DIMENSIONS", "3072"))

# =============================================================================
# Financial Telemetry (Pricing per 1M tokens)
# =============================================================================

PRICE_PER_M_INPUT = 1.25
PRICE_PER_M_OUTPUT = 10.00

# =============================================================================
# Temperature & Thinking Level
# =============================================================================

# Temperature MUST be 1.0. Lower values cause looping/degradation on Gemini 3.
# Internal thinking_level handles determinism natively.
TEMP_DEFAULT = 1.0

# Thinking level configuration
# "high" = maximum reasoning depth (default for investigations)
# "medium" = balanced speed/depth (for health checks)
# "low" = minimal reasoning (for simple lookups)
THINKING_LEVEL_INVESTIGATE = "high"
THINKING_LEVEL_DIAGNOSTIC = "medium"

# Investigation keyword triggers
_INVESTIGATION_KEYWORDS = ["audit", "root", "threat", "investigate", "compromise", "attack"]

# Max turns for the agentic loop
# Increased from 10 to 14 — thought signatures eliminate attention coherence decay.
MAX_TURNS = 14


def classify_mode(query: str) -> str:
    """
    Returns 'investigate' or 'diagnostic' based on query keywords.
    Used to select thinking_level and output format.
    """
    if any(k in query.lower() for k in _INVESTIGATION_KEYWORDS):
        return "investigate"
    return "diagnostic"


def get_thinking_level(mode: str) -> str:
    """Returns the thinking_level for the given mode."""
    if mode == "investigate":
        return THINKING_LEVEL_INVESTIGATE
    return THINKING_LEVEL_DIAGNOSTIC


def get_generation_config() -> genai.types.GenerationConfig:
    """
    Returns the standard Gemini 3 generation config.
    Temperature locked at 1.0, output capped at 16K tokens.
    """
    return genai.types.GenerationConfig(
        temperature=TEMP_DEFAULT,
        max_output_tokens=16384  # Supports 64K output, using 16K for investigation depth
    )


def get_card_generation_config() -> genai.types.GenerationConfig:
    """
    Returns the card-specific generation config with logprobs enabled.
    Used by CardRunner for visibility into the model's internal uncertainty.
    """
    return genai.types.GenerationConfig(
        temperature=TEMP_DEFAULT,
        max_output_tokens=4096,
        response_logprobs=True,
        logprobs=5,
    )

