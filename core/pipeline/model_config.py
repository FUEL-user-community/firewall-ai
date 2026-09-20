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

# Investigation keyword triggers
_INVESTIGATION_KEYWORDS = ["audit", "root", "threat", "investigate", "compromise"]

# Max turns for the agentic loop
MAX_TURNS = 14

# Probe budget for Range simulation (allows multi-hop traversal before forced synthesis)
RANGE_PROBE_LIMIT = 7


def classify_mode(query: str, target_mode: str = "default") -> str:
    """
    Returns 'range', 'investigate', or 'diagnostic' based on target_mode and query keywords.
    Used to select thinking_level and output format.
    """
    if target_mode == "range":
        return "range"
    if any(k in query.lower() for k in _INVESTIGATION_KEYWORDS):
        return "investigate"
    return "diagnostic"


def get_thinking_level(mode: str) -> str:
    """Returns the thinking_level for the given mode."""
    if mode == "range":
        return THINKING_LEVEL_RANGE
    if mode == "investigate":
        return THINKING_LEVEL_INVESTIGATE
    return THINKING_LEVEL_DIAGNOSTIC


def get_generation_config(target_mode: str = "default") -> genai.types.GenerationConfig:
    """
    Returns GenerationConfig compliant with Gemini 3.8 Flash specifications.
    Deprecated sampling parameters (temperature, top_p, top_k) stripped per Google TechDocs.
    """
    config_kwargs = {
        "max_output_tokens": 16384
    }
    return genai.types.GenerationConfig(**config_kwargs)


def get_card_generation_config() -> genai.types.GenerationConfig:
    """
    Returns the card-specific generation config.
    Used by CardRunner for structured synthesis.
    """
    return genai.types.GenerationConfig(
        max_output_tokens=4096,
        response_mime_type="application/json",
    )

