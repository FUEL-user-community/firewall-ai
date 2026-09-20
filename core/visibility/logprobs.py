"""
Logprob Extraction & Entropy Scoring.

Extracts token-level probability distributions from Gemini API responses.
Computes confidence margins and entropy scores to surface the model's
internal uncertainty on critical classification decisions.

The key insight: if the model outputs "CRITICAL" but was internally torn
between CRITICAL (52%) and CAUTION (47%), that 5% margin should trigger
human review — not blind trust in the output text.
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Canonical mapping from synonyms and BPE subwords to core severity tiers
_SEVERITY_CANONICAL_MAP = {
    # Critical tier
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "sever": "critical",
    "fatal": "critical",
    "high": "critical",
    "p1": "critical",

    # Caution tier
    "caution": "caution",
    "caut": "caution",
    "warning": "caution",
    "warn": "caution",
    "medium": "caution",
    "med": "caution",
    "moderate": "caution",
    "p2": "caution",

    # Normal tier
    "normal": "normal",
    "norm": "normal",
    "low": "normal",
    "info": "normal",
    "healthy": "normal",
    "clean": "normal",
    "p3": "normal",
}

_CLEAN_TOKEN_RE = re.compile(r'[^a-zA-Z0-9]')

# If the margin between top-2 tokens for a severity decision is below this,
# the model is internally uncertain and should flag for human review.
ENTROPY_HITL_THRESHOLD = 0.10  # 10% margin


@dataclass
class LogprobResult:
    """Parsed logprob data from a single Gemini response."""
    confidence_margin: Optional[float] = None  # Gap between top-1 and top-2 (0.0 to 1.0)
    entropy_score: Optional[float] = None       # Shannon entropy of the distribution
    top_tokens: List[Dict[str, float]] = field(default_factory=list)  # [{token: prob}, ...]
    severity_distribution: Dict[str, float] = field(default_factory=dict)  # {CRITICAL: 0.52, ...}
    should_escalate: bool = False               # True if model is too uncertain


def extract_logprobs(response) -> LogprobResult:
    """
    Extract logprob data from a Gemini API response.

    Cleans JSON-quoted and subword tokens, clusters synonyms into canonical
    severity tiers ('critical', 'caution', 'normal'), and computes:
    1. confidence_margin — the probability gap between the top-2 canonical tiers
    2. entropy_score — normalized Shannon entropy across active tiers
    3. severity_distribution — probability mass allocated to each tier

    Falls back gracefully if the model/endpoint doesn't support logprobs.
    """
    result = LogprobResult()

    try:
        # Access logprobs from the response candidates
        if not hasattr(response, 'candidates') or not response.candidates:
            logger.debug("[LOGPROBS] No candidates in response")
            return result

        candidate = response.candidates[0]

        # The logprobs live in candidate.logprobs_result
        logprobs_result = getattr(candidate, 'logprobs_result', None)
        if logprobs_result is None:
            logger.debug("[LOGPROBS] No logprobs_result in candidate (model may not support logprobs)")
            return result

        # Iterate through all token positions looking for severity decisions
        top_candidates_list = getattr(logprobs_result, 'top_candidates', [])

        tier_probs = {"critical": 0.0, "caution": 0.0, "normal": 0.0}
        severity_found = False

        for i, top_candidates in enumerate(top_candidates_list):
            candidates = getattr(top_candidates, 'candidates', [])
            if not candidates:
                continue

            token_probs = []
            for cand in candidates:
                raw_token = getattr(cand, 'token', '')
                clean_token = _CLEAN_TOKEN_RE.sub('', raw_token).lower()
                log_prob = getattr(cand, 'log_probability', None)
                if log_prob is not None:
                    prob = math.exp(log_prob)
                    token_probs.append((clean_token or raw_token.strip(), prob))

                    canonical_tier = _SEVERITY_CANONICAL_MAP.get(clean_token)
                    if canonical_tier:
                        tier_probs[canonical_tier] += prob
                        severity_found = True

            # Store top tokens for this position (for debugging/display)
            if token_probs:
                result.top_tokens.append({t: round(p, 4) for t, p in token_probs[:5]})

        # Filter to active tiers and compute margin
        if severity_found:
            total_mass = sum(tier_probs.values())
            if total_mass > 0:
                result.severity_distribution = {k: round(v / total_mass, 4) for k, v in tier_probs.items() if v > 0}
            else:
                result.severity_distribution = {k: round(v, 4) for k, v in tier_probs.items() if v > 0}

            sorted_probs = sorted(result.severity_distribution.values(), reverse=True)
            if len(sorted_probs) >= 2:
                result.confidence_margin = round(sorted_probs[0] - sorted_probs[1], 4)
            elif len(sorted_probs) == 1:
                result.confidence_margin = round(sorted_probs[0], 4)

            # Compute Shannon entropy across canonical severity tiers
            result.entropy_score = _shannon_entropy(list(result.severity_distribution.values()))

        # Determine if this should escalate to HITL
        if result.confidence_margin is not None:
            result.should_escalate = result.confidence_margin < ENTROPY_HITL_THRESHOLD

        if severity_found:
            logger.info(
                f"[LOGPROBS] Severity distribution: {result.severity_distribution} | "
                f"Margin: {result.confidence_margin} | Escalate: {result.should_escalate}"
            )

    except Exception as e:
        logger.warning(f"[LOGPROBS] Extraction failed (graceful fallback): {e}")

    return result


def _shannon_entropy(probs: List[float]) -> float:
    """Compute normalized Shannon entropy from a probability distribution (M2)."""
    if not probs:
        return 0.0
    total = sum(p for p in probs if p > 0)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for p in probs:
        if p > 0:
            p_norm = p / total
            entropy -= p_norm * math.log2(p_norm)
    return round(entropy, 4)
