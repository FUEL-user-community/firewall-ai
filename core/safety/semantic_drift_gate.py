"""
Semantic Drift Gate — Pre-Execution Safety Interceptor

Embeds the AI's <REASONING> trace per-turn into vector space using
Gemini's embedding API. Compares each new reasoning vector against
the rolling average of prior turns in the same investigation.

If cosine similarity drops below threshold, the gate BLOCKS further
tool execution — preventing a drifting/hallucinating agent from
touching the firewall.

Architecture:
    Turn N: LLM outputs <REASONING> → Embed → Compare to Turns 1..(N-1)
        → Similar?  → ALLOW tool calls
        → Drifted?  → BLOCK tool calls, force re-reasoning

Thresholds:
    > 0.85  = NORMAL  (coherent investigation)
    0.70-0.85 = CAUTION (warn but allow — reasoning is diverging)
    < 0.70  = CRITICAL (block — agent has lost the thread)

Cost: ~14 embedding calls per investigation (one per turn). Fractions of a penny.
"""

import math
import logging
from typing import List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DriftGateResult:
    """Result of a per-turn drift check."""
    allowed: bool = True
    severity: str = "normal"
    similarity: float = 1.0
    message: str = ""


class SemanticDriftGate:
    """
    Per-investigation drift gate. Instantiated fresh for each investigation.
    Accumulates reasoning embeddings and checks for cognitive drift
    before allowing tool execution.
    """

    # Thresholds (matching BaselineEngine for consistency)
    CAUTION_THRESHOLD = 0.85
    CRITICAL_THRESHOLD = 0.70

    # Minimum turns before drift comparison activates (cold start)
    MIN_TURNS = 1

    def __init__(self):
        self._embeddings: List[List[float]] = []
        self._reasoning_texts: List[str] = []
        self._embed_fn = None  # Lazy-loaded Gemini embedding function

    def _get_embed_fn(self):
        """Lazy-load the Gemini embedding function."""
        if self._embed_fn is None:
            try:
                import google.generativeai as genai
                def embed(text: str) -> List[float]:
                    result = genai.embed_content(
                        model="models/gemini-embedding-001",
                        content=text,
                        task_type="SEMANTIC_SIMILARITY"
                    )
                    return result['embedding']
                self._embed_fn = embed
                logger.info("[DRIFT-GATE] Gemini embedding function loaded.")
            except Exception as e:
                logger.warning(f"[DRIFT-GATE] Failed to load embedding function: {e}")
                self._embed_fn = None
        return self._embed_fn

    def check(self, reasoning_text: str, trace_id: str = "", turn: int = 0) -> DriftGateResult:
        """
        Embed the current turn's reasoning trace and compare against
        the investigation's rolling baseline.

        Args:
            reasoning_text: The extracted <REASONING> block from the LLM.
            trace_id: Investigation trace ID for logging.
            turn: Current turn number.

        Returns:
            DriftGateResult indicating whether tool execution should proceed.
        """
        if not reasoning_text or not reasoning_text.strip():
            # No reasoning to embed — allow (fail-open for safety)
            return DriftGateResult(allowed=True, message="No reasoning trace to embed.")

        embed_fn = self._get_embed_fn()
        if embed_fn is None:
            # Embedding unavailable — fail-open (don't block the investigation)
            return DriftGateResult(allowed=True, message="Embedding unavailable — skipping drift check.")

        # Embed the current reasoning trace
        try:
            current_embedding = embed_fn(reasoning_text)
        except Exception as e:
            logger.warning(f"[{trace_id}] [DRIFT-GATE] Embedding failed: {e}")
            return DriftGateResult(allowed=True, message=f"Embedding failed: {e}")

        # Store for future comparisons
        self._embeddings.append(current_embedding)
        self._reasoning_texts.append(reasoning_text)

        # Cold start — not enough history to compare
        if len(self._embeddings) <= self.MIN_TURNS:
            logger.info(f"[{trace_id}] [DRIFT-GATE] Turn {turn}: Cold start ({len(self._embeddings)}/{self.MIN_TURNS+1} traces). Allowing.")
            return DriftGateResult(allowed=True, similarity=1.0, message="Cold start — baseline accumulating.")

        # Compute rolling average of all PRIOR embeddings (exclude current)
        prior_embeddings = self._embeddings[:-1]
        dim = len(current_embedding)
        avg_embedding = [0.0] * dim
        for emb in prior_embeddings:
            for j in range(min(dim, len(emb))):
                avg_embedding[j] += emb[j]
        avg_embedding = [v / len(prior_embeddings) for v in avg_embedding]

        # Cosine similarity
        similarity = self._cosine_similarity(current_embedding, avg_embedding)

        # Evaluate
        if similarity < self.CRITICAL_THRESHOLD:
            logger.warning(
                f"[{trace_id}] [DRIFT-GATE] Turn {turn}: CRITICAL DRIFT — "
                f"cosine={similarity:.3f} (threshold={self.CRITICAL_THRESHOLD}). BLOCKING."
            )
            return DriftGateResult(
                allowed=False,
                severity="critical",
                similarity=similarity,
                message=f"SEMANTIC DRIFT CRITICAL: cosine similarity {similarity:.3f}. "
                        f"Agent reasoning has diverged from investigation baseline. "
                        f"Tool execution blocked."
            )
        elif similarity < self.CAUTION_THRESHOLD:
            logger.warning(
                f"[{trace_id}] [DRIFT-GATE] Turn {turn}: CAUTION — "
                f"cosine={similarity:.3f} (threshold={self.CAUTION_THRESHOLD}). Allowing with warning."
            )
            return DriftGateResult(
                allowed=True,
                severity="caution",
                similarity=similarity,
                message=f"SEMANTIC DRIFT CAUTION: cosine similarity {similarity:.3f}. "
                        f"Agent reasoning is diverging."
            )
        else:
            logger.info(f"[{trace_id}] [DRIFT-GATE] Turn {turn}: CLEAR — cosine={similarity:.3f}")
            return DriftGateResult(
                allowed=True,
                severity="normal",
                similarity=similarity,
                message=f"Drift check passed: cosine={similarity:.3f}"
            )

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)
