"""
Semantic Drift Gate — Pre-Execution Safety Interceptor
Compares each turn's reasoning trace against historical vectors with dimension safety (M3).
"""
import math
import logging
from typing import List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

__all__ = ["SemanticDriftGate", "DriftGateResult"]


@dataclass
class DriftGateResult:
    allowed: bool = True
    severity: str = "normal"
    similarity: float = 1.0
    message: str = ""


class SemanticDriftGate:
    CAUTION_THRESHOLD = 0.85
    CRITICAL_THRESHOLD = 0.70
    MIN_TURNS = 1

    def __init__(self):
        self._embeddings: List[List[float]] = []
        self._reasoning_texts: List[str] = []
        self._embed_fn = None

    def _get_embed_fn(self):
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
        if not reasoning_text or not reasoning_text.strip():
            return DriftGateResult(allowed=True, message="No reasoning trace to embed.")

        embed_fn = self._get_embed_fn()
        if embed_fn is None:
            return DriftGateResult(allowed=True, message="Embedding unavailable — skipping drift check.")

        try:
            current_embedding = embed_fn(reasoning_text)
        except Exception as e:
            logger.warning(f"[{trace_id}] [DRIFT-GATE] Embedding failed: {e}")
            return DriftGateResult(allowed=True, message=f"Embedding failed: {e}")

        self._embeddings.append(current_embedding)
        self._reasoning_texts.append(reasoning_text)

        dim = len(current_embedding)
        if dim == 0:
            return DriftGateResult(allowed=True, message="Empty embedding vector.")

        # Cold start
        if len(self._embeddings) <= self.MIN_TURNS:
            return DriftGateResult(allowed=True, similarity=1.0, message="Cold start — baseline accumulating.")

        # Dimension safety: only average prior embeddings matching dim (M3)
        matching_priors = [emb for emb in self._embeddings[:-1] if len(emb) == dim]
        if not matching_priors:
            return DriftGateResult(allowed=True, similarity=1.0, message="Insufficient prior matching vectors.")

        avg_embedding = [0.0] * dim
        for emb in matching_priors:
            for j in range(dim):
                avg_embedding[j] += emb[j]
        avg_embedding = [v / len(matching_priors) for v in avg_embedding]

        similarity = self._cosine_similarity(current_embedding, avg_embedding)
        # Clamp to [-1.0, 1.0] to prevent floating point imprecision
        similarity = max(-1.0, min(1.0, similarity))

        if similarity < self.CRITICAL_THRESHOLD:
            return DriftGateResult(
                allowed=False,
                severity="critical",
                similarity=similarity,
                message=f"SEMANTIC DRIFT CRITICAL: cosine similarity {similarity:.3f}."
            )
        elif similarity < self.CAUTION_THRESHOLD:
            return DriftGateResult(
                allowed=True,
                severity="caution",
                similarity=similarity,
                message=f"SEMANTIC DRIFT CAUTION: cosine similarity {similarity:.3f}."
            )

        return DriftGateResult(allowed=True, severity="normal", similarity=similarity, message=f"Clear: {similarity:.3f}")

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        if len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return max(-1.0, min(1.0, dot / (norm_a * norm_b)))
