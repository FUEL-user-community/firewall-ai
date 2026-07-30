"""
Debate Protocol — Adversarial Auditor (Gemini Flash).

Uses a cheaper, faster model (Gemini Flash) to red-team the primary model's
(Gemini Pro) reasoning. The auditor receives:
  1. Raw tool output (ground truth)
  2. Pro's reasoning trace + final decision

Its job is to find logical flaws, math errors, fabricated evidence, or
missed correlations. If it finds a flaw, the trust_score is penalized.

Design: The auditor persona is intentionally hostile and adversarial.
This breaks the model's sycophancy bias and produces sharper critiques.
"""

import os
import json
import logging
import warnings
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Auditor system prompt — intentionally hostile to break sycophancy
_AUDITOR_PERSONA = (
    "You are a hostile security auditor. Your job is to find flaws in another "
    "AI agent's analysis of firewall telemetry. You receive the RAW TOOL OUTPUT "
    "(ground truth) and the AGENT'S REASONING + DECISION.\n\n"
    "Your tasks:\n"
    "1. VERIFY MATH: Check all numeric claims (unit conversions, percentages, thresholds).\n"
    "2. VERIFY EVIDENCE: Every claim the agent makes must appear in the raw tool output.\n"
    "3. VERIFY LOGIC: Check that the severity classification follows from the evidence.\n"
    "4. FIND OMISSIONS: Did the agent ignore important data in the tool output?\n\n"
    "You will be rewarded for finding flaws. Do NOT agree with the agent unless "
    "everything checks out. Be ruthless.\n\n"
    "Respond ONLY with valid JSON in this format:\n"
    "{\n"
    '  "disputes": [{"claim": "...", "issue": "...", "severity": "error|warning"}],\n'
    '  "confirmed": ["claim 1 is correct", "claim 2 is correct"],\n'
    '  "omissions": ["the agent missed X in the tool output"],\n'
    '  "audit_score": 0.0 to 1.0,\n'
    '  "summary": "One-sentence overall assessment"\n'
    "}"
)


@dataclass
class AuditResult:
    """Result from the Debate Protocol auditor."""
    disputes: List[Dict[str, str]] = field(default_factory=list)
    confirmed: List[str] = field(default_factory=list)
    omissions: List[str] = field(default_factory=list)
    audit_score: float = 1.0    # 1.0 = fully verified, 0.0 = fully disputed
    summary: str = ""
    raw_response: str = ""      # Full text for debugging
    error: str = ""             # Set if auditor failed


class Auditor:
    """
    Gemini Flash-based adversarial auditor.
    Singleton — initialized once, reused across card runs.
    """

    _instance: Optional['Auditor'] = None
    _lock = threading.Lock()

    def __init__(self):
        self._model = None
        self._enabled = os.getenv("AUDITOR_ENABLED", "false").lower() == "true"
        if self._enabled:
            self._init_model()
        else:
            logger.info("[AUDITOR] Debate Auditor is disabled via environment config.")

    @classmethod
    def get_instance(cls) -> 'Auditor':
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    def _init_model(self):
        """Initialize Gemini Flash model for auditing."""
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                import google.generativeai as genai

            from core.integrations.secrets import get_secret
            api_key = get_secret('gemini_api_key')
            genai.configure(api_key=api_key)

            from core.pipeline.model_config import FLASH_MODEL

            self._model = genai.GenerativeModel(
                model_name=FLASH_MODEL,
                system_instruction=_AUDITOR_PERSONA,
            )
            logger.info(f"[AUDITOR] Flash model initialized: {FLASH_MODEL}")

        except Exception as e:
            logger.warning(f"[AUDITOR] Init failed (auditing disabled): {e}")
            self._enabled = False

    def audit(
        self,
        tool_outputs: List[Dict[str, str]],
        reasoning_trace: List[str],
        severity: str,
        finding: str,
    ) -> AuditResult:
        """
        Run the Debate Protocol: send raw tool output + agent reasoning
        to Flash for adversarial review.

        Returns AuditResult with disputes, confirmed claims, and audit_score.
        """
        if not self._enabled or self._model is None:
            return AuditResult(
                summary="Auditor unavailable — skipped",
                error="Model not initialized"
            )

        # Build the audit prompt
        tool_section = "\n\n".join([
            f"--- RAW TOOL: {t['tool']} ---\n{t['output'][:30000]}"
            for t in tool_outputs
        ])

        trace_section = "\n".join([f"  {i+1}. {step}" for i, step in enumerate(reasoning_trace)])

        audit_prompt = (
            f"=== RAW TOOL OUTPUT (GROUND TRUTH) ===\n{tool_section}\n\n"
            f"=== AGENT'S REASONING TRACE ===\n{trace_section}\n\n"
            f"=== AGENT'S FINAL DECISION ===\n"
            f"Severity: {severity}\n"
            f"Finding: {finding}\n\n"
            "Now audit this. Respond with JSON only."
        )

        raw_text = ""
        try:
            import google.generativeai as genai
            config = genai.types.GenerationConfig(
                temperature=1.0,
                max_output_tokens=2048,
                response_mime_type="application/json"
            )

            import concurrent.futures
            
            def _call_model():
                return self._model.generate_content(
                    audit_prompt,
                    generation_config=config,
                    tool_config={'function_calling_config': {'mode': 'NONE'}}
                )
                
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_call_model)
                try:
                    # Fragile #3 Fix: 15-second timeout to prevent stalling the CardRunner pipeline
                    response = future.result(timeout=15.0)
                except concurrent.futures.TimeoutError:
                    logger.warning(f"[AUDITOR] Audit timed out after 15 seconds. Skipping.")
                    return AuditResult(summary="Audit timed out", error="Timeout")

            raw_text = response.text.strip()
            parsed = json.loads(raw_text)

            result = AuditResult(
                disputes=parsed.get("disputes", []),
                confirmed=parsed.get("confirmed", []),
                omissions=parsed.get("omissions", []),
                audit_score=float(parsed.get("audit_score", 1.0)),
                summary=parsed.get("summary", ""),
                raw_response=raw_text,
            )

            dispute_count = len(result.disputes)
            if dispute_count > 0:
                logger.warning(
                    f"[AUDITOR] 🔴 {dispute_count} dispute(s) found | "
                    f"Score: {result.audit_score} | {result.summary}"
                )
            else:
                logger.info(
                    f"[AUDITOR] ✅ No disputes | Score: {result.audit_score} | {result.summary}"
                )

            return result

        except json.JSONDecodeError as je:
            logger.warning(f"[AUDITOR] JSON parse failed: {je}")
            return AuditResult(
                summary="Audit response was not valid JSON",
                raw_response=raw_text,
                error=str(je),
            )
        except Exception as e:
            logger.warning(f"[AUDITOR] Audit failed: {e}")
            return AuditResult(
                summary=f"Audit error: {e}",
                error=str(e),
            )
