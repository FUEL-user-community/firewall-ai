"""
ResponseSynthesizer — Investigation Guards, Retry Logic, and Final Output.

Single responsibility: handle end-of-turn decisions when no tool calls are present —
first-turn retry guards, Drive follow-up guards, empty response handling,
and final text extraction.
"""

import re
import logging
from typing import Optional

from core.pipeline.model_config import MAX_TURNS

logger = logging.getLogger(__name__)


class ResponseSynthesizer:
    """
    Handles investigation output logic:
    - First-turn execution guard (Turn 0, no tools → retry)
    - Drive follow-up guard (early turns, page refs found → retry)
    - Empty response handling (silence from Gemini)
    - Final text extraction
    """

    def check_first_turn_guard(self, turn, tool_parts, chat, base_config, trace_id):
        """
        Turn 0 guard: if the agent returned text without tool calls,
        force it to execute a tool. Returns new response or None.
        """
        if turn != 0 or tool_parts:
            return None

        logger.warning(f"[{trace_id}] [GUARD] Agent returned text without tool calls on Turn 1. Initiating retry...")
        retry_prompt = (
            "[SYSTEM: FUNCTION CALL REQUIRED. "
            "Select the most relevant tool from your manifest and execute it now. "
            "Text-only responses are not valid at this stage.]"
        )
        return chat.send_message(retry_prompt, generation_config=base_config)

    def check_drive_guard(self, turn, tool_parts, response, chat, base_config, history, trace_id):
        """
        Early-turn guard: if agent found page references but didn't call read_slice,
        force it to read those pages. Returns new response or None.
        """
        if tool_parts or turn >= 3:
            return None

        # Safe text accessor
        try:
            raw_text = response.text
            response_text = raw_text if isinstance(raw_text, str) else ""
        except (ValueError, AttributeError):
            response_text = ""

        page_refs = re.findall(r'[Pp]age\s+(\d+)', response_text)

        # Check if query_knowledge_base was used in this investigation
        drive_tool_used = any(
            'query_knowledge_base' in str(part)
            for part in history
            if hasattr(part, 'function_call')
        )

        if page_refs and drive_tool_used and 'read_slice' not in response_text.lower():
            logger.warning(
                f"[{trace_id}] [GUARD] Agent found page references {page_refs[:3]} "
                "but didn't execute read_slice. Initiating retry..."
            )
            pages_str = ", ".join(page_refs[:3])
            retry_prompt = (
                f"[SYSTEM: FUNCTION CALL REQUIRED. "
                f"Page references detected: {pages_str}. "
                f"Execute query_knowledge_base with action='read_slice' on these pages now.]"
            )
            return chat.send_message(retry_prompt, generation_config=base_config)

        return None

    def synthesize_final(self, response, trace_id):
        """
        Extract final text from the response, handling empty/silent responses.
        Returns the final text string or an error message.
        """
        try:
            # Safe parts access guarding against ValueError on safety-filtered candidates
            try:
                parts = getattr(response, 'parts', None)
            except (ValueError, AttributeError):
                parts = None

            if not parts:
                finish_reason = "Unknown"
                candidates = getattr(response, 'candidates', [])
                if candidates:
                    finish_reason = getattr(candidates[0], 'finish_reason', "Unknown")

                logger.warning(f"[{trace_id}] [-] Brain returned complete silence (Finish: {finish_reason}).")

                return (
                    f"**Status:** Interrupted (Silent Response)\n\n"
                    f"**Observation:** The Brain processed the inputs but generated no text output. "
                    f"This can happen if a Tool Call was malformed internally or the model hit a safety filter.\n\n"
                    f"**Recommendation:** Please retry your query. If it persists, checking specific documents "
                    f"(e.g. 'Read pages 1-3') is more reliable than broad 'Investigate' commands."
                )

            final_text = response.text
            logger.info(f"[{trace_id}] [ARCHITECT] Investigation Complete.")
            return final_text
        except Exception as e:
            logger.warning(f"[{trace_id}] [-] Synthesis Failed: {e}")
            return "The investigation was completed, but the final report was empty/blocked."

    def check_guards(self, turn, tool_parts, response, chat, base_config, history, trace_id):
        """
        Convenience method: runs all guards in sequence.
        Returns a new response if any guard fired, None otherwise.
        """
        # First-turn guard
        result = self.check_first_turn_guard(turn, tool_parts, chat, base_config, trace_id)
        if result:
            return result

        # Drive follow-up guard
        result = self.check_drive_guard(turn, tool_parts, response, chat, base_config, history, trace_id)
        if result:
            return result

        return None
