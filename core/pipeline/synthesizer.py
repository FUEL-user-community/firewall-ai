"""
ResponseSynthesizer — Investigation Guards, Retry Logic, and Final Output.

Single responsibility: handle end-of-turn decisions when no tool calls are present —
first-turn retry guards, Drive follow-up guards, empty response handling,
and final text extraction.
"""

import re
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


_ECHO_SENTINELS = (
    "DETERMINISTIC DEVICE TOPOLOGY",
    "<cartographer_state>",
    "<resident_session_memory>",
    "[SYSTEM COGNITIVE BOUNDS:",
    "REALITY_CHECK:",
    "[SYSTEM: COMPUTED FACTS",
    "<computed_facts>",
    "<operator_message>",
    "### Device Facts (computed by code",
)


def _has_prompt_echo(text: str) -> bool:
    """Detect preview-model context regurgitation of input prompt wrappers or Cartographer JSON."""
    if not text:
        return False
    if any(s in text for s in _ECHO_SENTINELS):
        return True
    if re.search(r"(?:^|\n)\s*INVESTIGATE:\s+\S+", text):
        return True
    return False


def strip_prompt_echo(text: str) -> str:
    """Strip internal <REASONING> traces and any residual echoed prompt/Cartographer blocks from final synthesis text."""
    if not text:
        return ""
    out = text
    out = re.sub(r"<REASONING>.*?</REASONING>", "", out, flags=re.DOTALL | re.IGNORECASE)
    out = re.sub(r"</?REASONING>", "", out, flags=re.IGNORECASE)
    out = re.sub(r"<cartographer_state>.*?</cartographer_state>", "", out, flags=re.DOTALL | re.IGNORECASE)
    out = re.sub(r"<resident_session_memory>.*?</resident_session_memory>", "", out, flags=re.DOTALL | re.IGNORECASE)
    out = re.sub(r"<computed_facts>.*?</computed_facts>", "", out, flags=re.DOTALL | re.IGNORECASE)
    out = re.sub(r"<operator_message>.*?</operator_message>", "", out, flags=re.DOTALL | re.IGNORECASE)
    out = re.sub(
        r"---\s*DETERMINISTIC DEVICE TOPOLOGY\s*&\s*POSTURE\s*\(CARTOGRAPHER\)\s*---.*?(?:---+|(?=\n### )|$)",
        "",
        out,
        flags=re.DOTALL | re.IGNORECASE,
    )
    out = re.sub(r"\[SYSTEM COGNITIVE BOUNDS:[^\]]*\]", "", out, flags=re.IGNORECASE)
    out = re.sub(r"\[Reference topology snapshot only[^\]]*\]", "", out, flags=re.IGNORECASE)
    out = re.sub(r"\[END COMPUTED FACTS[^\]]*\]", "", out, flags=re.IGNORECASE)
    out = re.sub(r"(?:^|\n)\s*INVESTIGATE:\s*[^\n]*", "", out)
    return out.strip()


class ResponseSynthesizer:
    """
    Handles investigation output logic:
    - First-turn execution guard (Turn 0, no tools → retry)
    - Drive follow-up guard (early turns, page refs found → retry)
    - Empty response handling (silence from Gemini)
    - Final text extraction
    """

    def check_first_turn_guard(
        self,
        turn,
        tool_parts,
        chat,
        base_config,
        trace_id,
        response=None,
        history=None,
        target_mode="default",
    ):
        """
        Turn 0 guard: on cold starts or strict forensic/range runs, force at least one tool call.
        On ongoing resident sessions (<resident_session_memory> present), permit direct conversational follow-ups.
        """
        if turn != 0 or tool_parts:
            return None

        if target_mode not in ("investigate", "range") and response is not None:
            chat_hist = getattr(chat, "history", None)
            combined_hist = list(history or []) + (list(chat_hist) if isinstance(chat_hist, (list, tuple)) else [])
            has_session_mem = any("<resident_session_memory>" in str(h) for h in combined_hist)
            if has_session_mem:
                try:
                    txt = (response.text or "").strip() if isinstance(getattr(response, "text", None), str) else ""
                except (ValueError, AttributeError):
                    txt = ""
                if len(strip_prompt_echo(txt)) >= 15 and not _has_prompt_echo(txt):
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

    def check_terminal_synthesis_guard(
        self,
        turn,
        tool_parts,
        response,
        chat,
        base_config,
        history,
        trace_id,
        receipts=None,
        target_mode="default",
    ):
        """
        Terminal Synthesis Guard:
        Fires when tool execution has concluded (turn > 0 and no new tool_parts),
        at least one receipt was captured, but the model emitted silence, stub text
        (< 150 chars), or lacks required structural headings.

        Forces a terminal turn with tool_config mode='NONE' to guarantee a complete
        executive report with Logic vs. Counter-Logic analysis, Mermaid overlay,
        and CLI remediation.
        """
        # Only evaluate when tool calling in this turn has ended
        if tool_parts:
            return None

        # Must have executed at least 1 tool in prior turns
        receipt_list = receipts or []
        if not receipt_list:
            return None

        # Guard against recursive firing: check both explicit history and chat.history
        chat_hist = getattr(chat, "history", None)
        combined_hist = list(history or []) + (list(chat_hist) if isinstance(chat_hist, (list, tuple)) else [])
        if any("[SYSTEM: TOOL EXECUTION COMPLETED" in str(h) for h in combined_hist):
            return None

        # Extract text safely
        try:
            raw_text = response.text
            response_text = raw_text if isinstance(raw_text, str) else ""
        except (ValueError, AttributeError):
            response_text = ""

        clean_text = response_text.strip()

        # If in Range simulation mode:
        # If in Advisory mode:
        if target_mode == "advisory":
            if len(clean_text) >= 20 and not _has_prompt_echo(clean_text):
                return None

        # Standard / Investigate mode: Check for prompt-echo corruption, receipt grounding, and structure
        is_deep_investigation = False
        raw_h0 = str(combined_hist[0]) if combined_hist else ""
        op_match = re.search(r"<operator_message>(.*?)</operator_message>", raw_h0, re.DOTALL | re.IGNORECASE)
        if op_match:
            user_q_str = op_match.group(1)
        else:
            user_q_str = raw_h0.split("CARTOGRAPHER", 1)[0].split("<cartographer_state>", 1)[0].split("\n{", 1)[0]
            if "INVESTIGATE:" in user_q_str:
                user_q_str = user_q_str.rsplit("INVESTIGATE:", 1)[-1]

        if any(w in user_q_str.lower() for w in ["investigate", "incident", "compromise", "exploit", "cve", "threat", "logic vs", "counter-logic", "falsif"]):
            is_deep_investigation = True

        has_echo = _has_prompt_echo(clean_text)
        visible_text = strip_prompt_echo(clean_text)

        # Cybersec Resident modes ('default', 'diagnostic', 'resident'):
        # Never force SOC compliance report headers—pass any clean non-echo visible output >= 15 chars.
        if target_mode != "investigate":
            if len(visible_text) >= 15 and not has_echo:
                return None
            reason_tag = "prompt/context echo detected" if has_echo else f"empty/reasoning-only resident turn ({len(visible_text)} visible chars)"
            logger.warning(
                f"[{trace_id}] [GUARD] Tool execution concluded ({len(receipt_list)} steps), {reason_tag}. Requesting clean resident synthesis..."
            )
            echo_warning = (
                "CRITICAL: Your previous turn echoed raw input context/JSON instead of answering. "
                "Output ZERO raw JSON/XML wrappers and ZERO echoed system headers.\n"
                if has_echo
                else ""
            )
            resident_retry = (
                f"[SYSTEM: TOOL EXECUTION COMPLETED ({len(receipt_list)} steps recorded).\n"
                f"{echo_warning}"
                "Tool calling is now DISABLED. Respond directly in your Cybersec Resident voice "
                "grounded in your [Step N] receipts—concise, technical, no corporate report templates.]"
            )
            return chat.send_message(
                resident_retry,
                generation_config=base_config,
                tool_config={"function_calling_config": {"mode": "NONE"}},
            )

        # Strict Forensic Audit mode ('investigate'): enforce structured incident report
        has_receipt_anchor = bool(re.search(r"\[Steps?\s+\d+", clean_text, re.IGNORECASE))

        if not has_echo:
            if not is_deep_investigation and len(clean_text) >= 30:
                return None
            if len(clean_text) >= 60 and has_receipt_anchor:
                return None

            has_substance = len(clean_text) >= 150
            has_structure = any(
                heading in clean_text for heading in [
                    "### Incident Investigation Summary",
                    "### Compensating Policy Compilation Manifest",
                    "### Executive Health Summary",
                    "## Executive Diagnosis",
                    "#### Architectural Logic vs. Counter-Logic Analysis"
                ]
            )

            if has_substance and has_structure:
                return None

        reason_tag = "prompt/context echo detected" if has_echo else f"missing/stubbed/uncited narrative ({len(clean_text)} chars)"
        logger.warning(
            f"[{trace_id}] [GUARD] Tool execution concluded ({len(receipt_list)} steps), {reason_tag}. Forcing Terminal Synthesis..."
        )

        echo_warning = (
            "CRITICAL: Your previous turn echoed raw input context/JSON instead of synthesizing your findings. "
            "Output ZERO raw Cartographer JSON, ZERO REALITY_CHECK lines, and ZERO echoed system headers.\n"
            if has_echo
            else ""
        )

        terminal_prompt = (
            f"[SYSTEM: TOOL EXECUTION COMPLETED ({len(receipt_list)} steps recorded).\n"
            f"{echo_warning}"
            "Tool calling is now DISABLED. Synthesize the gathered firewall/harness receipts without filler:\n"
            "- Cite every factual statement with its [Step N] SUCCESS receipt.\n"
            "- For concise or ZERO_DRIFT checks, state the verified state directly with [Step N] proof.\n"
            "- For deep incident/boundary/health audits, open with `### Incident Investigation Summary` (or "
            "`### Executive Health Summary` / `### Compensating Policy Compilation Manifest`) and include "
            "`#### Architectural Logic vs. Counter-Logic Analysis` contrasting surface Logic against live SP3/wire Counter-Logic.\n"
            "Deliver the report in markdown NOW.]"
        )

        return chat.send_message(
            terminal_prompt,
            generation_config=base_config,
            tool_config={"function_calling_config": {"mode": "NONE"}}
        )

    def synthesize_final(self, response, trace_id, target_mode="default"):
        """
        Extract final text from the response, handling empty/silent responses.
        Returns the final text string or an error message (sanitized for range mode if applicable).
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
            if isinstance(final_text, str):
                final_text = strip_prompt_echo(final_text)

            if not final_text or not final_text.strip():
                logger.warning(f"[{trace_id}] [-] response.text is empty or whitespace.")
                return (
                    f"**Status:** Interrupted (Empty Response)\n\n"
                    f"**Observation:** The model completed its execution but generated no narrative text.\n\n"
                    f"**Recommendation:** Please review the execution receipts above or re-run the diagnostic."
                )

            logger.info(f"[{trace_id}] [ARCHITECT] Investigation Complete.")
            return final_text
        except Exception as e:
            logger.warning(f"[{trace_id}] [-] Synthesis Failed: {e}")
            return "The investigation was completed, but the final report was empty/blocked."

    def check_guards(
        self,
        turn,
        tool_parts,
        response,
        chat,
        base_config,
        history,
        trace_id,
        receipts=None,
        target_mode="default",
    ):
        """
        Convenience method: runs all guards in sequence.
        Returns a new response if any guard fired, None otherwise.
        """
        # First-turn guard
        result = self.check_first_turn_guard(
            turn,
            tool_parts,
            chat,
            base_config,
            trace_id,
            response=response,
            history=history,
            target_mode=target_mode,
        )
        if result:
            return result

        # Drive follow-up guard
        result = self.check_drive_guard(turn, tool_parts, response, chat, base_config, history, trace_id)
        if result:
            return result

        # Terminal synthesis guard
        result = self.check_terminal_synthesis_guard(
            turn,
            tool_parts,
            response,
            chat,
            base_config,
            history,
            trace_id,
            receipts=receipts,
            target_mode=target_mode,
        )
        if result:
            return result

        return None
