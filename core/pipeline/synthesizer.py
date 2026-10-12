"""
ResponseSynthesizer — Investigation Guards, Retry Logic, and Final Output.

Single responsibility: handle end-of-turn decisions when no tool calls are present —
first-turn retry guards, Drive follow-up guards, empty response handling,
and final text extraction.
"""

import re
import logging


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

        # Guard against recursive firing: check if terminal directive was already dispatched
        if any("[SYSTEM: TOOL EXECUTION COMPLETED" in str(h) for h in history):
            return None

        # Extract text safely
        try:
            raw_text = response.text
            response_text = raw_text if isinstance(raw_text, str) else ""
        except (ValueError, AttributeError):
            response_text = ""

        clean_text = response_text.strip()

        # If in Range simulation mode:
        if target_mode == "range":
            if "mermaid" in clean_text or "graph " in clean_text or "flowchart " in clean_text:
                return None
            logger.warning(f"[{trace_id}] [GUARD] Range simulation concluded tools without topology. Forcing terminal synthesis...")
            retry_prompt = (
                "[SYSTEM: TOOL EXECUTION COMPLETED. Tool calling is now DISABLED.\n"
                "You must emit your terminal pure JSON simulation payload NOW containing 'mermaid', 'message', 'threats', and 'drops'.]"
            )
            return chat.send_message(
                retry_prompt,
                generation_config=base_config,
                tool_config={"function_calling_config": {"mode": "NONE"}}
            )

        # If in Advisory mode:
        if target_mode == "advisory":
            if len(clean_text) >= 20:
                return None

        # Standard / Investigate mode: Check if report has substance and structure
        is_deep_investigation = False
        user_q_str = str(history[0]) if history else ""
        if any(w in user_q_str.lower() for w in ["investigate", "incident", "compromise", "exploit", "cve", "threat", "logic vs", "counter-logic", "falsif"]):
            is_deep_investigation = True

        # Permit concise answers for direct operational queries (e.g. FIB lookups, IP checks)
        if not is_deep_investigation and len(clean_text) >= 30:
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

        logger.warning(
            f"[{trace_id}] [GUARD] Tool execution concluded ({len(receipt_list)} steps), but narrative is missing "
            f"or stubbed ({len(clean_text)} chars). Forcing Terminal Synthesis..."
        )

        terminal_prompt = (
            f"[SYSTEM: TOOL EXECUTION COMPLETED ({len(receipt_list)} steps recorded).\n"
            "Tool calling is now DISABLED. You have gathered the empirical firewall telemetry.\n"
            "You must now synthesize all evidence into your final structured report following FORMAT 3:\n\n"
            "### Incident Investigation Summary\n"
            "[CRITICAL | CAUTION | NORMAL] <Clear Assessment Title>\n"
            "**Scope:** <Source Zone/IP -> Destination Zone/IP> | **Telemetry Sources:** <Tools queried>\n\n"
            "#### Architectural Logic vs. Counter-Logic Analysis\n"
            "- **Logic (Attack Vector & Operator Premise):** <Contrast what the operator or adversary assumed>\n"
            "- **Counter-Logic (Empirical Telemetry & Physical Reality):** <State what the firewall architecture, routing FIB, and interface bindings empirically prove>\n\n"
            "#### Threat Assessment & Hypothesis Matrix\n"
            "| Hypothesis / Vector | Evidential Status | Basis & Corroborating Telemetry | Falsification Check |\n"
            "| :--- | :--- | :--- | :--- |\n\n"
            "#### Chronological Event Progression\n"
            "- <Timestamp/Step> - <Observed telemetry and causal significance>\n\n"
            "#### Traversal Path Analysis (Mermaid Architecture Overlay)\n"
            "```mermaid\n"
            "graph LR\n"
            "  Attacker[\"Source / Attacker<br>[<Source_IP>]\"]\n"
            "  ...\n"
            "  Attacker -.->|Logic: Attempted Transit| DataplaneInterface[\"Dataplane: <interface>\"]\n"
            "  DataplaneInterface -.->|Counter-Logic: Dropped / No Mgmt Profile| Drop[\"Boundary Drop\"]\n"
            "  Attacker ==>|Counter-Logic: L2 Switch Direct ARP| Target[\"MGT Port: <Target_IP>\"]\n"
            "```\n\n"
            "#### Governed Remediation Actions\n"
            "```panos\n"
            "<Exact PAN-OS CLI commands or configuration changes needed>\n"
            "```\n\n"
            "Deliver the complete executive report in markdown NOW.]"
        )

        return chat.send_message(
            terminal_prompt,
            generation_config=base_config,
            tool_config={"function_calling_config": {"mode": "NONE"}}
        )

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
        result = self.check_first_turn_guard(turn, tool_parts, chat, base_config, trace_id)
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
