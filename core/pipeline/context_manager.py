"""
ContextManager — Investigation Context, Checkpoints, and Drive File Injection.

Single responsibility: manage investigation context across turns —
mid-investigation checkpoints, context compression, and Drive file injection.
"""

import re
import logging

import warnings
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import google.generativeai as genai

from core.pipeline.model_config import MAX_TURNS

logger = logging.getLogger(__name__)


class ContextManager:
    """
    Manages investigation context across turns:
    - Mid-investigation checkpoint (Turn 7)
    - Context compression (every 3 turns)
    - Drive file extraction and injection
    """

    # Checkpoint fires at the midpoint of MAX_TURNS
    CHECKPOINT_TURN = MAX_TURNS // 2

    # Context compression interval
    COMPRESS_INTERVAL = 3

    def get_checkpoint_prompt(self, turn, prev_turn_tools, trace_id, target_mode: str = "default"):
        """
        Mid-Investigation Context Checkpoint.
        Fires at CHECKPOINT_TURN if tools have been called.
        Counter-Logic: NEVER ask the model to emit standalone prose here (which causes
        tool_parts == [] and aborts the loop prematurely); keep correlation inside <REASONING>.
        """
        if turn != self.CHECKPOINT_TURN or not prev_turn_tools:
            return None

        logger.info(f"[{trace_id}] [CHECKPOINT] Injecting mid-investigation correlation checkpoint at Turn {turn}")
        return (
            f"\n\n[SYSTEM: MID-INVESTIGATION CHECKPOINT — Turn {turn} of {MAX_TURNS}. "
            "Do NOT stop calling tools just to print a scratchpad. Reconcile shared IPs/rules/sessions "
            "silently inside <REASONING> and either dispatch your next targeted tool batch or deliver "
            "your final synthesis if all hypotheses are already proven.]"
        )

    def get_compression_prompt(self, turn, history_length, trace_id, target_mode: str = "default"):
        """
        Context focus anchor every COMPRESS_INTERVAL turns when history grows long.
        """
        if turn <= 0 or turn == self.CHECKPOINT_TURN or turn % self.COMPRESS_INTERVAL != 0 or history_length <= 6:
            return None

        logger.info(f"[{trace_id}] [COMPRESS] Injecting state-focus anchor at Turn {turn+1}")
        return (
            "\n\n[SYSTEM: STATE-FOCUS CHECKPOINT. Before your next tool call, keep working focus tight: "
            "(1) proven facts with [Step N] receipts, (2) remaining unresolved state gap, and "
            "(3) whether current evidence already suffices to terminate cleanly without wasted turns.]"
        )

    MAX_FILES_PER_TURN = 5

    def extract_drive_files(self, tool_parts, trace_id):
        """
        Scan tool response parts for GEMINI_FILE_URI sentinels.
        Returns a list of resolved Gemini file objects for context injection (deduplicated, bounded).
        """
        drive_files = []
        seen_uris = set()

        for part in tool_parts:
            if len(drive_files) >= self.MAX_FILES_PER_TURN:
                break
            if not hasattr(part, 'function_response'):
                continue
            fname = getattr(part.function_response, 'name', None)
            if isinstance(fname, str) and fname and fname != 'query_knowledge_base':
                continue
            result_text = part.function_response.response.get('result', '')
            if not isinstance(result_text, str) or 'GEMINI_FILE_URI:' not in result_text:
                continue

            # Robust validation: accept alphanumeric, hyphen, and underscore URIs (8-64 chars)
            file_match = re.search(r'GEMINI_FILE_URI:\s*(files/[a-zA-Z0-9_-]{8,64})\b', result_text)
            if file_match:
                file_uri = file_match.group(1)
                if file_uri in seen_uris:
                    continue
                seen_uris.add(file_uri)

                try:
                    gemini_file = genai.get_file(file_uri)
                    drive_files.append(gemini_file)
                    logger.info(f"[{trace_id}] [MULTIMODAL] Injecting {file_uri} into next turn context")
                except Exception as e:
                    logger.warning(f"[{trace_id}] [MULTIMODAL] Failed to retrieve {file_uri}: {e}")

        return drive_files

    def build_message_payload(self, tool_parts, trace_id):
        """
        Build the message payload: tool response parts + any Drive files.
        """
        drive_files = self.extract_drive_files(tool_parts, trace_id)
        return tool_parts + drive_files
