"""
ContextManager — Investigation Context, Checkpoints, and Drive File Injection.

Single responsibility: manage investigation context across turns —
mid-investigation checkpoints, context compression, and Drive file injection.
"""

import re
import logging
from typing import Optional, List

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

    def get_checkpoint_prompt(self, turn, prev_turn_tools, trace_id):
        """
        Mid-Investigation Context Checkpoint.
        Fires at CHECKPOINT_TURN if tools have been called.
        Returns the prompt string to append to the payload, or None.
        """
        if turn != self.CHECKPOINT_TURN or not prev_turn_tools:
            return None

        logger.info(f"[{trace_id}] [CHECKPOINT] Injecting mid-investigation correlation checkpoint at Turn {turn}")
        return (
            f"\n\n[SYSTEM: MID-INVESTIGATION CHECKPOINT — Turn {turn} of {MAX_TURNS}]\n"
            "Before continuing, output a brief correlation summary:\n"
            "1. SHARED KEYS: List any IP addresses, usernames, rule names, or timestamps "
            "that have appeared in 2+ tool outputs.\n"
            "2. CORRELATIONS: Any causal chains identified so far.\n"
            "3. OPEN HYPOTHESES: What remains untested.\n"
            "4. NEXT PRIORITY: Most important tool to call next and why.\n"
            "Then continue the investigation."
        )

    def get_compression_prompt(self, turn, history_length, trace_id):
        """
        Context summarization every N turns.
        Fires when turn > 0, turn divisible by COMPRESS_INTERVAL, and history is substantial.
        Returns the prompt string to append to the payload, or None.
        """
        if turn <= 0 or turn % self.COMPRESS_INTERVAL != 0 or history_length <= 6:
            return None

        logger.info(f"[{trace_id}] [COMPRESS] Injecting context summarization at Turn {turn+1}")
        return (
            "\n\n[SYSTEM: CONTEXT CHECKPOINT. Summarize your observations so far in 3-5 bullet points. "
            "State the original user query, key findings, and what remains unresolved. "
            "This summary replaces the raw tool logs in your working memory.]"
        )

    def extract_drive_files(self, tool_parts, trace_id):
        """
        Scan tool response parts for GEMINI_FILE_URI sentinels.
        Returns a list of resolved Gemini file objects for context injection.
        """
        drive_files = []
        for part in tool_parts:
            if not hasattr(part, 'function_response'):
                continue
            result_text = part.function_response.response.get('result', '')
            if not isinstance(result_text, str) or 'GEMINI_FILE_URI:' not in result_text:
                continue

            # Strict validation: only accept alphanumeric URIs of expected length (10-25 chars)
            file_match = re.search(r'GEMINI_FILE_URI:\s*(files/[a-zA-Z0-9]{10,25})\b', result_text)
            if file_match:
                file_uri = file_match.group(1)
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
