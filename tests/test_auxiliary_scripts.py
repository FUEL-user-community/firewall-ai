"""
Unit tests for auxiliary scripts and previously unreviewed pipeline utilities:
- core/pipeline/context_manager.py (Drive URI regex parsing with hyphens/underscores)
- core/pipeline/synthesizer.py (resilience against safety filter candidate exceptions)
"""

import sys
import os
import unittest.mock as mock
import pytest

from core.pipeline.context_manager import ContextManager
from core.pipeline.synthesizer import ResponseSynthesizer


# ═══════════════════════════════════════════════════════════════
# 2. core/pipeline/context_manager.py Tests
# ═══════════════════════════════════════════════════════════════

@mock.patch("google.generativeai.get_file")
def test_context_manager_extract_drive_files_robust_regex(mock_get_file):
    """Verify extract_drive_files accepts URIs with hyphens and underscores."""
    mock_file = mock.MagicMock()
    mock_get_file.return_value = mock_file

    cm = ContextManager()

    # Part containing hyphens and underscores in file ID
    mock_part = mock.MagicMock()
    mock_part.function_response.response = {
        "result": "Observation: Found GEMINI_FILE_URI: files/sec-doc_2026_v2 for reference."
    }

    files = cm.extract_drive_files([mock_part], trace_id="test-trace")
    assert len(files) == 1
    mock_get_file.assert_called_once_with("files/sec-doc_2026_v2")


# ═══════════════════════════════════════════════════════════════
# 3. core/pipeline/synthesizer.py Tests
# ═══════════════════════════════════════════════════════════════

def test_synthesizer_safe_parts_on_safety_filtered_response():
    """Verify synthesize_final handles safety-blocked response without raising ValueError."""
    synth = ResponseSynthesizer()

    mock_resp = mock.MagicMock()
    # Simulate Google GenAI SDK behavior: accessing .parts on safety block raises ValueError
    type(mock_resp).parts = mock.PropertyMock(side_effect=ValueError("Candidate was blocked by SAFETY"))

    candidate = mock.MagicMock()
    candidate.finish_reason = "SAFETY"
    mock_resp.candidates = [candidate]

    final_text = synth.synthesize_final(mock_resp, trace_id="test-trace")
    assert "Interrupted (Silent Response)" in final_text
    assert "safety filter" in final_text.lower()


def test_terminal_synthesis_guard_triggers_on_empty_narrative():
    """Verify check_terminal_synthesis_guard intercepts silent exits and forces terminal synthesis with mode=NONE."""
    synth = ResponseSynthesizer()
    mock_chat = mock.MagicMock()
    mock_resp = mock.MagicMock()
    mock_resp.text = ""  # Empty silent dropout from model

    mock_terminal_resp = mock.MagicMock()
    mock_terminal_resp.text = "### Incident Investigation Summary\nFull report..."
    mock_chat.send_message.return_value = mock_terminal_resp

    receipts = [{"tool": "system_info", "status": "success"}, {"tool": "get_live_config", "status": "success"}]
    res = synth.check_terminal_synthesis_guard(
        turn=2,
        tool_parts=[],
        response=mock_resp,
        chat=mock_chat,
        base_config=mock.MagicMock(),
        history=[],
        trace_id="test-trace",
        receipts=receipts,
        target_mode="investigate"
    )

    assert res == mock_terminal_resp
    assert mock_chat.send_message.called
    kwargs = mock_chat.send_message.call_args.kwargs
    assert kwargs.get("tool_config") == {"function_calling_config": {"mode": "NONE"}}
    prompt_arg = mock_chat.send_message.call_args.args[0]
    assert "TOOL EXECUTION COMPLETED (2 steps recorded)" in prompt_arg
    assert "Architectural Logic vs. Counter-Logic" in prompt_arg


def test_terminal_synthesis_guard_passes_when_report_structured():
    """Verify check_terminal_synthesis_guard allows structured report without re-prompting."""
    synth = ResponseSynthesizer()
    mock_chat = mock.MagicMock()
    mock_resp = mock.MagicMock()
    mock_resp.text = (
        "### Incident Investigation Summary\n"
        "#### Architectural Logic vs. Counter-Logic Analysis\n"
        "Detailed analysis of traffic from 192.168.1.100 to 192.168.1.254 demonstrating "
        "Layer 2 switch bypass and absence of interface management profile."
    )

    receipts = [{"tool": "system_info", "status": "success"}]
    res = synth.check_terminal_synthesis_guard(
        turn=1,
        tool_parts=[],
        response=mock_resp,
        chat=mock_chat,
        base_config=mock.MagicMock(),
        history=[],
        trace_id="test-trace",
        receipts=receipts,
        target_mode="investigate"
    )

    assert res is None
    assert not mock_chat.send_message.called

