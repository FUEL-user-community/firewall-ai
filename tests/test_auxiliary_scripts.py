"""
Unit tests for auxiliary scripts and previously unreviewed pipeline utilities:
- scripts/run_card.py (card key resolution and execution parameters)
- core/pipeline/context_manager.py (Drive URI regex parsing with hyphens/underscores)
- core/pipeline/synthesizer.py (resilience against safety filter candidate exceptions)
"""

import sys
import os
import unittest.mock as mock
import pytest

from core.pipeline.context_manager import ContextManager
from core.pipeline.synthesizer import ResponseSynthesizer
from scripts.run_card import find_card_key, run_card


# ═══════════════════════════════════════════════════════════════
# 1. scripts/run_card.py Tests
# ═══════════════════════════════════════════════════════════════

def test_find_card_key_resolution():
    """Verify find_card_key resolves both direct keys and card IDs (case-insensitive)."""
    # Direct key resolution
    assert find_card_key("operational_resilience") == "operational_resilience"

    # Card ID resolution (e.g. SY-09 -> operational_resilience)
    assert find_card_key("SY-09") == "operational_resilience"
    assert find_card_key("sy-09") == "operational_resilience"

    # Non-existent returns None
    assert find_card_key("NON_EXISTENT_XYZ_123") is None


@mock.patch("core.engine.card_runner.CardRunner.execute")
def test_run_card_device_forwarding(mock_execute, capsys):
    """Verify run_card forwards target device and surfaces confidence and audit metrics."""
    mock_result = mock.MagicMock()
    mock_result.card_id = "SY-09"
    mock_result.severity = "caution"
    mock_result.trust_score = 0.95
    mock_result.confidence_margin = 0.42
    mock_result.audit_result = {"audit_score": 1.0}
    mock_result.title = "Test Card"
    mock_result.finding = "Healthy metrics"
    mock_result.reasoning_trace = ["step 1"]
    mock_result.evidence = ["fact 1"]
    mock_result.metrics = {"cpu": 12}
    mock_execute.return_value = mock_result

    run_card("operational_resilience", device="fw-dmz")

    # Verify device was forwarded
    mock_execute.assert_called_once_with("operational_resilience", device="fw-dmz")

    out = capsys.readouterr().out
    assert "Device: fw-dmz" in out
    assert "Confidence Margin: 42.0%" in out
    assert "Audit Score: 100%" in out


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
