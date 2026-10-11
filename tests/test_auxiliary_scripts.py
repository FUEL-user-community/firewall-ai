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
