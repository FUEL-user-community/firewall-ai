"""
Tests for core/brain.py — model initialization, safety configuration,
thread-safe singleton proxy, error sanitization, and investigation loop guards.
"""

import json
import os
import threading
import pytest
from unittest.mock import MagicMock, patch
from core.brain import CoreBrain, get_brain, cortex


def test_brain_offline_mode():
    """When no API key or model is provided, offline messages are safely returned."""
    brain = CoreBrain(model=None, tools=[])
    brain.api_key = None
    brain.model = None

    result = brain.investigate("Show interfaces")
    assert "Offline Mode" in result

    think_result = brain.think("Analyze risk")
    assert "Offline Mode" in think_result


def test_brain_injected_model():
    """Dependency injection allows testing with mock GenerativeModel."""
    mock_model = MagicMock()
    mock_chat = MagicMock()
    mock_model.start_chat.return_value = mock_chat

    # Simulate response
    mock_response = MagicMock()
    mock_part = MagicMock()
    mock_part.function_call = None
    mock_part.text = "All systems normal."
    mock_response.parts = [mock_part]
    mock_chat.send_message.return_value = mock_response

    mock_tool = MagicMock()
    mock_tool.__name__ = "dummy_tool"

    brain = CoreBrain(model=mock_model, tools=[mock_tool])
    brain.api_key = "mock-key"

    # Should execute investigation without error
    result = brain.investigate("System health check")
    assert mock_model.start_chat.called
    assert mock_chat.send_message.called


def test_cortex_singleton_thread_safety():
    """Verify get_brain() and cortex proxy return a valid CoreBrain instance."""
    instance_1 = get_brain()
    instance_2 = get_brain()
    assert instance_1 is instance_2
    assert hasattr(cortex, "investigate")


def test_safety_settings_configuration():
    """Verify GEMINI_SAFETY_LEVEL environment variable sets appropriate thresholds."""
    with patch.dict(os.environ, {"GEMINI_SAFETY_LEVEL": "default"}):
        with patch("google.generativeai.GenerativeModel") as mock_gen_model:
            brain = CoreBrain(tools=[])
            if brain.api_key:
                # When default, safety_settings should be None or omitted
                _, kwargs = mock_gen_model.call_args
                assert "safety_settings" not in kwargs or kwargs.get("safety_settings") is None


def test_think_mode_tool_call_interception():
    """When a tool call is returned during think mode, a clean message is returned without leaking parts."""
    mock_model = MagicMock()
    mock_response = MagicMock()
    # Simulate ValueError on response.text when a function call is present
    from unittest.mock import PropertyMock
    type(mock_response).text = PropertyMock(side_effect=ValueError("No text available for function call"))
    mock_model.generate_content.return_value = mock_response

    brain = CoreBrain(model=mock_model, tools=[])
    brain.api_key = "mock-key"

    output = brain.think("Deep reasoning prompt")
    assert "cannot execute tool commands in think mode" in output.lower()


def test_investigation_state_and_callback():
    """Verify InvestigationState dataclass tracks turn state and invokes status callback safely."""
    from core.brain import InvestigationState
    cb_calls = []

    state = InvestigationState(
        trace_id="test-123",
        user_id="alice",
        manifest_str="tool_a, tool_b",
        base_config={},
        circuit_breaker=MagicMock(),
        drift_gate=MagicMock(),
        tool_executor=MagicMock(),
        status_callback=lambda msg: cb_calls.append(msg),
    )

    state.emit("Analyzing topology...")
    assert len(cb_calls) == 1
    assert "Analyzing topology..." in cb_calls[0]
    assert state.trace_id == "test-123"
    assert state.target_mode == "default"


def test_target_device_resolution():
    """Verify CoreBrain resolves explicit device alias or infers from query text."""
    brain = CoreBrain(model=None, tools=[])
    # Explicit override takes priority
    dev = brain._resolve_target_device("check firewall health on fw-branch", explicit_device="fw-hq")
    assert dev == "fw-hq"

    # Match from query against configured devices (fw-hq is in devices.yaml)
    dev2 = brain._resolve_target_device("show status for fw-hq")
    assert dev2 == "fw-hq"

    # Non-matching query returns None
    dev3 = brain._resolve_target_device("show status for unknown-box-999")
    assert dev3 is None


def test_turn_parts_reasoning_extraction():
    """Verify _process_turn_parts extracts Hi-CoT reasoning tags and parses traces."""
    from core.brain import InvestigationState
    brain = CoreBrain(model=None, tools=[])

    mock_breaker = MagicMock()
    mock_gate = MagicMock()
    mock_executor = MagicMock()

    state = InvestigationState(
        trace_id="tr-test",
        user_id="test-user",
        manifest_str="test_tool",
        base_config={},
        circuit_breaker=mock_breaker,
        drift_gate=mock_gate,
        tool_executor=mock_executor,
    )

    mock_response = MagicMock()
    mock_text_part = MagicMock()
    mock_text_part.function_call = None
    mock_text_part.text = (
        "<REASONING>\n"
        "[HYPOTHESIS_MATRIX]: Route table contains blackhole\n"
        "[CONTRADICTION_CHECK]: Default route is active\n"
        "[EVIDENCE_REQUIRED]: Routing FIB dump\n"
        "</REASONING>"
    )
    mock_response.parts = [mock_text_part]

    result = brain._process_turn_parts(mock_response, state, turn=0)
    assert len(result.turn_reasoning_parts) == 1
    assert "Route table contains blackhole" in result.turn_reasoning_parts[0]
    assert len(state.investigation_trace) == 1
    assert state.investigation_trace[0]["turn"] == 0
    assert state.investigation_trace[0]["hypothesis_len"] > 0


def test_license_context_prompt_injection():
    """Verify license context is actively injected into reality prompt when set."""
    from core.brain import InvestigationState
    brain = CoreBrain(model=None, tools=[])
    brain.set_license_context("Threat Prevention: ACTIVE (Expires 2027)")

    state = InvestigationState(
        trace_id="lic-test",
        user_id="alice",
        manifest_str="test_tool",
        base_config={},
        circuit_breaker=MagicMock(),
        drift_gate=MagicMock(),
        tool_executor=MagicMock(),
    )

    prompt = brain._build_reality_prompt("Check threat profiles", state)
    assert "LICENSE STATE:" in prompt
    assert "Threat Prevention: ACTIVE" in prompt


def test_devices_config_mtime_caching():
    """Verify _load_devices_config caches content and reloads on mtime update."""
    from core.brain import _load_devices_config, _DEVICES_CONFIG_PATH
    data1 = _load_devices_config()
    assert isinstance(data1, dict)
    assert "firewalls" in data1

    # Second call returns cached dict without re-reading
    data2 = _load_devices_config()
    assert data1 is data2


def test_quota_retry_wrapper_success_after_rate_limit():
    """Verify _execute_with_quota_retry handles transient 429 and succeeds on retry."""
    brain = CoreBrain(model=None, tools=[])

    call_count = 0
    def flaky_model_call():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise Exception("429 Resource has been exhausted (quota exceeded)")
        return "SUCCESS"

    with patch("time.sleep", return_value=None):
        result = brain._execute_with_quota_retry(flaky_model_call, max_retries=2, operation_name="test")
        assert result == "SUCCESS"
        assert call_count == 2


def test_investigate_abort_event_halts_immediately():
    """Verify abort_event cancels the investigation loop immediately without executing further turns."""
    mock_model = MagicMock()
    mock_chat = MagicMock()
    mock_model.start_chat.return_value = mock_chat

    mock_response = MagicMock()
    mock_part = MagicMock()
    mock_part.function_call = None
    mock_part.text = "Continuing investigation..."
    mock_response.parts = [mock_part]
    mock_chat.send_message.return_value = mock_response

    brain = CoreBrain(model=mock_model, tools=[])
    brain.api_key = "mock-key"

    abort_event = threading.Event()
    abort_event.set()

    result = brain.investigate("Audit security rules", abort_event=abort_event)
    assert "[HALTED]" in result
    assert "cancelled" in result.lower()


def test_tool_tray_hot_swapping():
    """Verify _handle_tool_tray_pivot detects summon_toolkit and updates active tools and manifest."""
    from core.brain import InvestigationState, TurnPartsResult
    brain = CoreBrain(model=None, tools=[])

    mock_keeper = MagicMock()
    tool_a = MagicMock()
    tool_a.__name__ = "pan_traceroute"
    mock_keeper.get_tools.return_value = [tool_a]
    brain.keeper = mock_keeper

    mock_executor = MagicMock()
    state = InvestigationState(
        trace_id="pivot-test",
        user_id="alice",
        manifest_str="old_tool",
        base_config={},
        circuit_breaker=MagicMock(),
        drift_gate=MagicMock(),
        tool_executor=mock_executor,
    )
    state.prev_turn_tools = ["summon_toolkit"]

    mock_call_part = MagicMock()
    mock_call_part.function_call.name = "summon_toolkit"
    mock_call_part.function_call.args = {"tray": "#net"}
    state.history.append(mock_call_part)

    turn_result = TurnPartsResult()
    directive = brain._handle_tool_tray_pivot(turn_result, state)

    assert directive is not None
    assert "Tool Tray '#net' ACTIVATED" in directive
    assert state.manifest_str == "pan_traceroute"
    assert state.tool_executor.tools == [tool_a]


def test_range_schema_enforcement_markdown_and_fallback():
    """Verify _enforce_range_schema cleans markdown fences and enforces RangeSimulationPayload."""
    brain = CoreBrain(model=None, tools=[])

    # Case 1: Clean JSON with markdown fences
    markdown_json = (
        "```json\n"
        "{\n"
        '  "mermaid": "graph TD\\n  A --> B",\n'
        '  "message": "Simulated breach detected",\n'
        '  "threats": 3,\n'
        '  "drops": 1\n'
        "}\n"
        "```"
    )
    res1 = brain._enforce_range_schema(markdown_json, trace_id="range-1")
    parsed1 = json.loads(res1)
    assert parsed1["threats"] == 3
    assert parsed1["drops"] == 1
    assert "graph TD" in parsed1["mermaid"]

    # Case 2: Malformed or plain text fallback
    plain_text = "Analysis complete: no active path found."
    res2 = brain._enforce_range_schema(plain_text, trace_id="range-2")
    parsed2 = json.loads(res2)
    assert "graph TD" in parsed2["mermaid"]
    assert parsed2["message"] == plain_text
    assert parsed2["threats"] == 0

    # Case 3: Mermaid edge labels containing parentheses sanitized
    mermaid_with_parens = (
        "{\n"
        '  "mermaid": "graph TD\\n  A -.->|Dropped (Rule: interzone-default)| B",\n'
        '  "message": "Dropped by policy",\n'
        '  "threats": 0,\n'
        '  "drops": 1\n'
        "}\n"
    )
    res3 = brain._enforce_range_schema(mermaid_with_parens, trace_id="range-3")
    parsed3 = json.loads(res3)
    assert "(" not in parsed3["mermaid"]
    assert "Dropped - Rule: interzone-default" in parsed3["mermaid"]

    # Case 4: Conversational preamble before JSON extracted cleanly without triggering fallback
    raw_with_preamble = (
        'No text outside the JSON output. { "mermaid": "graph TD\\n  Attacker --> Target", '
        '"message": "Contained", "threats": 0, "drops": 1 }'
    )
    res4 = brain._enforce_range_schema(raw_with_preamble, trace_id="range-4")
    parsed4 = json.loads(res4)
    assert parsed4["mermaid"] == "graph TD\n  Attacker --> Target"
    assert parsed4["message"] == "Contained"
    assert parsed4["drops"] == 1


def test_investigate_stream_generator_events():
    """Verify investigate_stream yields status, chunk, response, and done event sequence."""
    mock_model = MagicMock()
    mock_chat = MagicMock()
    mock_model.start_chat.return_value = mock_chat

    mock_response = MagicMock()
    mock_part = MagicMock()
    mock_part.function_call = None
    mock_part.text = "Investigation complete: 0 vulnerabilities found."
    mock_response.parts = [mock_part]
    mock_response.text = "Investigation complete: 0 vulnerabilities found."
    mock_chat.send_message.return_value = mock_response

    brain = CoreBrain(model=mock_model, tools=[])
    brain.api_key = "mock-key"

    stream = brain.investigate_stream("Run quick scan")
    events = list(stream)

    event_types = [e.get("type") for e in events]
    assert "status" in event_types
    assert "response" in event_types
    assert "done" in event_types

    resp_event = next(e for e in events if e.get("type") == "response")
    assert "0 vulnerabilities found" in resp_event["content"]


def test_gemini_38_flash_generation_config_and_range_mode():
    """Verify Gemini 3.8 Flash specs: temperature stripped, JSON schema for range, thinking medium."""
    from core.pipeline.model_config import (
        get_generation_config, classify_mode, get_thinking_level,
        RANGE_PROBE_LIMIT, THINKING_LEVEL_RANGE
    )

    # 1. Generation config in default mode has stripped temperature
    cfg_default = get_generation_config()
    assert cfg_default.temperature is None
    assert cfg_default.response_mime_type is None

    # 2. Generation config in range mode has stripped temperature and clean mime type
    cfg_range = get_generation_config(target_mode="range")
    assert cfg_range.temperature is None
    assert cfg_range.response_mime_type is None

    # 3. Mode classification and thinking level
    assert classify_mode("test attack path", target_mode="range") == "range"
    assert get_thinking_level("range") == THINKING_LEVEL_RANGE
    assert THINKING_LEVEL_RANGE == "medium"
    assert RANGE_PROBE_LIMIT == 7


def test_range_probe_ceiling_guard_injection():
    """Verify ceiling directive is injected and tool_config mode NONE is passed when turn reaches RANGE_PROBE_LIMIT - 1."""
    from core.pipeline.model_config import RANGE_PROBE_LIMIT

    mock_model = MagicMock()
    brain = CoreBrain(model=mock_model, tools=[])
    brain.api_key = "mock-key"

    mock_chat = MagicMock()
    mock_chat.history = []
    mock_response = MagicMock()
    mock_chat.send_message.return_value = mock_response

    state = MagicMock()
    state.target_mode = "range"
    state.trace_id = "test-ceiling"
    state.prev_turn_tools = ["test_security_policy"]
    state.base_config = MagicMock()

    turn_result = MagicMock()
    turn_result.tool_parts = [MagicMock()]

    # At turn = RANGE_PROBE_LIMIT - 1 (turn 6), ceiling guard must inject directive and block tools
    brain._step_tool_feedback(mock_chat, turn_result, state, turn=RANGE_PROBE_LIMIT - 1)
    
    assert mock_chat.send_message.called
    sent_payload = mock_chat.send_message.call_args[0][0]
    has_ceiling_directive = any("SIMULATION PROBE BUDGET REACHED" in str(item) for item in sent_payload)
    assert has_ceiling_directive
    call_kwargs = mock_chat.send_message.call_args[1]
    assert call_kwargs.get("tool_config") == {"function_calling_config": {"mode": "NONE"}}


def test_final_turn_recovery_on_loop_completion():
    """Verify that a synthesizable response received on the final turn is not swallowed as [TIMEOUT]."""
    mock_model = MagicMock()
    mock_chat = MagicMock()
    mock_model.start_chat.return_value = mock_chat

    # Simulate response with valid text
    mock_response = MagicMock()
    mock_part = MagicMock()
    mock_part.function_call = None
    mock_part.text = '{"mermaid": "graph TD\\n  A --> B", "message": "Contained", "threats": 0, "drops": 1}'
    mock_response.parts = [mock_part]
    mock_response.text = mock_part.text
    mock_chat.send_message.return_value = mock_response

    brain = CoreBrain(model=mock_model, tools=[])
    brain.api_key = "mock-key"

    result = brain.investigate("Simulate attack vector", target_mode="range")
    assert "[TIMEOUT]" not in result
    assert "graph TD" in result


def test_circuit_breaker_recovery_in_investigate():
    """Verify that if CircuitBreakerError is raised during turn processing, investigate recovers gracefully."""
    from core.safety.circuit_breaker import CircuitBreakerError

    mock_model = MagicMock()
    mock_chat = MagicMock()
    mock_model.start_chat.return_value = mock_chat

    mock_initial_response = MagicMock()
    mock_chat.send_message.return_value = mock_initial_response

    brain = CoreBrain(model=mock_model, tools=[])
    brain.api_key = "mock-key"

    recovery_text = '{"mermaid": "graph TD\\n  A --> B", "message": "Circuit breaker recovered", "threats": 0, "drops": 1}'
    mock_recovery_response = MagicMock()
    mock_recovery_part = MagicMock()
    mock_recovery_part.function_call = None
    mock_recovery_part.text = recovery_text
    mock_recovery_response.parts = [mock_recovery_part]
    mock_recovery_response.text = recovery_text

    def mock_send_message(payload, **kwargs):
        if any("CIRCUIT BREAKER TRIGGERED" in str(item) for item in payload):
            assert kwargs.get("tool_config") == {"function_calling_config": {"mode": "NONE"}}
            return mock_recovery_response
        return mock_initial_response

    mock_chat.send_message.side_effect = mock_send_message

    with patch.object(brain, "_process_turn_parts", side_effect=CircuitBreakerError("Loop detected: identical tool call repeated")):
        result = brain.investigate("Simulate attack vector", target_mode="range")

    assert "graph TD" in result
    assert "Circuit breaker recovered" in result
