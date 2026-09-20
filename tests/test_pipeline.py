"""
Unit tests for core.pipeline framework.
Tests tool registry loading, Pydantic argument schemas, ghost tool matching,
tool execution caching, prompt assembly, and cognitive trace logging.
"""

import os
import pytest
from unittest.mock import MagicMock, patch

from core.pipeline.tool_keeper import ToolKeeper, summon_toolkit
from core.pipeline.tool_schemas import (
    ExecuteOperationalCommandArgs,
    TestSecurityPolicyArgs,
    GetLiveConfigArgs,
    ExecuteLogQueryArgs,
    TOOL_SCHEMAS,
)
from core.pipeline.tool_executor import ToolExecutor
from core.pipeline.cognitive_trace import CognitiveTraceLogger
from core.pipeline.prompt_assembler import load_system_prompt, load_range_prompt


# ─── 1. Tool Keeper Tests ─────────────────────────────────────────────

def test_tool_keeper_loads_single_commands_and_macros():
    """Verify H1 fix: single commands in commands.yaml return function closure and are registered."""
    keeper = ToolKeeper()
    tools = keeper.get_tools("#core")
    tool_names = [t.__name__ for t in tools]

    assert "summon_toolkit" in tool_names
    # Verify native tools
    assert "test_security_policy" in tool_names
    assert "get_live_config" in tool_names

    # Verify single commands from commands.yaml (e.g. system_info, session_info)
    # These previously returned None and were never loaded
    assert any("system_info" in name or "session_info" in name or "interface_all" in name for name in tool_names)


def test_summon_toolkit_pivot():
    """Verify summon_toolkit returns expected pivot string."""
    res = summon_toolkit("#net")
    assert "#net" in res


# ─── 2. Tool Schemas Tests ────────────────────────────────────────────

def test_execute_operational_command_args_dual_mapping():
    """Verify H2 fix: both 'cmd' and 'command' work and dump to canonical 'cmd'."""
    # Using 'cmd'
    args1 = ExecuteOperationalCommandArgs(cmd="show session info")
    dump1 = args1.model_dump()
    assert dump1["cmd"] == "show session info"

    # Using 'command'
    args2 = ExecuteOperationalCommandArgs(command="show interface all")
    dump2 = args2.model_dump()
    assert dump2["cmd"] == "show interface all"

    # Missing both raises ValueError
    with pytest.raises(ValueError):
        ExecuteOperationalCommandArgs().model_dump()


def test_security_policy_schema_validation():
    """Verify IP and FQDN validation."""
    valid = TestSecurityPolicyArgs(source="10.0.0.1", destination="8.8.8.8", port="443")
    assert valid.port == "443"

    with pytest.raises(ValueError):
        TestSecurityPolicyArgs(source="not-an-ip-or-fqdn!!!", destination="8.8.8.8", port="443")


def test_live_config_xpath_validation():
    """Verify XPath must start with '/'."""
    valid = GetLiveConfigArgs(xpath="/config/devices")
    assert valid.xpath == "/config/devices"

    with pytest.raises(ValueError):
        GetLiveConfigArgs(xpath="config/devices")


# ─── 3. Tool Executor Tests ───────────────────────────────────────────

def test_tool_executor_ghost_tool_exact_matching():
    """Verify H3 fix: substring of an allowed tool name is blocked if not in manifest."""
    breaker = MagicMock()
    executor = ToolExecutor(policy=None, hitl=None, circuit_breaker=breaker, tools=[])

    # Manifest contains 'test_security_policy', but NOT 'test'
    manifest = "test_security_policy, show_system_resources"

    part_mock = MagicMock()
    part_mock.function_call.name = "test"
    part_mock.function_call.args = {}

    result = executor.execute_function_call(
        part=part_mock,
        manifest_str=manifest,
        trace_id="trace-123",
        user_id="user1",
        drive_call_history={},
        turn=0,
        thought_signatures=[]
    )

    # Must be blocked as a ghost tool, not allowed via substring
    assert result.blocked_by == "ghost"
    assert "unknown" in str(result.response_part.function_response.response["result"])


def test_tool_executor_safe_call_kwarg_sanitization():
    """Verify safe_call drops hallucinated arguments."""
    def sample_tool(device: str = "default"):
        return f"Device: {device}"

    # Pass hallucinated argument 'invented_arg'
    result = ToolExecutor.safe_call(sample_tool, {"device": "fw-hq", "invented_arg": "hack"})
    assert result == "Device: fw-hq"


# ─── 4. Cognitive Trace Logger Tests ──────────────────────────────────

def test_cognitive_trace_logger_anchored_path(tmp_path):
    """Verify M2: logs trace to configured or anchored directory with traversal protection."""
    logger = CognitiveTraceLogger(trace_dir=str(tmp_path))
    trace_data = [
        {"turn": 0, "hypothesis_len": 150, "contradiction_len": 50, "drift_score": 0.95}
    ]

    logger.log_trace(trace_id="test/../../escape", target_mode="default", trace_data=trace_data, total_turns=1)

    # Check safe sanitized filename
    files = list(tmp_path.glob("trace_*.json"))
    assert len(files) == 1
    assert "escape" in files[0].name


# ─── 5. Prompt Assembler Tests ────────────────────────────────────────

def test_prompt_assembler_loads_system_prompt():
    """Verify load_system_prompt compiles expected sections without error."""
    prompt = load_system_prompt(persona="neo")
    assert len(prompt) > 500
    assert "PAN-OS" in prompt or "Firewall" in prompt or "NEO" in prompt


# ─── 6. Full Tool Catalog & Schema Hardening ─────────────────────────

def test_tool_keeper_get_all_tools():
    """Verify get_all_tools loads tools across all trays plus native routing tools."""
    keeper = ToolKeeper()
    all_tools = keeper.get_all_tools()
    tool_names = {t.__name__ for t in all_tools}

    # Verify native policy and routing math tools
    assert "test_security_policy" in tool_names
    assert "test_nat_policy" in tool_names
    assert "test_routing_fib" in tool_names

    # Verify tools from other trays are present (e.g. vpn, logs, sys)
    assert "auth_logs" in tool_names
    assert "gp_history" in tool_names
    assert "ha_deep_audit" in tool_names
    assert len(tool_names) >= 40


def test_routing_fib_args_validation():
    """Verify TestRoutingFibArgs schema validates IP addresses."""
    from core.pipeline.tool_schemas import TestRoutingFibArgs
    import pytest

    # Valid IP
    args1 = TestRoutingFibArgs(ip="10.0.1.5")
    assert args1.ip == "10.0.1.5"
    assert args1.virtual_router == "default"

    # Valid CIDR
    args2 = TestRoutingFibArgs(ip="192.168.0.0/24", virtual_router="custom-vr")
    assert args2.virtual_router == "custom-vr"

    # Empty IP should fail
    with pytest.raises(ValueError, match="cannot be empty"):
        TestRoutingFibArgs(ip="   ")

    # Invalid characters / dangerous command injection should fail
    with pytest.raises(ValueError):
        TestRoutingFibArgs(ip="10.0.1.1; reboot")

