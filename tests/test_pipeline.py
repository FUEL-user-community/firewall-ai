"""
Unit tests for core.pipeline framework.
Tests tool registry loading, Pydantic argument schemas, ghost tool matching,
tool execution caching, prompt assembly, and cognitive trace logging.
"""

import pytest
from unittest.mock import MagicMock

from core.pipeline.tool_keeper import ToolKeeper, summon_toolkit, inspect_own_harness
from core.pipeline.tool_schemas import (
    ExecuteOperationalCommandArgs,
    TestSecurityPolicyArgs,
    GetLiveConfigArgs,
    ExecuteLogQueryArgs,
    TOOL_SCHEMAS,
)
from core.pipeline.tool_executor import ToolExecutor
from core.pipeline.prompt_assembler import load_system_prompt, load_range_prompt


# ─── 1. Tool Keeper Tests ─────────────────────────────────────────────

def test_tool_keeper_loads_single_commands_and_macros():
    """Verify H1 fix: single commands in commands.yaml return function closure and are registered."""
    keeper = ToolKeeper()
    tools = keeper.get_tools("#core")
    tool_names = [t.__name__ for t in tools]

    assert "summon_toolkit" in tool_names
    assert "inspect_own_harness" in tool_names
    # Verify native tools
    assert "test_security_policy" in tool_names
    assert "test_pbf_policy" in tool_names
    assert "get_live_config" in tool_names

    # Verify single commands from commands.yaml (e.g. system_info, session_info)
    # These previously returned None and were never loaded
    assert any("system_info" in name or "session_info" in name or "interface_all" in name for name in tool_names)


def test_summon_toolkit_pivot():
    """Verify summon_toolkit returns expected pivot string."""
    res = summon_toolkit("#net")
    assert "#net" in res


def test_inspect_own_harness_manifest_tree():
    """Verify inspect_own_harness in tree mode lists scoped files without leaking credentials or tests."""
    manifest = inspect_own_harness("tree")
    assert "--- HARNESS SOURCE TREE ---" in manifest
    assert "server.py" in manifest
    assert "config/commands.yaml" in manifest
    assert "core/brain.py" in manifest
    assert ".env" not in manifest
    assert "tests/" not in manifest


def test_inspect_own_harness_file_read():
    """Verify inspect_own_harness can read allowed files with line numbers."""
    content = inspect_own_harness("core/pipeline/tool_keeper.py", start_line=1, end_line=15)
    assert "--- HARNESS SOURCE: core/pipeline/tool_keeper.py (Lines 1-15 of" in content
    assert "1: import" in content


def test_inspect_own_harness_security_blocks():
    """Verify inspect_own_harness enforces path traversal, credential, and test fixture guardrails."""
    # Test directory blocked
    res_test = inspect_own_harness("tests/test_pipeline.py")
    assert "forbidden" in res_test

    # .env blocked
    res_env = inspect_own_harness(".env")
    assert "forbidden" in res_env

    # Path traversal blocked
    res_trav = inspect_own_harness("../../../etc/passwd")
    assert "forbidden" in res_trav

    # Non-python/yaml extension blocked
    res_ext = inspect_own_harness("README.md")
    assert "forbidden" in res_ext



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


def test_tool_executor_unbounded_session_hitl_override():
    """Verify ToolExecutor intercepts unbounded 'show session all', requests HITL, and strips self-approvals."""
    from core.safety.policy_engine import PolicyEngine
    from core.safety.hitl import ApprovalResult

    mock_tool = MagicMock(return_value="session-data")
    mock_tool.__name__ = "execute_operational_command"

    policy = PolicyEngine(mode="READ_ONLY")
    hitl_mock = MagicMock()
    breaker = MagicMock()
    executor = ToolExecutor(policy=policy, hitl=hitl_mock, circuit_breaker=breaker, tools=[mock_tool])

    # 1. Denied branch
    hitl_mock.request_approval.return_value = ApprovalResult(approved=False, reason="Too risky")
    part_mock = MagicMock()
    part_mock.function_call.name = "execute_operational_command"
    part_mock.function_call.args = {"cmd": "show session all"}

    res_denied = executor.execute_function_call(
        part=part_mock,
        manifest_str="execute_operational_command",
        trace_id="tr-1",
        user_id="alice",
        drive_call_history={},
        turn=0,
        thought_signatures=[]
    )
    assert res_denied.blocked_by == "hitl"
    assert "HITL DENIED" in str(res_denied.response_part.function_response.response["result"])
    assert not mock_tool.called

    # 2. Approved branch with counter-logic: LLM attempts self-approval
    hitl_mock.reset_mock()
    hitl_mock.request_approval.return_value = ApprovalResult(approved=True, signature="abc123sig")
    part_mock.function_call.args = {"cmd": "show   session   all", "hitl_approved": True}

    res_approved = executor.execute_function_call(
        part=part_mock,
        manifest_str="execute_operational_command",
        trace_id="tr-2",
        user_id="bob",
        drive_call_history={},
        turn=0,
        thought_signatures=[]
    )
    assert res_approved.blocked_by == ""
    assert hitl_mock.request_approval.called
    assert mock_tool.called
    call_kwargs = mock_tool.call_args[1]
    assert call_kwargs.get("hitl_approved") is True


def test_tool_executor_device_access_rbac():
    """Verify ToolExecutor enforces per-device RBAC via PolicyEngine.check_device_access."""
    from core.safety.policy_engine import PolicyEngine

    mock_tool = MagicMock(return_value="inventory-data")
    mock_tool.__name__ = "get_device_inventory"

    policy = PolicyEngine(mode="READ_ONLY")
    breaker = MagicMock()
    executor = ToolExecutor(policy=policy, hitl=None, circuit_breaker=breaker, tools=[mock_tool])

    class MockUserContext:
        def __init__(self, user_id, allowed):
            self.user_id = user_id
            self.role = "operator"
            self.allowed_devices = allowed

        def can_access_device(self, dev):
            return dev in self.allowed_devices

    # 1. Denied device access
    user_restricted = MockUserContext("alice", ["fw-hq"])
    part_mock = MagicMock()
    part_mock.function_call.name = "get_device_inventory"
    part_mock.function_call.args = {"target_device": "fw-restricted-branch"}

    res_denied = executor.execute_function_call(
        part=part_mock,
        manifest_str="get_device_inventory",
        trace_id="tr-rbac-1",
        user_id=user_restricted,
        drive_call_history={},
        turn=0,
        thought_signatures=[]
    )
    assert res_denied.blocked_by == "rbac"
    assert "DEVICE ACCESS DENIED" in str(res_denied.response_part.function_response.response["result"])
    assert not mock_tool.called

    # 2. Allowed device access
    mock_tool.reset_mock()
    part_mock.function_call.args = {"target_device": "fw-hq"}
    res_allowed = executor.execute_function_call(
        part=part_mock,
        manifest_str="get_device_inventory",
        trace_id="tr-rbac-2",
        user_id=user_restricted,
        drive_call_history={},
        turn=0,
        thought_signatures=[]
    )
    assert res_allowed.blocked_by == ""
    assert mock_tool.called


def test_tool_keeper_registers_telemetry_snapshot():
    """Verify get_telemetry_snapshot is registered in #core and all_tools catalog."""
    keeper = ToolKeeper()
    core_names = [t.__name__ for t in keeper.get_tools("#core")]
    all_names = [t.__name__ for t in keeper.get_all_tools()]
    assert "get_telemetry_snapshot" in core_names
    assert "get_telemetry_snapshot" in all_names




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


def test_tool_schemas_preserve_target_device():
    """Verify target_device is preserved across all registered schemas."""
    from core.pipeline.tool_schemas import TOOL_SCHEMAS
    for tool_name, schema in TOOL_SCHEMAS.items():
        fields = schema.model_fields
        assert "target_device" in fields, f"Schema for '{tool_name}' is missing target_device"


def test_load_range_prompt():
    """Verify load_range_prompt loads valid YAML directives for the range simulator."""
    prompt = load_range_prompt(persona="neo")
    assert isinstance(prompt, str)
    assert len(prompt) > 0
    assert "RANGE SIMULATION MISSION" in prompt


def test_execute_log_query_schema():
    """Verify ExecuteLogQueryArgs accepts valid log types and rejects invalid ones."""
    args = ExecuteLogQueryArgs(log_type="traffic")
    assert args.log_type == "traffic"
    with pytest.raises(ValueError, match="not in valid log types"):
        ExecuteLogQueryArgs(log_type="invalid_type")
