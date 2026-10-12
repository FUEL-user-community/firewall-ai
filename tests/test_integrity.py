"""
Integrity tests: tool contracts, honest receipts, and computed report banners.

These cover the path the model actually exercises (model args -> sanitizer ->
Pydantic schema -> tool function) and the audit trail built from it. The
original test suite was green while test_nat_policy failed on every call;
these tests exist so that class of failure cannot hide behind green again.
"""

import inspect
from unittest.mock import MagicMock, patch

import pytest

import core.panos.config as panos_config
import core.panos.logs as panos_logs
import core.panos.ops as panos_ops
from core.integrations.google_export import generate_incident_markdown
from core.pipeline.outcomes import classify_outcome, effective_status
from core.pipeline.tool_executor import ToolExecutor
from core.pipeline.tool_schemas import TOOL_SCHEMAS


# Minimal valid arguments per schema'd tool. A new schema without an entry here
# fails test_every_schema_has_contract_sample, forcing the contract to be tested.
CONTRACT_SAMPLES = {
    "test_security_policy": {"source": "10.0.0.1", "destination": "8.8.8.8", "port": "443"},
    "test_nat_policy": {"source": "8.8.8.8", "destination": "203.0.113.20", "port": "443"},
    "test_routing_fib": {"ip": "8.8.8.8"},
    "test_pbf_policy": {"source": "10.0.0.1", "destination": "8.8.8.8"},
    "get_telemetry_snapshot": {},
    "get_live_config": {"xpath": "/config/devices"},
    "execute_log_query": {"log_type": "traffic"},
    "execute_operational_command": {"cmd": "show system info"},
}


def _resolve_tool(name):
    for module in (panos_ops, panos_config, panos_logs):
        fn = getattr(module, name, None)
        if callable(fn):
            return fn
    raise AssertionError(f"Schema '{name}' has no matching tool function in core.panos")


# ─── 1. Tool Contracts ───────────────────────────────────────────────

def test_every_schema_has_contract_sample():
    assert set(TOOL_SCHEMAS) == set(CONTRACT_SAMPLES)


@pytest.mark.parametrize("tool_name", sorted(TOOL_SCHEMAS))
def test_schema_output_fits_function_signature(tool_name):
    """Whatever the schema hands to the function must be accepted by it."""
    fn = _resolve_tool(tool_name)
    dumped = TOOL_SCHEMAS[tool_name](**CONTRACT_SAMPLES[tool_name]).model_dump()
    params = inspect.signature(fn).parameters
    accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())
    if not accepts_kwargs:
        unexpected = set(dumped) - set(params)
        assert not unexpected, f"{tool_name}: schema emits {unexpected} which the function rejects"


def test_nat_policy_end_to_end_through_safe_call():
    """The exact call that failed in production now reaches the device with zone context."""
    with patch("core.panos.ops._get_pool") as get_pool:
        client = MagicMock()
        client.execute_op.return_value = (200, "<response status='success'><result/></response>")
        get_pool.return_value.get_client.return_value = client

        result = ToolExecutor.safe_call(
            panos_ops.test_nat_policy,
            {"source": "8.8.8.8", "destination": "203.0.113.20", "port": "443",
             "from_zone": "outside", "to_interface": "ethernet1/1"},
        )
        xml = client.execute_op.call_args[0][0]

    assert not str(result).startswith(("Tool Error", "ERROR"))
    assert "<from>outside</from>" in xml
    assert "<to-interface>ethernet1/1</to-interface>" in xml


def test_nat_policy_omits_optional_elements_when_unset():
    with patch("core.panos.ops._get_pool") as get_pool:
        client = MagicMock()
        client.execute_op.return_value = (200, "<response status='success'><result/></response>")
        get_pool.return_value.get_client.return_value = client

        ToolExecutor.safe_call(
            panos_ops.test_nat_policy,
            {"source": "8.8.8.8", "destination": "203.0.113.20", "port": "443"},
        )
        xml = client.execute_op.call_args[0][0]

    assert "<from>" not in xml
    assert "<to-interface>" not in xml


def test_executor_discloses_dropped_arguments():
    """A silently dropped arg means the device answered a different question."""
    def sample_tool(device: str = "default"):
        return f"Device: {device}"

    executor = ToolExecutor(policy=None, hitl=None, circuit_breaker=MagicMock(), tools=[sample_tool])
    result, _, _ = executor._raw_execute("sample_tool", {"device": "fw-hq", "zone": "dmz"}, "t-1")

    assert result.startswith("Device: fw-hq")
    assert "[EXECUTOR NOTE]" in result
    assert "zone" in result


# ─── 2. Outcome Classification ───────────────────────────────────────

@pytest.mark.parametrize("raw, blocked_by, expected", [
    ("Tool Error: unexpected keyword argument 'from_zone'", "", "failed"),
    ("ERROR: [test_nat_policy] PAN-OS returned HTTP 500.", "", "failed"),
    ("Error: No data returned from firewall.", "", "failed"),
    ("Argument validation error for get_live_config: ...", "", "failed"),
    ("   ERROR: leading whitespace still a failure", "", "failed"),
    ("ERROR: Security Policy Block - XPath not permitted", "", "blocked"),
    ("ERROR: Tool 'x' unknown.", "ghost", "blocked"),
    ("POLICY BLOCKED: write tool", "policy", "blocked"),
    ("This content was already loaded on Turn 1.", "duplicate", "skipped"),
    ("response:\n  result:\n    msg: 'counter error-rate 0'", "", "success"),
    ("hostname: firewall-a\nsw-version: 10.0.12-h3", "", "success"),
])
def test_classify_outcome(raw, blocked_by, expected):
    assert classify_outcome(raw, blocked_by) == expected


def test_effective_status_overrides_stale_success_label():
    """Receipts recorded before honest classification are corrected at render time."""
    receipt = {"status": "success", "raw_output": "Tool Error: unexpected keyword argument 'from_zone'"}
    assert effective_status(receipt) == "failed"


# ─── 3. Computed Report Banner ───────────────────────────────────────

def _receipt(tool, raw, status="success"):
    return {"tool": tool, "duration_ms": 1.0, "status": status, "args": {}, "raw_output": raw}


def test_report_never_self_certifies():
    md = generate_incident_markdown("t", "q", "verdict", receipts=[_receipt("system_info", "sw-version: 10.0.12-h3")])
    assert "Zero Hallucination" not in md
    assert "Verified" not in md.split("---")[0]
    assert "Claim Verification:** Enforced by code" in md
    assert "not that it supports the sentence" in md or "no checkable claims" in md


def test_report_flags_partial_receipts_and_lists_gaps():
    receipts = [
        _receipt("system_info", "sw-version: 10.0.12-h3"),
        _receipt("test_nat_policy", "Tool Error: unexpected keyword argument 'from_zone'"),
        _receipt("get_live_config", "nat: rules: ..."),
    ]
    md = generate_incident_markdown("t", "q", "verdict", receipts=receipts)

    assert "PARTIAL - 2/3" in md
    assert "1 failed; Step 2)" in md
    assert "| 2 | `test_nat_policy` | 1.0ms | FAILED |" in md
    assert "Step 2 `test_nat_policy` FAILED" in md


def test_report_with_no_receipts_is_unverified():
    md = generate_incident_markdown("t", "q", "verdict", receipts=[])
    assert "Receipt Integrity:** NONE" in md
