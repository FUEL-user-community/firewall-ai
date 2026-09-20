"""
Unit tests for core.safety framework.
Tests command filtering, API key auth, policy engine elevation, budget limits,
circuit breaker loop detection, PII scrubbing, drift gating, and HITL signatures.
"""

import os
import pytest
from unittest.mock import MagicMock, patch
from starlette.requests import Request
from starlette.responses import Response

from core.safety.command_filter import CommandFilter
from core.safety.auth import AuthMiddleware
from core.safety.policy_engine import PolicyEngine, PolicyViolationError
from core.safety.budget_guard import BudgetGuard, BudgetExceededError
from core.safety.circuit_breaker import CircuitBreaker, CircuitBreakerError
from core.safety.scrubber import scrub
from core.safety.semantic_drift_gate import SemanticDriftGate
from core.safety.hitl import ApprovalRequest, AutoApproveProvider, SimulatedInteractiveProvider, get_hitl_provider


# ─── 1. Command Filter Tests ─────────────────────────────────────────

def test_command_filter_allows_valid_commands():
    """Verify H1 fix: valid operational queries with 'set' substring are allowed."""
    assert CommandFilter.is_allowed("show ruleset")[0] is True
    assert CommandFilter.is_allowed("show system setting")[0] is True
    assert CommandFilter.is_allowed("show interface ethernet1/1 offset")[0] is True
    assert CommandFilter.is_allowed("show asset")[0] is True
    assert CommandFilter.is_allowed("test security-policy-match")[0] is True
    assert CommandFilter.is_allowed("request license info")[0] is True


def test_command_filter_blocks_destructive_commands():
    """Verify dangerous CLI patterns are blocked."""
    assert CommandFilter.is_allowed("set address test ip-netmask 1.1.1.1")[0] is False
    assert CommandFilter.is_allowed("delete security rules rule1")[0] is False
    assert CommandFilter.is_allowed("configure")[0] is False
    assert CommandFilter.is_allowed("request restart system")[0] is False
    assert CommandFilter.is_allowed("debug dataplane pool")[0] is False
    assert CommandFilter.is_allowed("test vpn ike-sa gateway test-gw")[0] is False
    assert CommandFilter.is_allowed("test vpn ipsec-sa tunnel test-tun")[0] is False


def test_command_filter_blocks_xml_injection():
    """Verify XML tags inside commands are blocked."""
    assert CommandFilter.is_allowed("<show><system></system></show>")[0] is False
    assert CommandFilter.is_allowed("")[0] is False
    assert CommandFilter.is_allowed(None)[0] is False


# ─── 2. Auth Middleware Tests ─────────────────────────────────────────

def test_auth_middleware_handles_none_client():
    """Verify H3: None client IP does not raise AttributeError."""
    import asyncio
    app_mock = MagicMock()
    middleware = AuthMiddleware(app_mock)

    # Construct request with client=None
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/chat",
        "headers": [],
        "query_string": b"",
        "client": None,
    }
    req = Request(scope)

    async def call_next(r):
        return Response("ok")

    resp = asyncio.run(middleware.dispatch(req, call_next))
    assert resp.status_code == 401


# ─── 3. Policy Engine Tests ──────────────────────────────────────────

def test_policy_engine_thread_local_elevation():
    """Verify H5: mode elevation is thread-scoped."""
    engine = PolicyEngine(mode="READ_ONLY")
    assert engine.mode == "READ_ONLY"

    with engine.elevated("READ_WRITE"):
        assert engine.mode == "READ_WRITE"
        assert engine.check("capture_pcap") is True

    # Restored after context exit
    assert engine.mode == "READ_ONLY"
    with pytest.raises(PolicyViolationError):
        engine.check("capture_pcap")


def test_policy_engine_fail_closed_unknown_tools():
    """Verify H6: unknown tools with write prefixes require WRITE permission."""
    engine = PolicyEngine(mode="READ_ONLY")

    # Safe unknown tool
    assert engine.check("calculate_subnet_overlap") is True

    # Dangerous unknown tool with write prefix
    with pytest.raises(PolicyViolationError):
        engine.check("delete_custom_object")

    with pytest.raises(PolicyViolationError):
        engine.check("clear_arp_cache")


# ─── 4. Budget Guard Tests ───────────────────────────────────────────

def test_budget_guard_trace_isolation():
    """Verify H4: separate trace IDs track independent expenditure."""
    guard = BudgetGuard(max_per_investigation=1.00, max_per_day=50.00)

    # Trace 1 consumes tokens
    guard.record_usage(prompt_tokens=100_000, response_tokens=50_000, trace_id="trace-1")
    cost_1 = guard.get_investigation_cost("trace-1")
    assert cost_1 > 0.0

    # Resetting trace 2 does not clear trace 1
    guard.reset_investigation("trace-2")
    assert guard.get_investigation_cost("trace-1") == cost_1

    # Over-budget on trace 1 triggers error
    with pytest.raises(BudgetExceededError):
        guard.record_usage(prompt_tokens=10_000_000, response_tokens=10_000_000, trace_id="trace-1")


# ─── 5. Circuit Breaker Tests ─────────────────────────────────────────

def test_circuit_breaker_alternating_loop_detection():
    """Verify M1: 2-cycle alternating loop (A -> B -> A -> B) trips the breaker."""
    breaker = CircuitBreaker(max_steps=20, max_loops=3)

    # Alternating calls between tool_a and tool_b
    for _ in range(2):
        breaker.track_tool("tool_a", {"ip": "1.1.1.1"})
        breaker.track_tool("tool_b", {"ip": "2.2.2.2"})

    # On the 3rd pair, it should detect the alternating loop
    breaker.track_tool("tool_a", {"ip": "1.1.1.1"})
    with pytest.raises(CircuitBreakerError) as exc_info:
        breaker.track_tool("tool_b", {"ip": "2.2.2.2"})

    assert "ALTERNATING LOOP DETECTED" in str(exc_info.value)


def test_circuit_breaker_reset():
    """Verify reset clears step count and history."""
    breaker = CircuitBreaker(max_steps=5, max_loops=2)
    breaker.tick()
    breaker.track_tool("tool_a", {})
    assert breaker.step_count == 1
    assert len(breaker.tool_history) == 1

    breaker.reset()
    assert breaker.step_count == 0
    assert len(breaker.tool_history) == 0


# ─── 6. Scrubber Tests ───────────────────────────────────────────────

def test_scrubber_preserves_standard_network_constants():
    """Verify M2: 0.0.0.0, 127.0.0.1, and DNS servers are preserved."""
    raw = "Route: 0.0.0.0/0 via 192.168.1.1 DNS: 8.8.8.8 Local: 127.0.0.1 Serial: 0123456789ABCDEF"
    result = scrub(raw)

    assert "0.0.0.0/0" in result
    assert "8.8.8.8" in result
    assert "127.0.0.1" in result
    # Private IP and Serial should be masked
    assert "192.168.1.1" not in result
    assert "[IP_" in result
    assert "[SN_" in result


# ─── 7. Semantic Drift Gate Tests ────────────────────────────────────

def test_semantic_drift_gate_dimension_clamping():
    """Verify M3: vectors clamped and dimension mismatch handled safely."""
    gate = SemanticDriftGate()
    gate.MIN_TURNS = 1

    # Mock embed_fn to return controlled vectors
    gate._embed_fn = lambda text: [1.0, 0.0, 0.0] if "firewall" in text else [0.0, 1.0, 0.0]

    # Turn 0: baseline accumulates
    r0 = gate.check("firewall investigation start", trace_id="t1", turn=0)
    assert r0.allowed is True

    # Turn 1: same context
    r1 = gate.check("firewall investigation continues", trace_id="t1", turn=1)
    assert r1.allowed is True

    # Turn 2: completely diverged context (orthogonal vector)
    r2 = gate.check("completely unrelated topic cooking recipes", trace_id="t1", turn=2)
    assert r2.allowed is False
    assert r2.severity == "critical"
    assert -1.0 <= r2.similarity <= 1.0


# ─── 8. HITL Provider Tests ──────────────────────────────────────────

def test_hitl_signature_generation():
    """Verify HITL approval produces valid deterministic HMAC signature."""
    provider = AutoApproveProvider()
    req = ApprovalRequest(
        tool_name="apply_dynamic_tag",
        tool_args={"ip": "10.0.0.5", "tag": "Quarantine"},
        user_id="alice",
        trace_id="trace-xyz"
    )

    result = provider.request_approval(req)
    assert result.approved is True
    assert len(result.signature) == 16
    assert result.approver_id == "alice"
