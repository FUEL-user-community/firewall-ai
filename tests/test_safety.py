"""
Unit tests for core.safety framework.
Tests command filtering, API key auth, policy engine elevation, budget limits,
circuit breaker loop detection, PII scrubbing, and HITL signatures.
"""

import time
import threading
import pytest
from unittest.mock import MagicMock
from starlette.requests import Request
from starlette.responses import Response

from core.safety.command_filter import CommandFilter
from core.safety.auth import AuthMiddleware
from core.safety.policy_engine import PolicyEngine, PolicyViolationError
from core.safety.budget_guard import BudgetGuard, BudgetExceededError
from core.safety.circuit_breaker import CircuitBreaker, CircuitBreakerError
from core.safety.scrubber import scrub
from core.safety.hitl import (
    ApprovalRequest,
    AutoApproveProvider,
    SimulatedInteractiveProvider,
    InteractiveHITLProvider,
    get_hitl_provider,
    get_pending_approvals,
    submit_approval_decision,
    clear_pending_approvals,
)


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
    """Verify real IP addresses are preserved while hardware serial numbers are masked."""
    raw = "Route: 0.0.0.0/0 via 192.168.1.1 DNS: 8.8.8.8 Local: 127.0.0.1 Serial: 0123456789ABCDEF"
    result = scrub(raw)

    assert "0.0.0.0/0" in result
    assert "8.8.8.8" in result
    assert "127.0.0.1" in result
    # Real IP addresses must remain visible for diagnostics
    assert "192.168.1.1" in result
    assert "[IP_" not in result
    assert "[SN_" in result

    # English phrases like 'serial identifiers' must not be masked
    prose = "Extract hardware models and serial identifiers from output."
    assert scrub(prose) == prose


# ─── 7. HITL Provider Tests ──────────────────────────────────────────

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

def test_policy_engine_set_xml_output_allowed_in_read_only():
    """Verify set_xml_output is permitted in READ_ONLY mode despite 'set_' prefix."""
    engine = PolicyEngine(mode="READ_ONLY")
    assert engine.check("set_xml_output") is True


def test_get_hitl_provider_modes():
    """Verify get_hitl_provider returns correct provider for mode."""
    assert isinstance(get_hitl_provider("autopilot"), AutoApproveProvider)
    assert isinstance(get_hitl_provider(), SimulatedInteractiveProvider)
    assert isinstance(get_hitl_provider("interactive"), InteractiveHITLProvider)
    assert isinstance(get_hitl_provider("queue"), InteractiveHITLProvider)


def test_interactive_hitl_approve_flow():
    """Verify interactive HITL enqueues request, unblocks on approval, and returns valid HMAC signature."""
    clear_pending_approvals()
    provider = InteractiveHITLProvider(timeout_seconds=5.0)
    req = ApprovalRequest(
        tool_name="commit_changes",
        tool_args={"description": "Emergency route fix"},
        user_id="operator1",
        trace_id="trace-test-approve"
    )

    worker_result = [None]
    worker_error = [None]

    def worker():
        try:
            worker_result[0] = provider.request_approval(req)
        except Exception as e:
            worker_error[0] = e

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    # Poll until queued
    deadline = time.time() + 2.0
    pending = []
    while time.time() < deadline:
        pending = get_pending_approvals()
        if pending:
            break
        time.sleep(0.02)

    assert len(pending) == 1
    assert pending[0]["request_id"] == req.request_id
    assert pending[0]["tool_name"] == "commit_changes"

    # Submit operator approval
    success, msg = submit_approval_decision(
        request_id=req.request_id,
        approved=True,
        approver_id="sec-lead",
        reason="Peer-reviewed and approved"
    )
    assert success is True

    t.join(timeout=3.0)
    assert worker_error[0] is None
    res = worker_result[0]
    assert res is not None
    assert res.approved is True
    assert res.approver_id == "sec-lead"
    assert res.reason == "Peer-reviewed and approved"
    assert len(res.signature) == 16
    assert res.latency_ms >= 0

    # Queue must be cleared after resolution
    assert len(get_pending_approvals()) == 0


def test_interactive_hitl_reject_flow():
    """Verify interactive HITL enqueues request and unblocks on operator rejection with fail-safe signature."""
    clear_pending_approvals()
    provider = InteractiveHITLProvider(timeout_seconds=5.0)
    req = ApprovalRequest(
        tool_name="delete_security_rule",
        tool_args={"rule_name": "Block-Malware"},
        user_id="analyst",
        trace_id="trace-test-reject"
    )

    worker_result = [None]

    def worker():
        worker_result[0] = provider.request_approval(req)

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    deadline = time.time() + 2.0
    while time.time() < deadline:
        if get_pending_approvals():
            break
        time.sleep(0.02)

    # Reject
    success, msg = submit_approval_decision(
        request_id=req.request_id,
        approved=False,
        approver_id="sec-lead",
        reason="Unauthorized rule deletion"
    )
    assert success is True

    t.join(timeout=3.0)
    res = worker_result[0]
    assert res is not None
    assert res.approved is False
    assert res.approver_id == "sec-lead"
    assert res.reason == "Unauthorized rule deletion"
    assert res.signature == ""
    assert len(get_pending_approvals()) == 0


def test_interactive_hitl_timeout_fail_closed():
    """Verify interactive HITL fails closed when operator does not respond within timeout window."""
    clear_pending_approvals()
    provider = InteractiveHITLProvider(timeout_seconds=0.08)
    req = ApprovalRequest(
        tool_name="restart_dataplane",
        tool_args={"force": True},
        user_id="analyst",
        trace_id="trace-test-timeout"
    )

    res = provider.request_approval(req)
    assert res.approved is False
    assert res.approver_id == "system-timeout"
    assert "fail-closed" in res.reason.lower()
    assert res.signature == ""
    assert len(get_pending_approvals()) == 0


def test_interactive_hitl_submit_unknown_request():
    """Verify submitting decision for non-existent or expired request returns error tuple without crashing."""
    clear_pending_approvals()
    success, msg = submit_approval_decision("ghost-id-999", approved=True)
    assert success is False
    assert "not found" in msg.lower()


# ─── 8. Hardened Injection & Integrity Tests ─────────────────────────

def test_command_filter_blocks_multiline_and_chaining():
    """Verify that commands containing newlines or shell chaining operators are blocked."""
    assert CommandFilter.is_allowed("show system info\nrequest restart system")[0] is False
    assert CommandFilter.is_allowed("ping 127.0.0.1; whoami")[0] is False
    assert CommandFilter.is_allowed("show interface all & delete rules")[0] is False
    assert CommandFilter.is_allowed("show routing `reboot`")[0] is False


def test_command_filter_blocks_reboot_and_shutdown():
    """Verify explicit blocks for reboot and shutdown commands."""
    assert CommandFilter.is_allowed("reboot")[0] is False
    assert CommandFilter.is_allowed("shutdown")[0] is False


def test_outcomes_classifies_xml_error_as_failed():
    """Verify that PAN-OS XML error responses are classified as failed, not success."""
    from core.pipeline.outcomes import classify_outcome
    xml_err = '<response status="error" code="17"><result><msg>Syntax error</msg></result></response>'
    assert classify_outcome(xml_err) == "failed"
    json_err = '{"status": "error", "message": "unauthorized"}'
    assert classify_outcome(json_err) == "failed"


def test_budget_guard_bounds_memory_under_load():
    """Verify that BudgetGuard prunes old trace keys when tracking over 1000 investigations."""
    guard = BudgetGuard()
    for i in range(1200):
        guard.record_usage(prompt_tokens=10, response_tokens=10, trace_id=f"trace-{i}")
    assert len(guard._investigation_costs) <= 1000


def test_policy_engine_blocks_expanded_write_prefixes_and_dangerous_actions():
    """Verify that administrative prefixes and dangerous action verbs require WRITE permission."""
    engine = PolicyEngine(mode="READ_ONLY")

    # Expanded prefixes
    with pytest.raises(PolicyViolationError):
        engine.check("commit_changes")
    with pytest.raises(PolicyViolationError):
        engine.check("push_panorama_template")
    with pytest.raises(PolicyViolationError):
        engine.check("create_admin_user")
    with pytest.raises(PolicyViolationError):
        engine.check("disable_security_rule")
    with pytest.raises(PolicyViolationError):
        engine.check("override_routing_table")
    with pytest.raises(PolicyViolationError):
        engine.check("reboot_system")

    # Exact dangerous action verbs
    with pytest.raises(PolicyViolationError):
        engine.check("reboot")
    with pytest.raises(PolicyViolationError):
        engine.check("shutdown")
    with pytest.raises(PolicyViolationError):
        engine.check("commit")


def test_scrubber_redacts_credentials_and_keys():
    """Verify that private keys, API keys, and sensitive XML tags are scrubbed while IPs remain."""
    sample = (
        "Server 192.168.1.1 responded.\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\n"
        "Key: LUFRPT1BOWEwV3BqV2l4TE9y... (PAN-OS token)\n"
        "<phash>$1$xyz123$abcd</phash>\n"
        "<pre-shared-key>TopSecretPSK999</pre-shared-key>\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
        "Route 10.0.0.0/8 via 10.0.0.1"
    )

    scrubbed = scrub(sample)

    # Secrets must be masked
    assert "MIIEowIBAAKCAQEA0" not in scrubbed
    assert "[REDACTED_PRIVATE_KEY]" in scrubbed
    assert "LUFRPT1BOWEwV3BqV2l4TE9y" not in scrubbed
    assert "[REDACTED_API_KEY]" in scrubbed
    assert "$1$xyz123$abcd" not in scrubbed
    assert "<phash>[REDACTED_phash]</phash>" in scrubbed
    assert "TopSecretPSK999" not in scrubbed
    assert "<pre-shared-key>[REDACTED_pre-shared-key]</pre-shared-key>" in scrubbed
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in scrubbed
    assert "Bearer [REDACTED_TOKEN]" in scrubbed

    # Real IP addresses must remain visible
    assert "192.168.1.1" in scrubbed
    assert "10.0.0.0/8" in scrubbed
    assert "10.0.0.1" in scrubbed


def test_context_manager_bounds_and_deduplicates_drive_files():
    """Verify ContextManager deduplicates URIs and enforces MAX_FILES_PER_TURN cap."""
    from unittest.mock import MagicMock
    from core.pipeline.context_manager import ContextManager

    cm = ContextManager()
    tool_parts = []
    # Create 10 parts with duplicate and unique URIs
    for i in range(10):
        mock_part = MagicMock()
        uri_id = i % 7  # Some duplicate IDs
        mock_part.function_response.response = {
            "result": f"Analysis complete. GEMINI_FILE_URI: files/evidence_sample_{uri_id} recorded."
        }
        tool_parts.append(mock_part)

    with pytest.MonkeyMock() if hasattr(pytest, 'MonkeyMock') else MagicMock():
        import google.generativeai as genai
        original_get_file = getattr(genai, "get_file", None)
        try:
            genai.get_file = lambda uri: f"MockFile({uri})"
            extracted = cm.extract_drive_files(tool_parts, trace_id="trace-test")
            # Must be capped at MAX_FILES_PER_TURN (5)
            assert len(extracted) <= cm.MAX_FILES_PER_TURN
            assert len(extracted) == 5
        finally:
            if original_get_file:
                genai.get_file = original_get_file


