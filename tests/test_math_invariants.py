"""
Math invariant regression tests.

Each section pins a numeric bug found in the math review so it can't regress.
"""
import threading

import pytest

from core.safety.budget_guard import BudgetGuard, BudgetExceededError


# ─── S1. BudgetGuard: get_status must not deadlock ───────────────────

def test_budget_get_status_does_not_deadlock():
    guard = BudgetGuard(max_per_investigation=1.0, max_per_day=10.0)
    guard.record_usage(1000, 1000, trace_id="t")
    out = {}
    worker = threading.Thread(target=lambda: out.update(s=guard.get_status("t")), daemon=True)
    worker.start()
    worker.join(2.0)
    assert not worker.is_alive(), "get_status deadlocked on non-reentrant lock"
    assert "Investigation: $" in out["s"]


def test_budget_get_status_reports_trace_cost():
    guard = BudgetGuard(max_per_investigation=5.0, max_per_day=50.0)
    guard.record_usage(1_000_000, 0, trace_id="t")  # $1.25
    assert "$1.2500/" in guard.get_status("t")


# ─── S2. BudgetGuard: thinking tokens billed at output rate ──────────

def test_budget_thinking_tokens_billed_as_output():
    guard = BudgetGuard()
    base = guard._compute_cost(100_000, 5_000)
    with_thoughts = guard._compute_cost(100_000, 5_000, thoughts_tokens=20_000)
    # 20k thinking tokens * $10/M = $0.20
    assert with_thoughts - base == pytest.approx(20_000 / 1e6 * guard.price_output)


@pytest.mark.parametrize("bad", [None, -5, "x", 1.9])
def test_budget_token_coercion(bad):
    guard = BudgetGuard()
    cost = guard._compute_cost(bad, bad, bad)
    assert cost >= 0.0


def test_budget_record_usage_counts_thoughts():
    guard = BudgetGuard(max_per_investigation=10.0, max_per_day=100.0)
    guard.record_usage(0, 0, trace_id="t", thoughts_tokens=1_000_000)
    assert guard.get_investigation_cost("t") == pytest.approx(guard.price_output)


# ─── S3. BudgetGuard: trace scoping + LRU eviction ───────────────────

def test_budget_reset_one_trace_preserves_others():
    guard = BudgetGuard(max_per_investigation=10.0, max_per_day=100.0)
    guard.record_usage(1_000_000, 0, trace_id="a")
    guard.reset_investigation("b")
    assert guard.get_investigation_cost("a") == pytest.approx(1.25)


def test_budget_eviction_keeps_recently_active_trace():
    guard = BudgetGuard(max_per_investigation=1e9, max_per_day=1e9)
    guard.record_usage(1_000_000, 0, trace_id="LIVE")
    for i in range(1500):
        guard.record_usage(1, 1, trace_id=f"x{i}")
        if i % 100 == 0:
            guard.record_usage(0, 0, trace_id="LIVE")  # still active
    assert guard.get_investigation_cost("LIVE") == pytest.approx(1.25)
    assert len(guard._investigation_costs) <= guard._TRACE_MAX


def test_budget_overshoot_bounded_by_one_call():
    """Cap is checked post-spend: overshoot < cost of the tripping call."""
    guard = BudgetGuard(max_per_investigation=2.0, max_per_day=1e9)
    per_call = guard._compute_cost(100_000, 5_000)  # $0.175
    calls = 0
    with pytest.raises(BudgetExceededError):
        while True:
            calls += 1
            guard.record_usage(100_000, 5_000, trace_id="t")
    total = guard.get_investigation_cost("t")
    assert calls == 12
    assert 0 < total - guard.max_per_investigation < per_call


# ─── S4–S6. Health check math ────────────────────────────────────────

from core.workflows.health_check import (  # noqa: E402
    _FALLBACK_RULES, _apply_thresholds, _parse_telemetry, run_health_check,
)


def _verdict(metrics, subsystem):
    rows = [v for s, v, _ in _apply_thresholds(metrics, rules=_FALLBACK_RULES) if s == subsystem]
    return rows[0] if rows else None


# S4 — idle override must never hide CRITICAL load
def test_idle_override_does_not_mask_critical_load():
    # ratio = 10/2 = 5.0 > 1.50 critical, idle 71% > 70% suppress threshold
    assert _verdict({"load_avg": 10, "vcpu_count": 2, "cpu_idle_pct": 71.0}, "CPU Load") == "CRITICAL"


def test_idle_override_still_suppresses_caution():
    # ratio = 2.0/2 = 1.0 in (0.75, 1.50], idle 90% -> suppressed to NORMAL
    assert _verdict({"load_avg": 2.0, "vcpu_count": 2, "cpu_idle_pct": 90.0}, "CPU Load") == "NORMAL"


def test_zero_vcpu_is_flagged_not_silent():
    assert _verdict({"load_avg": 3.0, "vcpu_count": 0}, "CPU Load") == "CAUTION"


# S5 — parsing math
@pytest.mark.parametrize("raw,hours", [
    ("up 1 day, 3:00, load average: 0.5", 27.0),
    ("10:00:00 up 2 days,  1:30,  1 user", 49.5),
    ("up 5:59, load average: 0.5", 5.98),
    ("up 0 days, 11:30", 11.5),
    ("up 3 days, 45 min", 72.75),
    ("up 42 min", 0.7),
    ("up 10 days", 240.0),
])
def test_uptime_hours(raw, hours):
    assert _parse_telemetry(raw)["uptime_hours"] == pytest.approx(hours, abs=0.01)


@pytest.mark.parametrize("raw,mb", [
    ("Swap:  4095996k total,      1023k used", 1023 / 1024),
    ("Swap:  4095996k total,      1024k used", 1.0),
    ("Swap:  4095996k total,         0k used", 0.0),
    ("KiB Swap:  2048000 total,     2048 used", 2.0),
    ("MiB Swap:   2048.0 total,     12.5 used", 12.5),
])
def test_swap_mb_no_floor(raw, mb):
    assert _parse_telemetry(raw)["swap_mb"] == pytest.approx(mb, abs=1e-3)


def test_sub_mb_swap_triggers_caution():
    m = _parse_telemetry("Swap:  4095996k total,      1023k used")
    assert _verdict(m, "Swap") == "CAUTION"


@pytest.mark.parametrize("raw,idle", [
    ("Cpu(s):  3.0 us, 1.0 sy, 95.5%id", 95.5),
    ("%Cpu(s):  1.2 us,  0.3 sy,  0.0 ni, 98.3 id", 98.3),
    ("Cpu(s): . id", None),       # used to raise ValueError
    ("Cpu(s): 250 id", None),     # out of [0,100]
])
def test_cpu_idle_parse(raw, idle):
    assert _parse_telemetry(raw)["cpu_idle_pct"] == idle


@pytest.mark.parametrize("raw,mb", [
    ("Mem: 8192000k total", 8000.0),
    ("KiB Mem:  8174000 total", 7982.4),
    ("MiB Mem :   7982.4 total", 7982.4),
])
def test_mem_total_normalized_to_mb(raw, mb):
    assert _parse_telemetry(raw)["mem_total_mb"] == pytest.approx(mb, abs=0.1)


def test_vcpu_default_is_flagged():
    m = _parse_telemetry("load average: 0.5")
    assert m["vcpu_count"] == 2 and m["vcpu_assumed"] is True
    assert _parse_telemetry("load average: 0.5\n4 CPUs")["vcpu_assumed"] is False


# S6 — one convention: strict inequality everywhere
@pytest.mark.parametrize("metrics,subsystem,expected", [
    ({"disks": [{"mount": "/", "pct": 85}]}, "Disk", "NORMAL"),
    ({"disks": [{"mount": "/", "pct": 86}]}, "Disk", "CAUTION"),
    ({"disks": [{"mount": "/", "pct": 95}]}, "Disk", "CAUTION"),
    ({"disks": [{"mount": "/", "pct": 96}]}, "Disk", "CRITICAL"),
    ({"disks": [{"mount": "/opt/panlogs", "pct": 92}]}, "Disk", "NORMAL"),
    ({"disks": [{"mount": "/opt/panlogs", "pct": 93}]}, "Disk", "CAUTION"),
    ({"load_avg": 1.50, "vcpu_count": 2}, "CPU Load", "NORMAL"),     # ratio == 0.75
    ({"load_avg": 1.52, "vcpu_count": 2}, "CPU Load", "CAUTION"),
    ({"load_avg": 3.00, "vcpu_count": 2}, "CPU Load", "CAUTION"),    # ratio == 1.50
    ({"load_avg": 3.02, "vcpu_count": 2}, "CPU Load", "CRITICAL"),
    ({"cpu_idle_pct": 50.0}, "CPU Idle", "NORMAL"),
    ({"cpu_idle_pct": 49.9}, "CPU Idle", "CAUTION"),
    ({"cpu_idle_pct": 20.0}, "CPU Idle", "CAUTION"),
    ({"cpu_idle_pct": 19.9}, "CPU Idle", "CRITICAL"),
    ({"uptime_hours": 12}, "Uptime", "NORMAL"),
    ({"uptime_hours": 11.99}, "Uptime", "CAUTION"),
    ({"swap_mb": 0}, "Swap", "NORMAL"),
    ({"swap_mb": 0.001}, "Swap", "CAUTION"),
])
def test_threshold_boundaries_strict(metrics, subsystem, expected):
    assert _verdict(metrics, subsystem) == expected


def test_escalation_counts_subsystems_not_rows():
    # High CPU produces 2 rows (Load + Idle) but is ONE subsystem -> no escalation.
    raw = "up 5 days, 1:00\nload average: 4.0\n2 CPUs\nCpu(s): 10.0%id\nSwap: 100k total, 0k used"
    out = run_health_check(lambda name, args: raw)
    assert "ESCALATION" not in out
    # Add swap pressure -> CPU + Swap = 2 subsystems -> escalate.
    raw2 = raw.replace("0k used", "5000k used")
    out2 = run_health_check(lambda name, args: raw2)
    assert "ESCALATION: 2 subsystems degraded (CPU, Swap)" in out2


# ─── S7. HITL request identity ───────────────────────────────────────

import time  # noqa: E402

from core.safety import hitl  # noqa: E402
from core.safety.hitl import ApprovalRequest, InteractiveHITLProvider  # noqa: E402


@pytest.fixture
def clean_hitl():
    hitl.clear_pending_approvals()
    yield
    hitl.clear_pending_approvals()


def test_identical_requests_get_distinct_ids():
    a = ApprovalRequest("commit", {"x": 1}, "u", "trace-1")
    b = ApprovalRequest("commit", {"x": 1}, "u", "trace-1")
    assert a.request_id != b.request_id
    assert a.request_id == a.request_id  # stable per instance


def test_concurrent_identical_requests_resolve_independently(clean_hitl):
    r1 = ApprovalRequest("commit", {"x": 1}, "u", "trace-1")
    r2 = ApprovalRequest("commit", {"x": 1}, "u", "trace-1")
    out = {}
    t1 = threading.Thread(target=lambda: out.update(a=InteractiveHITLProvider(timeout_seconds=3).request_approval(r1)))
    t2 = threading.Thread(target=lambda: out.update(b=InteractiveHITLProvider(timeout_seconds=3).request_approval(r2)))
    t1.start(); t2.start()
    deadline = time.time() + 2
    while len(hitl.get_pending_approvals()) < 2 and time.time() < deadline:
        time.sleep(0.01)
    assert len(hitl.get_pending_approvals()) == 2
    assert hitl.submit_approval_decision(r1.request_id, True)[0]
    assert hitl.submit_approval_decision(r2.request_id, False)[0]
    t1.join(); t2.join()
    assert out["a"].approved is True
    assert out["b"].approved is False and out["b"].approver_id != "system-timeout"


def test_finished_request_does_not_evict_newer_entry(clean_hitl):
    req = ApprovalRequest("commit", {}, "u", "t")
    impostor = hitl.PendingApproval(request=req, created_at=0.0, event=threading.Event())
    provider = InteractiveHITLProvider(timeout_seconds=0)

    # Simulate a different request taking the same key after ours was inserted.
    real_wait = threading.Event.wait

    def swap_then_wait(self, timeout=None):
        with hitl._APPROVAL_LOCK:
            hitl._PENDING_APPROVALS[req.request_id] = impostor
        return real_wait(self, 0)

    threading.Event.wait = swap_then_wait
    try:
        provider.request_approval(req)
    finally:
        threading.Event.wait = real_wait
    assert hitl._PENDING_APPROVALS.get(req.request_id) is impostor


def test_timeout_zero_is_honored():
    assert InteractiveHITLProvider(timeout_seconds=0).timeout_seconds == 0.0
    t0 = time.time()
    res = InteractiveHITLProvider(timeout_seconds=0).request_approval(ApprovalRequest("c", {}, "u", "t"))
    assert res.approved is False and time.time() - t0 < 1.0


# ─── S8. IP math ─────────────────────────────────────────────────────

from core.pipeline.evidence import _extract_all_ips  # noqa: E402
from core.pipeline.tool_schemas import (  # noqa: E402
    TestRoutingFibArgs as FibArgs,
    TestSecurityPolicyArgs as SecArgs,
)


@pytest.mark.parametrize("text,expected", [
    ("10.0.0.1 and 999.1.1.1", ["10.0.0.1"]),
    ("192.168.001.001", []),
    ("255.255.255.255 0.0.0.0", ["255.255.255.255", "0.0.0.0"]),
    ("10.0.0.256", []),
    ("a 1.2.3.4/24 b", ["1.2.3.4"]),
    ("1.2.3.4.5", []),
])
def test_ip_regex_octet_bounds(text, expected):
    assert [ip for ip in _extract_all_ips(text) if "." in ip] == expected


def _sec(src):
    return SecArgs(source=src, destination="8.8.8.8", port="443")


@pytest.mark.parametrize("ok", ["10.0.0.1", "::1", "any", "fw.example.com"])
def test_policy_match_accepts_hosts(ok):
    assert _sec(ok).source == ok


@pytest.mark.parametrize("bad", [
    "0.0.0.0/0", "::/0", "10.0.0.0/8",            # networks: policy match is one flow
    "10.0.0.1/255.255.255.0", "10.0.0.1/0.0.0.255",  # dotted masks
    "10.0.0.256", "999.1.1.1",                     # malformed IPs (used to pass as FQDN)
])
def test_policy_match_rejects_non_hosts(bad):
    with pytest.raises(ValueError):
        _sec(bad)


def test_fib_cidr_prefix_only():
    assert FibArgs(ip="192.168.0.0/24").ip == "192.168.0.0/24"
    for bad in ("192.168.0.0/255.255.255.0", "192.168.0.0/0.0.0.255", "10.0.0.1/33", "10.0.0.256"):
        with pytest.raises(ValueError):
            FibArgs(ip=bad)


# ─── S9. Mask token width + keying ───────────────────────────────────

import hashlib  # noqa: E402
import math  # noqa: E402
import re  # noqa: E402

from core.safety import scrubber  # noqa: E402
from core.utils.xml_to_yaml import ToxicXmlSanitizer  # noqa: E402


def _birthday_n50(bits):
    return math.sqrt(2 * (2 ** bits) * math.log(2))


def test_scrubber_token_is_48_bits_and_keyed():
    tok = scrubber._deterministic_token("012345678901", "SN")
    m = re.fullmatch(r"\[SN_([0-9a-f]+)\]", tok)
    assert m and len(m.group(1)) * 4 == 48
    assert _birthday_n50(48) > 1e7
    # Not the unkeyed SHA-256 prefix (offline-guessable)
    assert m.group(1) != hashlib.sha256(b"012345678901").hexdigest()[:12]
    # Deterministic within a process
    assert tok == scrubber._deterministic_token("012345678901", "SN")


def test_scrubber_no_collisions_at_realistic_scale():
    toks = {scrubber._deterministic_token(f"{i:012d}", "SN") for i in range(20_000)}
    assert len(toks) == 20_000  # 24-bit tags: P(collision) at 20k ~ 1.0


def test_sanitizer_tag_is_48_bits_and_not_public_seed():
    s = ToxicXmlSanitizer()
    tag = s._hash_value("0123456789AB", "SERIAL")
    m = re.fullmatch(r"\{\{SERIAL_([0-9a-f]+)\}\}", tag)
    assert m and len(m.group(1)) == 12
    assert s.seed != b"panos_static_sanitizer_seed"
    assert ToxicXmlSanitizer()._hash_value("0123456789AB", "SERIAL") == tag  # same process -> same key


def test_sanitizer_explicit_seed_is_stable():
    a = ToxicXmlSanitizer(seed="k")._hash_value("X", "V")
    b = ToxicXmlSanitizer(seed="k")._hash_value("X", "V")
    c = ToxicXmlSanitizer(seed="other")._hash_value("X", "V")
    assert a == b != c


# ─── S10. Circuit breaker: general cycle detection ───────────────────

from core.safety.circuit_breaker import CircuitBreaker, CircuitBreakerError  # noqa: E402


def _trip_at(seq, max_loops=4):
    cb = CircuitBreaker(max_steps=1000, max_loops=max_loops)
    for i, name in enumerate(seq, 1):
        try:
            cb.track_tool(name, {})
        except CircuitBreakerError as e:
            return i, str(e)
    return None, ""


@pytest.mark.parametrize("block,expected_call,label", [
    ("A", 4, "LOOP DETECTED"),            # period 1: k calls
    ("AB", 8, "ALTERNATING"),             # period 2: 2k calls
    ("ABC", 12, "CYCLIC LOOP DETECTED"),  # period 3: 3k calls (was: never)
    ("AAB", 12, "CYCLIC LOOP DETECTED"),  # was: never
    ("ABCD", 16, "CYCLIC LOOP DETECTED"), # period 4: 4k calls (was: never)
])
def test_cycle_detected_at_p_times_k(block, expected_call, label):
    call, msg = _trip_at(list(block) * 10)
    assert call == expected_call and label in msg


def test_period_5_and_progressing_args_not_flagged():
    assert _trip_at(list("ABCDE") * 6)[0] is None  # beyond MAX_CYCLE_PERIOD
    cb = CircuitBreaker(max_steps=1000, max_loops=4)
    for i in range(50):
        cb.track_tool("A", {"page": i})  # new args each time = new information


def test_non_repeating_prefix_does_not_block_detection():
    call, _ = _trip_at(list("XYZ") + list("ABC") * 4)
    assert call == 3 + 12
