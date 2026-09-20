"""
Unit and integration tests for CardRunner (Script #3).

Covers:
- C1: Target device parameter validation & XML injection rejection
- C2: IPv4 address validation, filtering invalid IPs, and RFC1918 retention
- H3: Thread-safe load_cards() concurrency
- H4: Explicit tool output truncation notification
- H5: BudgetExceededError propagation & safe halt
- M1: Caller tool_outputs immutability in _resolve_identities()
- M3: Hardened evidence cross-validation & hallucination rejection
- Bonus: Graceful handling of blocked response.text ValueError
"""

import threading
from unittest.mock import MagicMock, patch
import pytest

from core.engine.card_runner import CardRunner, NO_TOOLS_CONFIG
from core.safety.budget_guard import BudgetExceededError


@pytest.fixture
def runner():
    """Create a CardRunner instance with mock dependencies where needed."""
    with patch("core.engine.card_runner.CardStore.get_instance"), \
         patch("core.engine.card_runner.BaselineEngine.get_instance"):
        r = CardRunner()
        return r


# ---------------------------------------------------------------------------
# C1: Device Validation & XML Injection Guard
# ---------------------------------------------------------------------------

def test_validate_device_default_and_empty(runner):
    """'default', empty string, and None should resolve to None without error."""
    assert runner._validate_device("default") is None
    assert runner._validate_device(None) is None
    assert runner._validate_device("") is None


def test_validate_device_rejects_injection(runner):
    """Device alias containing XML or shell injection characters must raise ValueError."""
    with pytest.raises(ValueError, match="Invalid device alias format"):
        runner._validate_device("<xml>attack</xml>")

    with pytest.raises(ValueError, match="Invalid device alias format"):
        runner._validate_device("fw-hq; rm -rf /")

    with pytest.raises(ValueError, match="Invalid device alias format"):
        runner._validate_device("fw hq with spaces")

    with pytest.raises(ValueError, match="Invalid device alias format"):
        runner._validate_device("fw/../../etc/passwd")


def test_validate_device_accepts_valid_format(runner):
    """Alphanumeric, hyphen, and underscore names should pass regex check."""
    # When devices.yaml is present, if the device exists it returns device,
    # or if devices.yaml does not declare firewalls, it returns device.
    with patch("core.engine.card_runner._DEVICES_PATH") as mock_path:
        mock_path.exists.return_value = False
        assert runner._validate_device("fw-hq_01") == "fw-hq_01"


# ---------------------------------------------------------------------------
# C2 & M2: IPv4 Address Parsing & Filtering
# ---------------------------------------------------------------------------

def test_resolve_identities_validates_ips_and_retains_rfc1918(runner):
    """
    Validates candidate IPs:
    - Rejects invalid octets (999.999.999.999)
    - Discards loopback (127.0.0.1) and multicast (224.0.0.1)
    - Retains RFC1918 private IPs (10.0.0.5) and public routable IPs
    """
    sample_xml = (
        "<response status='success'><result><ip-user-mapping>"
        "<entry><ip>10.0.0.5</ip><user>acme\\alice</user></entry>"
        "</ip-user-mapping></result></response>"
    )

    tool_outputs = [{
        "tool": "threat_logs",
        "output": (
            "Source IP: 10.0.0.5 and invalid IP: 999.999.999.999. "
            "Localhost 127.0.0.1 and Multicast 224.0.0.1 ignored."
        )
    }]

    with patch("core.panos.ops.execute_operational_command", return_value=sample_xml):
        augmented = runner._resolve_identities(tool_outputs, "default")

        # Identity middleware should be added
        assert len(augmented) == 2
        id_output = augmented[1]
        assert id_output["tool"] == "Identity_Middleware"
        assert "IP 10.0.0.5 belongs to User 'acme\\alice'" in id_output["output"]
        assert "999.999.999.999" not in id_output["output"]
        assert "127.0.0.1" not in id_output["output"]


# ---------------------------------------------------------------------------
# M1: Caller List Immutability
# ---------------------------------------------------------------------------

def test_resolve_identities_preserves_caller_list(runner):
    """_resolve_identities must not mutate the caller's list in-place."""
    tool_outputs = [{"tool": "test_tool", "output": "IP 10.1.1.1"}]
    original_len = len(tool_outputs)

    with patch("core.panos.ops.execute_operational_command", return_value="<entry><ip>10.1.1.1</ip><user>bob</user></entry>"):
        augmented = runner._resolve_identities(tool_outputs, "default")
        assert len(tool_outputs) == original_len
        assert len(augmented) == original_len + 1


# ---------------------------------------------------------------------------
# H4: Output Truncation Notice
# ---------------------------------------------------------------------------

def test_tool_output_truncation_marker(runner):
    """Outputs exceeding 8000 characters must have explicit truncation marker."""
    large_output = "X" * 12000
    mock_tool = MagicMock(return_value=large_output)
    runner._get_tool_map = MagicMock(return_value={"large_tool": mock_tool})

    card_def = {"tool_chain": ["large_tool"]}
    with patch.object(runner, "_resolve_identities", side_effect=lambda x, d: x):
        outputs = runner._run_tool_chain(card_def, "default")

    assert len(outputs) == 1
    out_text = outputs[0]["output"]
    assert len(out_text) < 9000
    assert "[... OUTPUT TRUNCATED — original length: 12000 chars]" in out_text


# ---------------------------------------------------------------------------
# M3: Hardened Evidence Cross-Validation
# ---------------------------------------------------------------------------

def test_evidence_grounding_hardened(runner):
    """
    A claim mentioning a tool name but with hallucinated numbers
    must NOT be marked verified.
    """
    tool_outputs = [{
        "tool": "session_info",
        "output": "Total sessions: 42, active throughput: 100 Mbps"
    }]

    evidence_claims = [
        "session_info: 42 active sessions found",        # Valid (tool + number match)
        "session_info: 9999 rogue sessions detected",    # Hallucinated number 9999
        "Throughput measured at 100 Mbps",              # Valid (number match)
        "threat_logs: attacker 8.8.8.8 detected",       # Hallucinated tool & IP
    ]

    result = runner._validate_evidence(tool_outputs, evidence_claims)

    assert "session_info: 42 active sessions found" in result["verified"]
    assert "Throughput measured at 100 Mbps" in result["verified"]
    assert "session_info: 9999 rogue sessions detected" in result["unverified"]
    assert "threat_logs: attacker 8.8.8.8 detected" in result["unverified"]
    assert result["trust_score"] == 0.5


# ---------------------------------------------------------------------------
# H5: BudgetExceededError Propagation
# ---------------------------------------------------------------------------

def test_budget_exceeded_halts_card(runner):
    """When BudgetExceededError is raised during synthesis, the card halts cleanly."""
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.usage_metadata.prompt_token_count = 500
    mock_response.usage_metadata.candidates_token_count = 100
    mock_model.generate_content.return_value = mock_response

    runner._model = mock_model
    runner.budget_guard = MagicMock()
    runner.budget_guard.record_usage.side_effect = BudgetExceededError("Card budget exceeded")

    card_def = {"id": "card_test", "name": "Test Card", "tool_chain": []}
    runner.get_card_def = MagicMock(return_value=card_def)
    runner._run_tool_chain = MagicMock(return_value=[])

    result = runner.execute("card_test")
    assert result is None  # Halted cleanly


# ---------------------------------------------------------------------------
# Bonus: Safety Block on response.text
# ---------------------------------------------------------------------------

def test_synthesize_handles_blocked_response_text(runner):
    """
    When response.text raises ValueError (e.g. candidate blocked by safety filter),
    _synthesize() should return None gracefully without an uncaught crash.
    """
    mock_model = MagicMock()
    mock_response = MagicMock()
    # Simulate Gemini SDK property getter exception
    type(mock_response).text = property(
        fget=MagicMock(side_effect=ValueError("The response.parts quick accessor only works for a single candidate"))
    )
    mock_model.generate_content.return_value = mock_response
    runner._model = mock_model

    card_def = {"name": "Test Card", "description": "Desc"}
    result = runner._synthesize(card_def, [])
    assert result is None


# ---------------------------------------------------------------------------
# H3: Thread-Safe load_cards()
# ---------------------------------------------------------------------------

def test_load_cards_thread_safety():
    """Concurrent threads calling load_cards() should return consistent results without race."""
    results = []

    def worker():
        cards = CardRunner.load_cards()
        results.append(cards)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 10
    # All threads must see identical dictionary instance or content
    first = results[0]
    for r in results[1:]:
        assert r == first


# ---------------------------------------------------------------------------
# Full Tool Resolution Across All Cards
# ---------------------------------------------------------------------------

def test_card_runner_all_cards_tool_resolution(runner):
    """Verify that every card defined in cards.yaml has all its tools resolved in tool_map."""
    tool_map = runner._get_tool_map()
    cards = runner.load_cards()

    assert len(cards) >= 14, f"Expected at least 14 cards, found {len(cards)}"

    missing_tools = {}
    for card_key, card_def in cards.items():
        chain = card_def.get("tool_chain", [])
        missing = [t for t in chain if t not in tool_map]
        if missing:
            missing_tools[card_key] = missing

    assert not missing_tools, f"Cards have unresolved tools: {missing_tools}"
    # Verify test_routing_fib is resolvable
    assert "test_routing_fib" in tool_map


def test_card_runner_ft01_tool_chain_and_synthesis(runner):
    """Verify FT-01 tool chain executes without missing argument errors and synthesis succeeds."""
    card_def = runner.get_card_def("autonomous_chain_breaker")
    assert card_def is not None

    with patch("core.panos.ops._get_pool") as mock_pool, \
         patch("core.panos.ops.execute_operational_command", return_value="<response status='success'><result/></response>"):
        mock_client = MagicMock()
        mock_client.execute_op.return_value = (200, "<response status='success'><result/></response>")
        mock_pool.return_value.get_client.return_value = mock_client

        outputs = runner._run_tool_chain(card_def, "default")
        assert len(outputs) >= 3
        for out in outputs:
            assert "missing 3 required positional arguments" not in out["output"]
            assert "missing 1 required positional argument" not in out["output"]

        # Test synthesis GenerationConfig
        mock_resp = MagicMock()
        mock_resp.text = '{"triggered": false, "severity": "normal", "title": "Clean", "finding": "Nominal", "evidence": [], "metrics": {}}'
        mock_resp.usage_metadata = MagicMock(prompt_token_count=100, candidates_token_count=50)

        runner._model = MagicMock()
        runner._model.generate_content.return_value = mock_resp

        parsed = runner._synthesize(card_def, outputs)
        assert parsed is not None
        assert parsed["severity"] == "normal"

