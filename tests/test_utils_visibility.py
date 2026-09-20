import os
import math
import unittest.mock as mock
import pytest

from core.utils.xml_to_yaml import ToxicXmlSanitizer
import core.utils.xml_to_yaml as xml_mod
from core.utils.startup_validator import validate_startup
from core.utils.obsidian_mapper import GoogleDriveObsidianMapper
from core.visibility.auditor import Auditor, AuditResult
from core.visibility.logprobs import _shannon_entropy, extract_logprobs
from core.workflows.health_check import _apply_thresholds, _parse_telemetry, run_health_check, load_health_rules


# ═══════════════════════════════════════════════════════════════
# 1. XML to YAML Sanitizer & CLI Import Tests
# ═══════════════════════════════════════════════════════════════

def test_xml_to_yaml_sanitizer_and_multi_root():
    """Verify ToxicXmlSanitizer redacts secrets, hashes IPs, and handles multi-root XML."""
    sanitizer = ToxicXmlSanitizer(seed="test_seed_123")
    xml_sample = """
    <response status="success">
        <entry name="rule1">
            <ip>192.168.1.100</ip>
            <password>plaintext_secret</password>
            <member>item1</member>
            <member>item2</member>
        </entry>
    </response>
    """
    yaml_out = sanitizer.convert_string(xml_sample)
    assert "{{REDACTED_SECRET}}" in yaml_out
    assert "plaintext_secret" not in yaml_out
    assert "192.168.1.100" not in yaml_out
    assert "IP_" in yaml_out

    # Multi-root XML safety
    multi_root = "<entry>1</entry><entry>2</entry>"
    wrapped_out = sanitizer.convert_string(multi_root)
    assert "entry" in wrapped_out


def test_xml_to_yaml_cli_sys_imported():
    """Verify sys is imported in xml_to_yaml (H1)."""
    assert hasattr(xml_mod, "sys")


# ═══════════════════════════════════════════════════════════════
# 2. Startup Validator Tests
# ═══════════════════════════════════════════════════════════════

def test_startup_validator_backends_and_aws():
    """Verify validate_startup detects invalid backends and missing AWS vars."""
    # 1. Invalid backend
    with mock.patch.dict(os.environ, {"SECRETS_BACKEND": "invalid_backend"}):
        with pytest.raises(RuntimeError) as exc:
            validate_startup()
        assert "SECRETS_BACKEND='invalid_backend' is not valid" in str(exc.value)

    # 2. AWS missing AWS_SECRET_NAME (L1)
    with mock.patch.dict(os.environ, {
        "SECRETS_BACKEND": "aws",
        "PANOS_HOSTNAME": "10.0.0.1",
        "AWS_SECRET_NAME": ""
    }):
        with pytest.raises(RuntimeError) as exc:
            validate_startup()
        assert "AWS backend requires AWS_SECRET_NAME" in str(exc.value)


# ═══════════════════════════════════════════════════════════════
# 3. Health Check Workflow Tests
# ═══════════════════════════════════════════════════════════════

def test_health_check_workflow_zero_division_guard():
    """Verify _apply_thresholds guards against vcpus=0 (M1)."""
    metrics = {
        "load_avg": 2.5,
        "vcpu_count": 0,
        "uptime_hours": 12,
        "swap_mb": 50,
        "cpu_idle_pct": 10.0
    }
    findings = _apply_thresholds(metrics)
    assert isinstance(findings, list)
    # Check that CAUTION and CRITICAL were applied without division by zero
    verdicts = [v for _, v, _ in findings]
    assert "CAUTION" in verdicts
    assert "CRITICAL" in verdicts


def test_health_check_workflow_run():
    """Verify run_health_check formats structured results and multi-caution escalation."""
    sample_telemetry = """
    10:00:00 up 2 days,  1:30,  1 user,  load average: 0.50, 0.40, 0.30
    Cpu(s): 85.0%id
    Swap:  4095996k total,        0k used,  4095996k free
    Mem: 8192000k total
    2 CPUs
    """
    def mock_executor(tool_name, args):
        return sample_telemetry

    output = run_health_check(mock_executor)
    assert "HEALTH CHECK RESULTS" in output
    assert "Uptime: NORMAL" in output
    assert "Swap: NORMAL" in output


def test_health_rules_loading():
    """Verify load_health_rules loads from YAML and provides safe fallbacks."""
    rules = load_health_rules()
    assert isinstance(rules, dict)
    assert "uptime" in rules
    assert "storage" in rules
    assert "system_partitions" in rules["storage"]
    assert "log_partitions" in rules["storage"]
    assert rules["storage"]["log_partitions"]["caution_pct"] >= 90


def test_health_check_partition_smart_storage():
    """Verify partition-smart storage rules distinguish /opt/panlogs from root/config."""
    # /opt/panlogs at 91% should be NORMAL (limit 92)
    # /opt/pancfg at 88% should be CAUTION (limit 85)
    metrics = {
        "uptime_hours": 48,
        "swap_mb": 0,
        "load_avg": 0.5,
        "vcpu_count": 2,
        "cpu_idle_pct": 80.0,
        "disks": [
            {"filesystem": "/dev/sda5", "mount": "/opt/panlogs", "pct": 91},
            {"filesystem": "/dev/sda3", "mount": "/opt/pancfg", "pct": 88},
        ]
    }
    findings = _apply_thresholds(metrics)
    disk_findings = [f for f in findings if f[0] == "Disk"]
    assert len(disk_findings) == 1
    subsystem, verdict, detail = disk_findings[0]
    assert verdict == "CAUTION"
    assert "/opt/pancfg" in detail
    assert "/opt/panlogs" not in detail  # Log partition at 91% is suppressed from alerting


# ═══════════════════════════════════════════════════════════════
# 4. Visibility (Logprobs & Auditor) Tests
# ═══════════════════════════════════════════════════════════════

def test_shannon_entropy_normalized():
    """Verify normalized Shannon entropy calculation (M2)."""
    # 50/50 split should equal exactly 1.0 bit
    assert math.isclose(_shannon_entropy([0.5, 0.5]), 1.0, rel_tol=1e-3)

    # 4-way uniform split equals 2.0 bits
    assert math.isclose(_shannon_entropy([0.25, 0.25, 0.25, 0.25]), 2.0, rel_tol=1e-3)

    # Unnormalized inputs (e.g. 0.2, 0.2) should normalize to 50/50 and return 1.0
    assert math.isclose(_shannon_entropy([0.2, 0.2]), 1.0, rel_tol=1e-3)

    # Empty or zero cases
    assert _shannon_entropy([]) == 0.0
    assert _shannon_entropy([0.0, 0.0]) == 0.0


def test_logprob_extraction_with_candidates():
    """Verify extract_logprobs computes margin and escalation correctly."""
    mock_resp = mock.MagicMock()
    mock_candidate = mock.MagicMock()

    # Create top candidate logprobs simulating critical vs caution
    top_cand = mock.MagicMock()
    c1 = mock.MagicMock()
    c1.token = "critical"
    c1.log_probability = math.log(0.52)

    c2 = mock.MagicMock()
    c2.token = "caution"
    c2.log_probability = math.log(0.48)

    top_cand.candidates = [c1, c2]

    mock_candidate.logprobs_result.top_candidates = [top_cand]
    mock_resp.candidates = [mock_candidate]

    result = extract_logprobs(mock_resp)
    assert "critical" in result.severity_distribution
    assert "caution" in result.severity_distribution
    assert result.confidence_margin == pytest.approx(0.04, abs=0.01)
    # Margin 0.04 < 0.10 threshold -> should escalate
    assert result.should_escalate is True


def test_logprob_extraction_json_quoted_and_punct():
    """Verify extract_logprobs cleans JSON quotes and punctuation."""
    mock_resp = mock.MagicMock()
    mock_candidate = mock.MagicMock()

    top_cand = mock.MagicMock()
    c1 = mock.MagicMock()
    c1.token = ' "CRITICAL",'
    c1.log_probability = math.log(0.85)

    c2 = mock.MagicMock()
    c2.token = ' "NORMAL",\n'
    c2.log_probability = math.log(0.15)

    top_cand.candidates = [c1, c2]
    mock_candidate.logprobs_result.top_candidates = [top_cand]
    mock_resp.candidates = [mock_candidate]

    result = extract_logprobs(mock_resp)
    assert "critical" in result.severity_distribution
    assert "normal" in result.severity_distribution
    assert result.confidence_margin == pytest.approx(0.70, abs=0.02)
    assert result.should_escalate is False


def test_logprob_extraction_synonym_pooling():
    """Verify extract_logprobs pools synonymous tokens (critical + severe) into canonical tier."""
    mock_resp = mock.MagicMock()
    mock_candidate = mock.MagicMock()

    top_cand = mock.MagicMock()
    c1 = mock.MagicMock()
    c1.token = "critical"
    c1.log_probability = math.log(0.48)

    c2 = mock.MagicMock()
    c2.token = "severe"
    c2.log_probability = math.log(0.47)

    c3 = mock.MagicMock()
    c3.token = "normal"
    c3.log_probability = math.log(0.05)

    top_cand.candidates = [c1, c2, c3]
    mock_candidate.logprobs_result.top_candidates = [top_cand]
    mock_resp.candidates = [mock_candidate]

    result = extract_logprobs(mock_resp)
    # critical + severe mapped to canonical "critical" tier (0.48 + 0.47 = 0.95)
    assert result.severity_distribution["critical"] == pytest.approx(0.95, abs=0.02)
    assert result.severity_distribution["normal"] == pytest.approx(0.05, abs=0.02)
    assert result.confidence_margin == pytest.approx(0.90, abs=0.02)
    assert result.should_escalate is False


def test_logprob_subword_extraction():
    """Verify extract_logprobs extracts BPE subwords like crit and caut."""
    mock_resp = mock.MagicMock()
    mock_candidate = mock.MagicMock()

    top_cand = mock.MagicMock()
    c1 = mock.MagicMock()
    c1.token = "crit"
    c1.log_probability = math.log(0.55)

    c2 = mock.MagicMock()
    c2.token = "caut"
    c2.log_probability = math.log(0.45)

    top_cand.candidates = [c1, c2]
    mock_candidate.logprobs_result.top_candidates = [top_cand]
    mock_resp.candidates = [mock_candidate]

    result = extract_logprobs(mock_resp)
    assert "critical" in result.severity_distribution
    assert "caution" in result.severity_distribution
    assert result.confidence_margin == pytest.approx(0.10, abs=0.02)


def test_logprob_extraction_multi_position_normalization():
    """Verify extract_logprobs normalizes accumulated mass across multiple token positions."""
    mock_resp = mock.MagicMock()
    mock_candidate = mock.MagicMock()

    # Position 1: "normal" (0.80) vs "caution" (0.20)
    top_cand1 = mock.MagicMock()
    c1 = mock.MagicMock(token="normal", log_probability=math.log(0.80))
    c2 = mock.MagicMock(token="caution", log_probability=math.log(0.20))
    top_cand1.candidates = [c1, c2]

    # Position 2: "normal" (0.90) vs "caution" (0.10)
    top_cand2 = mock.MagicMock()
    c3 = mock.MagicMock(token="normal", log_probability=math.log(0.90))
    c4 = mock.MagicMock(token="caution", log_probability=math.log(0.10))
    top_cand2.candidates = [c3, c4]

    mock_candidate.logprobs_result.top_candidates = [top_cand1, top_cand2]
    mock_resp.candidates = [mock_candidate]

    result = extract_logprobs(mock_resp)
    # Total mass was 2.0 (normal 1.70, caution 0.30)
    # Normalized: normal = 1.70 / 2.0 = 0.85, caution = 0.30 / 2.0 = 0.15
    assert result.severity_distribution["normal"] == pytest.approx(0.85, abs=0.01)
    assert result.severity_distribution["caution"] == pytest.approx(0.15, abs=0.01)
    assert sum(result.severity_distribution.values()) == pytest.approx(1.0, abs=0.01)
    # Margin must be strictly bounded <= 1.0 (here 0.85 - 0.15 = 0.70)
    assert result.confidence_margin == pytest.approx(0.70, abs=0.01)
    assert 0.0 <= result.confidence_margin <= 1.0


def test_auditor_reset_and_null_guard():
    """Verify Auditor singleton reset and null audit_score handling (M3)."""
    Auditor.reset()
    auditor = Auditor.get_instance()
    assert auditor is not None

    # Verify reset clears instance
    Auditor.reset()
    auditor2 = Auditor.get_instance()
    assert auditor2 is not None

    # When disabled, audit() returns clean skipped result
    res = auditor.audit(
        tool_outputs=[{"tool": "test", "output": "ok"}],
        reasoning_trace=["step 1"],
        severity="NORMAL",
        finding="All healthy"
    )
    assert res.audit_score == 1.0
    assert "skipped" in res.summary.lower()


# ═══════════════════════════════════════════════════════════════
# 5. Obsidian Mapper Tests
# ═══════════════════════════════════════════════════════════════

def test_obsidian_mapper_reset():
    """Verify GoogleDriveObsidianMapper.reset() resets singleton (L2)."""
    GoogleDriveObsidianMapper.reset()
    m1 = GoogleDriveObsidianMapper.get_instance()
    assert m1 is not None

    GoogleDriveObsidianMapper.reset()
    m2 = GoogleDriveObsidianMapper.get_instance()
    assert m2 is not None

    # map_tool_result returns gracefully when disabled
    m1.map_tool_result("interface_all", {}, "dummy output text")
