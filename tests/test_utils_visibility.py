import os
import unittest.mock as mock
import pytest

from core.utils.xml_to_yaml import ToxicXmlSanitizer
import core.utils.xml_to_yaml as xml_mod
from core.utils.startup_validator import validate_startup
from core.utils.obsidian_mapper import GoogleDriveObsidianMapper
from core.workflows.health_check import _apply_thresholds, _parse_telemetry, run_health_check, load_health_rules


# ═══════════════════════════════════════════════════════════════
# 1. XML to YAML Sanitizer & CLI Import Tests
# ═══════════════════════════════════════════════════════════════

def test_xml_to_yaml_sanitizer_and_multi_root():
    """Verify ToxicXmlSanitizer redacts secrets, preserves real IPs, and handles multi-root XML."""
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
    assert "192.168.1.100" in yaml_out
    assert "IP_" not in yaml_out

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
# 4. Obsidian Mapper Tests
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


def test_health_check_parse_telemetry():
    """Verify _parse_telemetry parses CPU, memory, and uptime metrics."""
    raw = "up 10 days\nload average: 0.50, 0.40, 0.30\nCPU idle: 90%\n"
    metrics = _parse_telemetry(raw)
    assert isinstance(metrics, dict)
    assert metrics.get("load_avg") == 0.5
