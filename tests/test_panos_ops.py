"""
Unit tests for core.panos.ops.
Tests operational command execution, telemetry parsing from raw XML,
XML injection defense in PCAP and policy matching, DAG tagging validation,
routing query auto-limiting, and PolicyEngine gates.
"""

import pytest
from unittest.mock import MagicMock, patch

import core.panos.ops as panos_ops


@pytest.fixture(autouse=True)
def reset_singletons():
    panos_ops.reset()
    yield
    panos_ops.reset()


@pytest.fixture
def mock_client_pool():
    with patch("core.panos.ops._get_pool") as mock_get_pool:
        mock_pool = MagicMock()
        mock_client = MagicMock()
        mock_pool.get_client.return_value = mock_client
        mock_get_pool.return_value = mock_pool
        yield mock_pool, mock_client


def test_execute_operational_command_blocked_by_filter():
    """Verify CommandFilter blocks dangerous commands."""
    res = panos_ops.execute_operational_command("request system private-data-reset")
    assert "ERROR: Security Policy Block" in res


def test_execute_operational_command_empty():
    """Verify empty or None command returns error."""
    assert "ERROR: [execute_operational_command]" in panos_ops.execute_operational_command("")
    assert "ERROR: [execute_operational_command]" in panos_ops.execute_operational_command(None)


def test_execute_operational_command_routing_query_auto_limit(mock_client_pool):
    """Verify M1: 'show routing route' automatically appends count 50."""
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'><result><routes/></result></response>")

    panos_ops.execute_operational_command("show routing route")
    called_cmd = mock_client.execute_op.call_args[0][0]
    assert called_cmd == "show routing route count 50"


def test_get_telemetry_snapshot_parses_raw_xml(mock_client_pool):
    """Verify H2: telemetry correctly parses session metrics from raw XML."""
    _, mock_client = mock_client_pool
    mock_session_xml = """<response status='success'>
        <result>
            <num-active>124</num-active>
            <cps>45</cps>
            <kbps>8192</kbps>
        </result>
    </response>"""
    mock_resources_out = "load average: 1.25, 0.95, 0.80\nCpu(s): 15.2%us"

    mock_client.execute_op.side_effect = [
        (200, mock_session_xml),
        (200, mock_resources_out)
    ]

    stats = panos_ops.get_telemetry_snapshot()
    assert stats["active_sessions"] == 124
    assert stats["cps"] == 45
    assert stats["throughput_kbps"] == 8192
    assert stats["mgmt_cpu"] == 1.25
    assert stats["data_cpu"] == 15.2


def test_security_policy_validates_port():
    """Verify H1: invalid port format is caught before querying."""
    res = panos_ops.test_security_policy("10.0.0.1", "8.8.8.8", "invalid_port")
    assert "ERROR: [test_security_policy] Invalid port number" in res


def test_security_policy_success(mock_client_pool):
    """Verify test_security_policy executes valid XML."""
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'><result><rules><entry name='allow-web'/></rules></result></response>")

    res = panos_ops.test_security_policy("10.0.0.5", "8.8.8.8", "443")
    assert "rules" in res or "allow-web" in res
    called_xml = mock_client.execute_op.call_args[0][0]
    assert "<source>10.0.0.5</source>" in called_xml
    assert "<destination-port>443</destination-port>" in called_xml


def test_routing_fib_execution(mock_client_pool):
    """Verify test_routing_fib queries routing table."""
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'><result><fib/></result></response>")

    res = panos_ops.test_routing_fib("1.1.1.1")
    assert "ERROR" not in res
    called_xml = mock_client.execute_op.call_args[0][0]
    assert "<ip>1.1.1.1</ip>" in called_xml

    # Empty IP should return error
    assert "ERROR: [test_routing_fib] IP address cannot be empty" in panos_ops.test_routing_fib("")


def test_nat_policy_validates_port():
    """Verify H1: test_nat_policy validates port number."""
    res = panos_ops.test_nat_policy("10.0.0.1", "8.8.8.8", "99999")
    assert "ERROR: [test_nat_policy] Invalid port number" in res


def test_apply_dynamic_tag_validates_ip_and_tag(mock_client_pool, monkeypatch):
    """Verify C1 & C3: IP address and tag format validation."""
    monkeypatch.setenv("POLICY_MODE", "READ_WRITE")

    # Invalid IP
    res_bad_ip = panos_ops.apply_dynamic_tag("999.999.999.999", "Quarantine-Tag")
    assert "Invalid IP address" in res_bad_ip

    # Invalid Tag (injection attempt)
    res_bad_tag = panos_ops.apply_dynamic_tag("10.0.0.5", "Tag</member><evil>")
    assert "Invalid Tag format" in res_bad_tag


def test_apply_dynamic_tag_read_only_blocked(monkeypatch):
    """Verify C3: apply_dynamic_tag blocked in READ_ONLY mode."""
    monkeypatch.setenv("POLICY_MODE", "READ_ONLY")
    res = panos_ops.apply_dynamic_tag("10.0.0.5", "Tag1")
    assert "ERROR: Security Policy Block" in res


def test_apply_dynamic_tag_success(mock_client_pool, monkeypatch):
    """Verify apply_dynamic_tag succeeds with valid input in READ_WRITE mode."""
    monkeypatch.setenv("POLICY_MODE", "READ_WRITE")
    _, mock_client = mock_client_pool
    mock_client.execute_user_id.return_value = (200, "<response status='success'/>")

    res = panos_ops.apply_dynamic_tag("10.0.0.5", "Quarantine-L1")
    assert "SUCCESS: Tag 'Quarantine-L1' applied to 10.0.0.5" in res
    called_xml = mock_client.execute_user_id.call_args[0][0]
    assert '<entry ip="10.0.0.5">' in called_xml
    assert "<member>Quarantine-L1</member>" in called_xml


def test_capture_pcap_read_only_blocked(monkeypatch):
    """Verify C2: capture_pcap blocked in READ_ONLY mode."""
    monkeypatch.setenv("POLICY_MODE", "READ_ONLY")
    res = panos_ops.capture_pcap("10.0.0.1", "8.8.8.8")
    assert "ERROR: Security Policy Block" in res


def test_capture_pcap_caps_duration_and_guarantees_cleanup(mock_client_pool, monkeypatch):
    """Verify C2 & M3: capture_pcap caps duration to 30s and cleans up in finally."""
    monkeypatch.setenv("POLICY_MODE", "READ_WRITE")
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'/>")
    mock_client.fw.xapi.export_result = b"\x00" * 30  # dummy PCAP

    with patch("core.panos.ops.time.sleep") as mock_sleep:
        res = panos_ops.capture_pcap("10.0.0.1", "8.8.8.8", duration_sec=999)
        assert mock_sleep.called
        # Verify duration capped at 30
        assert mock_sleep.call_args[0][0] == 30

    # Verify capture was stopped in finally
    stop_calls = [
        c for c in mock_client.execute_op.call_args_list
        if "<capture><off/></capture>" in str(c)
    ]
    assert len(stop_calls) >= 1


def test_get_device_inventory(mock_client_pool):
    """Verify get_device_inventory formats device list."""
    mock_pool, _ = mock_client_pool
    mock_pool.get_device_info.return_value = [
        {"name": "fw1", "label": "HQ Firewall", "ip": "192.168.1.1", "connected": True, "default": True},
        {"name": "fw2", "label": "Branch Firewall", "ip": "192.168.2.1", "connected": False, "default": False},
    ]

    inv = panos_ops.get_device_inventory()
    assert "HQ Firewall" in inv
    assert "Branch Firewall" in inv
    assert "[CONNECTED] (DEFAULT)" in inv
    assert "Total: 2 device(s)" in inv
