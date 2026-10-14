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


def test_execute_operational_command_routing_query_clean(mock_client_pool):
    """Verify 'show routing route' is passed cleanly without illegal count 50."""
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'><result><routes/></result></response>")

    panos_ops.execute_operational_command("show routing route")
    called_cmd = mock_client.execute_op.call_args[0][0]
    assert called_cmd == "show routing route"


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


def test_routing_fib_auto_heals_invalid_virtual_router(mock_client_pool):
    """Verify test_routing_fib auto-heals when virtual-router 'default' is rejected by PAN-OS."""
    _, mock_client = mock_client_pool
    mock_client.virtual_router = "default"
    mock_client._cached_vr = "default"

    vr_config_xml = "<response status='success'><result><virtual-router><entry name='lab-vr'/></virtual-router></result></response>"
    mock_client.execute_get.return_value = (200, vr_config_xml)

    call_count = 0
    def mock_execute_op(cmd):
        nonlocal call_count
        call_count += 1
        if "default" in cmd:
            return (400, "<response status='error'><msg>default is invalid virtual-router. Current target-vsys is none test -> routing -> fib-lookup -> virtual-router is invalid</msg></response>")
        elif "lab-vr" in cmd:
            return (200, "<response status='success'><result><fib><interface>ethernet1/2</interface></fib></result></response>")
        return (400, "error")

    mock_client.execute_op.side_effect = mock_execute_op

    res = panos_ops.test_routing_fib("192.168.1.254")
    assert "ERROR" not in res
    assert call_count == 2
    assert mock_client._cached_vr == "lab-vr"
    assert mock_client.virtual_router == "lab-vr"



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

def test_security_policy_requires_source_and_destination():
    """Verify test_security_policy rejects empty source/destination rather than faking defaults."""
    res1 = panos_ops.test_security_policy(source="", destination="8.8.8.8", port="443")
    assert "source IP address is required" in res1
    res2 = panos_ops.test_security_policy(source="10.0.0.1", destination="", port="443")
    assert "destination IP address is required" in res2


def test_security_policy_includes_zones_and_application_in_xml(mock_client_pool):
    """Verify test_security_policy injects from_zone, to_zone, and application into XML when provided."""
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'><result/></response>")

    panos_ops.test_security_policy(
        source="192.168.1.100",
        destination="192.168.1.1",
        port="443",
        protocol="6",
        from_zone="inside",
        to_zone="inside",
        application="web-browsing",
    )
    xml_called = mock_client.execute_op.call_args[0][0]
    assert "<from>inside</from>" in xml_called
    assert "<to>inside</to>" in xml_called
    assert "<application>web-browsing</application>" in xml_called
    assert "<source>192.168.1.100</source>" in xml_called
    assert "<destination>192.168.1.1</destination>" in xml_called


def test_pbf_policy_validation_and_no_match(mock_client_pool):
    """Verify test_pbf_policy validates input and cleanly parses 'No rule matched'."""
    _, mock_client = mock_client_pool

    # 1. Validation
    assert "source IP address is required" in panos_ops.test_pbf_policy(source="", destination="172.16.20.10")
    assert "destination IP address is required" in panos_ops.test_pbf_policy(source="10.0.1.5", destination="")
    assert "Invalid port number" in panos_ops.test_pbf_policy(source="10.0.1.5", destination="172.16.20.10", destination_port="999999")
    # Counter-logic tests: IP syntax validation & protocol normalization
    assert "Invalid source IP address" in panos_ops.test_pbf_policy(source="not_an_ip", destination="172.16.20.10")
    assert "Invalid destination IP address" in panos_ops.test_pbf_policy(source="10.0.1.5", destination="not_an_ip")
    assert "Invalid protocol" in panos_ops.test_pbf_policy(source="10.0.1.5", destination="172.16.20.10", protocol="999")

    # 2. Protocol name mapping ('tcp' -> 6)
    mock_client.execute_op.return_value = (200, "<response status='success'><result>No rule matched</result></response>")
    res_proto = panos_ops.test_pbf_policy(source="10.0.1.5", destination="172.16.20.10", protocol="tcp")
    assert "No PBF rule matched" in res_proto

    # 3. No rule match fallback
    res = panos_ops.test_pbf_policy(source="10.0.1.5", destination="172.16.20.10", destination_port="443", from_zone="trust")
    assert "No PBF rule matched" in res
    assert "Virtual Router FIB" in res

    # 4. Successful match
    mock_client.execute_op.return_value = (200, "<response status='success'><result><rule>Direct-SDWAN-PBF</rule><action>Forward</action><egress-interface>ethernet1/2</egress-interface></result></response>")
    res_match = panos_ops.test_pbf_policy(source="10.0.1.5", destination="172.16.20.10", destination_port="443")
    assert "Direct-SDWAN-PBF" in res_match
    assert "ethernet1/2" in res_match


def test_execute_operational_command_unbounded_session_safety_interceptor(mock_client_pool):
    """Verify management plane protection interceptor blocks unbounded 'show session all'."""
    _, mock_client = mock_client_pool

    # Unbounded show session all should be blocked by interceptor without hitting client
    res = panos_ops.execute_operational_command("show session all")
    assert "SAFETY INTERCEPTOR" in res
    assert "Unbounded 'show session all' is blocked" in res
    assert not mock_client.execute_op.called

    # Counter-logic test 1: multi-whitespace bypass attempt 'show   session   all'
    res_spaces = panos_ops.execute_operational_command("show   session   all")
    assert "SAFETY INTERCEPTOR" in res_spaces
    assert not mock_client.execute_op.called

    # Counter-logic test 2: empty filter evasion attempt 'show session all filter'
    res_empty_filter = panos_ops.execute_operational_command("show session all filter")
    assert "SAFETY INTERCEPTOR" in res_empty_filter
    assert not mock_client.execute_op.called

    # Filtered show session all must be allowed through
    mock_client.execute_op.return_value = (200, "<response status='success'><result><entry/></result></response>")
    res_filtered = panos_ops.execute_operational_command("show session all filter source 10.0.1.5")
    assert "SAFETY INTERCEPTOR" not in res_filtered
    assert mock_client.execute_op.called

    # Counter-logic test 3: safe session commands ('show session meter') must not be intercepted
    mock_client.execute_op.reset_mock()
    mock_client.execute_op.return_value = (200, "<response status='success'><result><meter/></result></response>")
    res_meter = panos_ops.execute_operational_command("show session meter")
    assert "SAFETY INTERCEPTOR" not in res_meter
    assert mock_client.execute_op.called

    # Counter-logic test 4: HITL operator override allows unbounded show session all through
    mock_client.execute_op.reset_mock()
    mock_client.execute_op.return_value = (200, "<response status='success'><result><entry name='1'/></result></response>")
    res_override = panos_ops.execute_operational_command("show session all", hitl_approved=True)
    assert "SAFETY INTERCEPTOR" not in res_override
    assert mock_client.execute_op.called



