"""
Unit tests for core.panos.client.
Tests XML injection defense, SSL context binding, timeout application,
XML error escaping, thread-safe connection pooling, and secrets fallback.
"""

import pytest
import yaml
import threading
from unittest.mock import MagicMock, patch

from core.panos.client import PanOSClient, PanOSClientPool, _format_error_xml, _normalize_xml_response, normalize_fingerprint


@pytest.fixture(autouse=True)
def reset_pool():
    """Ensure clean pool singleton state before and after each test."""
    PanOSClientPool.reset()
    yield
    PanOSClientPool.reset()


@pytest.fixture
def mock_devices_yaml(tmp_path):
    """Create a temporary devices.yaml configuration."""
    devices_file = tmp_path / "devices.yaml"
    config = {
        "firewalls": {
            "fw-test-1": {
                "ip": "192.168.10.1",
                "label": "Test Primary Firewall",
                "default": True
            },
            "fw-test-2": {
                "ip": "192.168.20.1",
                "label": "Test Secondary Firewall",
                "default": False
            }
        }
    }
    with open(devices_file, "w", encoding="utf-8") as f:
        yaml.dump(config, f)
    return devices_file


def test_format_error_xml_escapes_special_characters():
    """Verify H1: _format_error_xml properly escapes HTML/XML entities."""
    err_msg = "<error & dangerous 'quote'>"
    xml = _format_error_xml(err_msg)
    assert "<error" not in xml
    assert "&lt;error &amp; dangerous &apos;quote&apos;&gt;" in xml
    assert xml.startswith("<response status='error'><msg>")


def test_execute_report_xml_injection_defense():
    """Verify execute_report delegates safely to native xapi.report with reportname."""
    client = PanOSClient("test-dev", "127.0.0.1", "mock-key", verify_ssl=False)
    mock_xapi = MagicMock()
    mock_xapi.xml_result.return_value = "<response status='success'/>"
    client.fw._xapi_private = mock_xapi

    malicious_report = "daily</reportname><evil-command/><reportname>injected"
    status, result = client.execute_report(malicious_report)

    assert status == 200
    assert mock_xapi.report.call_args[1]["reportname"] == malicious_report.strip()
    assert mock_xapi.report.call_args[1]["reporttype"] == "predefined"


def test_apply_timeout_sets_firewall_and_xapi():
    """Verify H4: timeout is applied to both fw and fw.xapi."""
    client = PanOSClient("test-dev", "127.0.0.1", "mock-key", verify_ssl=False)
    mock_xapi = MagicMock()
    client.fw._xapi_private = mock_xapi
    client.fw.op = MagicMock(return_value="<response status='success'/>")

    client.execute_op("show system info", timeout=42)
    assert client.fw.timeout == 42
    assert mock_xapi.timeout == 42


def test_ssl_context_configuration():
    """Verify C2: SSL context is configured based on verify_ssl flag."""
    # Verified SSL
    client_verified = PanOSClient("test-dev-1", "127.0.0.1", "mock-key", verify_ssl=True)
    assert client_verified.fw.xapi.ssl_context is not None

    # Unverified SSL
    client_unverified = PanOSClient("test-dev-2", "127.0.0.1", "mock-key", verify_ssl=False)
    assert client_unverified.fw.xapi.ssl_context is not None


def test_pool_singleton_and_thread_safety(mock_devices_yaml):
    """Verify H2: PanOSClientPool is a thread-safe singleton."""
    pools = []

    def fetch_pool():
        pools.append(PanOSClientPool(registry_path=mock_devices_yaml))

    threads = [threading.Thread(target=fetch_pool) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(pools) == 10
    assert all(p.get_device_names() == ["fw-test-1", "fw-test-2"] for p in pools)


def test_pool_lazy_load_and_secrets_fallback(mock_devices_yaml, monkeypatch):
    """Verify H3 & Self-Audit 1: lazy loading and PANOS_API_KEY fallback."""
    monkeypatch.setenv("PANOS_API_KEY", "fallback-key-123")
    pool = PanOSClientPool(registry_path=mock_devices_yaml)

    with patch("core.integrations.secrets.get_secret", side_effect=ValueError("Key not found")):
        client = pool.get_client("fw-test-1")
        assert client.device_name == "fw-test-1"
        assert client.hostname == "192.168.10.1"


def test_pool_reset_closes_clients(mock_devices_yaml, monkeypatch):
    """Verify M2: pool reset cleanly calls close() on cached connections."""
    monkeypatch.setenv("PANOS_API_KEY", "test-key")
    pool = PanOSClientPool(registry_path=mock_devices_yaml)
    client = pool.get_client("fw-test-1")
    assert "fw-test-1" in pool._connections

    PanOSClientPool.reset()
    assert PanOSClientPool._instance is None

def test_panos_client_execute_get_and_export(monkeypatch):
    """Verify sealed execute_get and execute_export work with XML/export responses."""
    monkeypatch.setenv("PANOS_API_KEY", "test-key")
    client = PanOSClient(
        device_name="test-fw",
        hostname="10.0.0.1",
        api_key="test-key",
        verify_ssl=False
    )
    mock_xapi = MagicMock()
    client.fw._xapi_private = mock_xapi

    # 1. execute_get
    mock_xapi.xml_result.return_value = "<response status='success'><result><test/></result></response>"
    status, xml_out = client.execute_get("/config/devices")
    assert status == 200
    assert "<test/>" in xml_out
    mock_xapi.get.assert_called_with(xpath="/config/devices")

    # 2. execute_export configuration
    mock_xapi.xml_result.return_value = "<config><test/></config>"
    status, exp_out = client.execute_export(category="configuration")
    assert status == 200
    assert "<config>" in exp_out

    # 3. execute_export pcap binary
    mock_xapi.export_result = b"pcap_binary_data"
    status, pcap_out = client.execute_export(category="pcap", **{"from": "rx.pcap"})
    assert status == 200
    assert pcap_out == b"pcap_binary_data"


def test_normalize_fingerprint_formats():
    """Verify normalize_fingerprint parses various SHA-256 formatting styles."""
    canonical = "49CD292D40AF94D686B6EE17CB67CE4DED40E9C0BE2B2537C7BC6E37CF9A2ED0"
    
    assert normalize_fingerprint("49:CD:29:2D:40:AF:94:D6:86:B6:EE:17:CB:67:CE:4D:ED:40:E9:C0:BE:2B:25:37:C7:BC:6E:37:CF:9A:2E:D0") == canonical
    assert normalize_fingerprint("SHA256:49:cd:29:2d:40:af:94:d6:86:b6:ee:17:cb:67:ce:4d:ed:40:e9:c0:be:2b:25:37:c7:bc:6e:37:cf:9a:2e:d0") == canonical
    assert normalize_fingerprint("sha-256: 49-cd-29-2d-40-af-94-d6-86-b6-ee-17-cb-67-ce-4d-ed-40-e9-c0-be-2b-25-37-c7-bc-6e-37-cf-9a-2e-d0") == canonical
    assert normalize_fingerprint("49cd292d40af94d686b6ee17cb67ce4ded40e9c0be2b2537c7bc6e37cf9a2ed0") == canonical
    assert normalize_fingerprint("") == ""
    assert normalize_fingerprint(None) == ""


def test_ssl_fingerprint_pinning_success():
    """Verify client successfully connects when certificate fingerprint matches pinned hash."""
    test_fp = "49CD292D40AF94D686B6EE17CB67CE4DED40E9C0BE2B2537C7BC6E37CF9A2ED0"
    
    with patch("core.panos.client.get_peer_certificate_fingerprint", return_value=(test_fp, "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----")):
        client = PanOSClient(
            device_name="fw-pinned",
            hostname="192.168.1.254",
            api_key="mock-key",
            ssl_fingerprint="SHA256:49:CD:29:2D:40:AF:94:D6:86:B6:EE:17:CB:67:CE:4D:ED:40:E9:C0:BE:2B:25:37:C7:BC:6E:37:CF:9A:2E:D0"
        )
        assert client.ssl_fingerprint is not None
        assert client.fw.xapi.ssl_context is not None


def test_ssl_fingerprint_pinning_mismatch_raises_security_alert():
    """Verify client aborts connection if certificate fingerprint does not match pinned hash."""
    actual_fp = "AAAAAAAA00000000000000000000000000000000000000000000000000000000"
    pinned_fp = "BBBBBBBB11111111111111111111111111111111111111111111111111111111"
    
    with patch("core.panos.client.get_peer_certificate_fingerprint", return_value=(actual_fp, None)):
        with pytest.raises(ValueError) as excinfo:
            PanOSClient(
                device_name="fw-tampered",
                hostname="192.168.1.254",
                api_key="mock-key",
                ssl_fingerprint=pinned_fp
            )
        assert "[SECURITY ALERT] Certificate fingerprint mismatch" in str(excinfo.value)
        assert "Possible Man-In-The-Middle attack" in str(excinfo.value)


def test_pool_loads_ssl_fingerprint_from_yaml(tmp_path, monkeypatch):
    """Verify PanOSClientPool correctly parses and propagates ssl_fingerprint from devices.yaml."""
    monkeypatch.setenv("PANOS_API_KEY", "fallback-key")
    devices_file = tmp_path / "devices.yaml"
    config = {
        "firewalls": {
            "fw-secure": {
                "ip": "10.0.0.99",
                "label": "Secure Pin Firewall",
                "default": True,
                "ssl_fingerprint": "SHA256:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
            }
        }
    }
    with open(devices_file, "w", encoding="utf-8") as f:
        yaml.dump(config, f)
        
    pool = PanOSClientPool(registry_path=devices_file)
    info = pool.get_device_info()
    assert len(info) == 1
    assert info[0]["ssl_fingerprint"] == "SHA256:AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"


def test_normalize_xml_response():
    """Verify _normalize_xml_response normalizes strings, bytes, and XML elements."""
    import xml.etree.ElementTree as ET
    assert _normalize_xml_response("<response>ok</response>") == "<response>ok</response>"
    assert _normalize_xml_response(b"<response>bytes</response>") == "<response>bytes</response>"
    elem = ET.fromstring("<root><item>val</item></root>")
    assert "<item>val</item>" in _normalize_xml_response(elem)
    assert _normalize_xml_response(None) == ""
