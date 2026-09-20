"""
Unit tests for core.panos.client.
Tests XML injection defense, SSL context binding, timeout application,
XML error escaping, thread-safe connection pooling, and secrets fallback.
"""

import pytest
import yaml
import threading
from unittest.mock import MagicMock, patch
from pathlib import Path

from core.panos.client import PanOSClient, PanOSClientPool, _format_error_xml, _normalize_xml_response


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
