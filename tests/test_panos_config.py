"""
Unit tests for core.panos.config.
Tests XPath allowlisting and injection defense, User-ID XML injection defense,
cmd_xml flag correction, pagination logic without negative omission, and credential redaction.
"""

import pytest
from unittest.mock import MagicMock, patch

from core.panos.config import (
    get_live_config,
    audit_user_id,
    fetch_running_config_xml,
    _validate_xpath,
    _redact_sensitive_xml,
)


@pytest.fixture
def mock_client_pool():
    with patch("core.panos.config._get_pool") as mock_get_pool:
        mock_pool = MagicMock()
        mock_client = MagicMock()
        mock_pool.get_client.return_value = mock_client
        mock_get_pool.return_value = mock_pool
        yield mock_pool, mock_client


def test_validate_xpath_allows_safe_branches():
    """Verify safe configuration prefixes are allowed."""
    valid, res = _validate_xpath("/config/devices/entry/vsys/entry/rulebase/security")
    assert valid is True
    assert res == "/config/devices/entry/vsys/entry/rulebase/security"

    valid, res = _validate_xpath("/config/devices/entry/network/interface")
    assert valid is True

    valid, res = _validate_xpath("/config/devices/entry/vsys/entry/zone")
    assert valid is True


def test_validate_xpath_blocks_sensitive_keywords():
    """Verify C2: sensitive keywords (mgt-config, users, passwords) are blocked."""
    valid, res = _validate_xpath("/config/mgt-config/users")
    assert valid is False
    assert "disallowed sensitive" in res

    valid, res = _validate_xpath("/config/devices/entry/vsys/entry/rulebase/security?password=123")
    assert valid is False

    valid, res = _validate_xpath("/config/shared/certificate")
    assert valid is False


def test_validate_xpath_blocks_non_allowlisted_paths():
    """Verify C2: paths outside safe prefixes are blocked."""
    valid, res = _validate_xpath("/config/some/random/untrusted/path")
    assert valid is False
    assert "safe configuration allowlist" in res


def test_validate_xpath_empty_and_relative():
    """Verify empty, None, or relative XPaths are blocked."""
    valid, res = _validate_xpath("")
    assert valid is False

    valid, res = _validate_xpath(None)
    assert valid is False

    valid, res = _validate_xpath("config/devices")
    assert valid is False
    assert "must be absolute" in res


def test_get_live_config_security_block():
    """Verify get_live_config rejects unauthorized XPaths."""
    res = get_live_config("/config/mgt-config/users")
    assert "ERROR: Security Policy Block" in res


def test_get_live_config_success(mock_client_pool):
    """Verify get_live_config retrieves and sanitizes valid config."""
    _, mock_client = mock_client_pool
    mock_client.fw.xapi.xml_result.return_value = "<response status='success'><result><security/></result></response>"

    res = get_live_config("/config/devices/entry/vsys/entry/rulebase/security")
    assert "security" in res
    assert "ERROR" not in res


def test_audit_user_id_xml_injection_defense(mock_client_pool):
    """Verify C1: XML injection payloads are properly escaped in audit_user_id."""
    _, mock_client = mock_client_pool
    mock_client.execute_op.return_value = (200, "<response status='success'><result/></response>")

    malicious_user = "alice</user></ip-user-mapping></show><evil>"
    audit_user_id(malicious_user)

    called_xml = mock_client.execute_op.call_args[0][0]
    assert "<user>alice&lt;/user&gt;&lt;/ip-user-mapping&gt;&lt;/show&gt;&lt;evil&gt;</user>" in called_xml


def test_audit_user_id_empty_validation():
    """Verify empty or whitespace username is rejected."""
    assert "ERROR: [audit_user_id] Username cannot be empty" in audit_user_id("")
    assert "ERROR: [audit_user_id] Username cannot be empty" in audit_user_id("   ")
    assert "ERROR: [audit_user_id] Username cannot be empty" in audit_user_id(None)


def test_audit_user_id_pagination_math(mock_client_pool):
    """Verify H2: large response pagination avoids negative omission numbers."""
    _, mock_client = mock_client_pool

    # Build XML with 12 entries (previously triggered -3 routes omitted)
    entries_xml = "".join([f"<entry ip='10.0.0.{i}'><user>user_{i}</user></entry>" for i in range(12)])
    big_xml = f"<response status='success'><result><ip-user-mapping>{entries_xml}</ip-user-mapping></result></response>"
    # Pad to > 30000 bytes
    big_xml += " " * 31000

    mock_client.execute_op.return_value = (200, big_xml)

    res = audit_user_id("test_user")
    assert "omitted" not in res  # 12 entries shouldn't display negative omission
    assert "10.0.0.11" in res

    # Build XML with 25 entries (> 15 entries)
    entries_25 = "".join([f"<entry ip='10.0.0.{i}'><user>user_{i}</user></entry>" for i in range(25)])
    big_xml_25 = f"<response status='success'><result><ip-user-mapping>{entries_25}</ip-user-mapping></result></response>" + (" " * 31000)
    mock_client.execute_op.return_value = (200, big_xml_25)

    res_25 = audit_user_id("test_user")
    assert "10 entries omitted" in res_25  # 25 - 15 = 10 entries omitted


def test_redact_sensitive_xml():
    """Verify M1: credentials, hashes, and keys are redacted."""
    raw_xml = (
        "<config>"
        "<phash>$1$xyz$hashvalue</phash>"
        "<private-key>-----BEGIN RSA PRIVATE KEY-----SECRET-----END RSA PRIVATE KEY-----</private-key>"
        "<pre-shared-key>topsecretvpnkey</pre-shared-key>"
        "<bind-password>adpassword</bind-password>"
        "<normal-tag>public-info</normal-tag>"
        "</config>"
    )
    redacted = _redact_sensitive_xml(raw_xml)
    assert "<phash>[REDACTED]</phash>" in redacted
    assert "<private-key>[REDACTED]</private-key>" in redacted
    assert "<pre-shared-key>[REDACTED]</pre-shared-key>" in redacted
    assert "<bind-password>[REDACTED]</bind-password>" in redacted
    assert "hashvalue" not in redacted
    assert "topsecretvpnkey" not in redacted
    assert "<normal-tag>public-info</normal-tag>" in redacted


def test_fetch_running_config_xml_redacts_credentials(mock_client_pool):
    """Verify M1: fetch_running_config_xml returns redacted configuration."""
    _, mock_client = mock_client_pool
    mock_client.fw.xapi.xml_result.return_value = "<config><phash>$1$secret</phash><rule>allow-all</rule></config>"

    res = fetch_running_config_xml()
    assert "<phash>[REDACTED]</phash>" in res
    assert "$1$secret" not in res
    assert "<rule>allow-all</rule>" in res
