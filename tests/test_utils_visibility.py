import os
import unittest.mock as mock
import pytest

from core.utils.xml_to_yaml import ToxicXmlSanitizer
import core.utils.xml_to_yaml as xml_mod
from core.utils.startup_validator import validate_startup


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


def test_xml_to_yaml_preserves_key_and_hash_tags_while_redacting_credentials():
    """Verify F-03: bare <key> and <hash> diagnostic tags remain visible while credential tags and runtime secrets redact."""
    from core.safety.scrubber import clear_registered_secrets, register_runtime_secret

    clear_registered_secrets()
    try:
        register_runtime_secret("LiveRuntimeSecretToken_XYZ987")
        sanitizer = ToxicXmlSanitizer()
        xml_sample = """
        <response status="success">
            <result>
                <counter><key>flow_rcv_err</key><value>42</value></counter>
                <ike><hash>sha256</hash><pre-shared-key>SuperSecretPSK</pre-shared-key></ike>
                <auth><api-key>LUFRPT999888777</api-key><phash>$1$salt$hashval</phash></auth>
                <note>leaked=LiveRuntimeSecretToken_XYZ987</note>
            </result>
        </response>
        """
        yaml_out = sanitizer.convert_string(xml_sample)
        assert "flow_rcv_err" in yaml_out
        assert "sha256" in yaml_out
        assert "SuperSecretPSK" not in yaml_out
        assert "LUFRPT999888777" not in yaml_out
        assert "$1$salt$hashval" not in yaml_out
        assert "LiveRuntimeSecretToken_XYZ987" not in yaml_out
        assert "{{REDACTED_SECRET}}" in yaml_out
    finally:
        clear_registered_secrets()
