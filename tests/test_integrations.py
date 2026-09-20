import os
import json
import unittest.mock as mock
import pytest

from core.integrations.secrets import (
    DotenvSecretsProvider,
    VaultSecretsProvider,
    AWSSecretsProvider,
    get_provider,
    get_secret,
    reset_provider,
)
from core.integrations.drive_knowledge import query_knowledge_base, _extract_pdf_pages
from core.integrations.telemetry import UsageTracker


# ═══════════════════════════════════════════════════════════════
# 1. Secrets Provider Tests (Dotenv, Normalization, Reset, Backends)
# ═══════════════════════════════════════════════════════════════

def test_dotenv_secrets_provider_normalization():
    """Verify DotenvSecretsProvider handles exact keys, uppercase, and hyphen normalization."""
    provider = DotenvSecretsProvider()

    with mock.patch.dict(os.environ, {
        "simple_key": "val1",
        "UPPER_KEY": "val2",
        "PANOS_API_KEY_FW_HQ": "firewall_token_123"
    }):
        # 1. Exact key match
        assert provider.get("simple_key") == "val1"

        # 2. Uppercase match
        assert provider.get("upper_key") == "val2"

        # 3. Hyphen-to-underscore normalization (H1)
        assert provider.get("panos_api_key_fw-hq") == "firewall_token_123"

        # 4. Non-existent key raises ValueError
        with pytest.raises(ValueError) as exc:
            provider.get("non_existent_key_xyz")
        assert "not found in environment" in str(exc.value)

    assert provider.health_check() is True
    assert "Environment Variables" in provider.backend_name


def test_secrets_reset_provider():
    """Verify reset_provider clears the cached singleton."""
    reset_provider()
    with mock.patch.dict(os.environ, {"SECRETS_BACKEND": "dotenv"}):
        p1 = get_provider()
        p2 = get_provider()
        assert p1 is p2

        reset_provider()
        p3 = get_provider()
        assert p3 is not None


def test_vault_provider_mock():
    """Verify VaultSecretsProvider AppRole authentication and caching."""
    mock_hvac_mod = mock.MagicMock()
    mock_client = mock.MagicMock()
    mock_hvac_mod.Client.return_value = mock_client
    mock_client.auth.approle.login.return_value = {
        "auth": {"lease_duration": 3600}
    }
    mock_client.secrets.kv.read_secret_version.return_value = {
        "data": {"data": {"api_key": "vault_secret_val"}}
    }
    mock_client.is_authenticated.return_value = True

    import sys
    with mock.patch.dict(sys.modules, {"hvac": mock_hvac_mod}):
        with mock.patch.dict(os.environ, {
            "VAULT_ADDR": "http://127.0.0.1:8200",
            "VAULT_ROLE_ID": "role-123",
            "VAULT_SECRET_ID": "secret-456",
            "VAULT_SECRET_PATH": "core-defense"
        }):
            provider = VaultSecretsProvider()
            assert provider.health_check() is True
            val = provider.get("api_key")
            assert val == "vault_secret_val"


def test_aws_provider_mock():
    """Verify AWSSecretsProvider retrieves and extracts JSON secret string."""
    mock_boto_mod = mock.MagicMock()
    mock_client = mock.MagicMock()
    mock_boto_mod.client.return_value = mock_client
    mock_client.get_secret_value.return_value = {
        "SecretString": json.dumps({"panos_token": "aws_token_value"})
    }
    mock_client.describe_secret.return_value = {"ARN": "arn:aws:..."}

    import sys
    with mock.patch.dict(sys.modules, {"boto3": mock_boto_mod}):
        with mock.patch.dict(os.environ, {
            "AWS_REGION": "us-west-2",
            "AWS_SECRET_NAME": "core-defense-vault"
        }):
            provider = AWSSecretsProvider()
            assert provider.health_check() is True
            assert provider.get("panos_token") == "aws_token_value"


# ═══════════════════════════════════════════════════════════════
# 2. Drive Knowledge Tests (Action & Bounds Validation)
# ═══════════════════════════════════════════════════════════════

def test_drive_knowledge_action_validation():
    """Verify query_knowledge_base validates the action argument."""
    # 1. Missing action
    res1 = query_knowledge_base(action=None)
    assert "Error: 'action' parameter is required" in res1

    # 2. Unknown action
    with mock.patch("core.integrations.drive_knowledge._init_drive_service", return_value=(mock.MagicMock(), None)):
        with mock.patch.dict(os.environ, {"KNOWLEDGE_BASE_FOLDER_ID": "folder_123"}):
            res2 = query_knowledge_base(action="unsupported_action")
            assert "Unknown action 'unsupported_action'" in res2


def test_drive_knowledge_page_bounds():
    """Verify page bounds checks in _extract_pdf_pages."""
    mock_service = mock.MagicMock()

    # 1. start_page > end_page
    with mock.patch("pypdf.PdfReader") as mock_reader:
        mock_pdf = mock.MagicMock()
        mock_pdf.pages = [mock.MagicMock() for _ in range(10)]
        mock_reader.return_value = mock_pdf

        with mock.patch("core.integrations.drive_knowledge.MediaIoBaseDownload") as mock_dl:
            mock_inst = mock.MagicMock()
            mock_inst.next_chunk.return_value = (None, True)
            mock_dl.return_value = mock_inst

            # Inverted bounds
            res = _extract_pdf_pages(mock_service, "file_id", 10, 5)
            assert "start_page (10) cannot be greater than end_page (5)" in res

            # Non-positive page
            res2 = _extract_pdf_pages(mock_service, "file_id", 0, 5)
            assert "start_page (0) must be >= 1" in res2


# ═══════════════════════════════════════════════════════════════
# 3. Telemetry Module Tests (UsageTracker)
# ═══════════════════════════════════════════════════════════════

def test_usage_tracker_dict_and_callback():
    """Verify UsageTracker calculates costs and invokes callbacks with dict and object responses."""
    callback_calls = []

    def mock_callback(model, inp, out):
        callback_calls.append((model, inp, out))

    tracker = UsageTracker(
        model_name="gemini-3.1-pro-preview",
        price_input="1.25",
        price_output="10.00"
    )
    tracker.set_callback(mock_callback)

    # 1. Object attribute response
    mock_resp = mock.MagicMock()
    mock_resp.usage_metadata.prompt_token_count = 1000
    mock_resp.usage_metadata.candidates_token_count = 500
    tracker.track(mock_resp, trace_id="trace-1", tool_summary="test_tool")

    assert len(callback_calls) == 1
    assert callback_calls[0] == ("gemini-3.1-pro-preview", 1000, 500)

    # 2. Dictionary response
    dict_resp = {
        "usage_metadata": {
            "prompt_token_count": 2000,
            "candidates_token_count": 800
        }
    }
    tracker.track(dict_resp, trace_id="trace-2")
    assert len(callback_calls) == 2
    assert callback_calls[1] == ("gemini-3.1-pro-preview", 2000, 800)
