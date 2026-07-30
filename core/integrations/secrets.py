"""
Secrets Provider Abstraction Layer

Pluggable backend for credential management. Raw environment variables for
API keys are NOT supported — every deployment must configure a secrets backend.

Supported backends (set via SECRETS_BACKEND env var):
    dotenv  — Environment variables via .env file (DEFAULT, simplest)
    vault   — HashiCorp Vault via AppRole
    gcp     — GCP Secret Manager
    aws     — AWS Secrets Manager
    azure   — Azure Key Vault

Usage:
    from core.integrations.secrets import get_secret
    api_key = get_secret("gemini_api_key")
    panos_key = get_secret("panos_api_key_fw_hq")
"""

import os
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# Module-level singleton
_provider = None


# =============================================================================
# Base Interface
# =============================================================================

class SecretsProvider(ABC):
    """All secrets backends implement this interface."""

    @abstractmethod
    def get(self, key: str) -> str:
        """Retrieve a secret value by key. Raises ValueError if not found."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Returns True if the backend is reachable and authenticated."""
        ...

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Human-readable name of this backend."""
        ...


# =============================================================================
# Vault Backend (Default, Required)
# =============================================================================

class VaultSecretsProvider(SecretsProvider):
    """
    HashiCorp Vault via AppRole authentication.
    
    Required env vars:
        VAULT_ADDR        — Vault server URL (e.g., http://localhost:8200)
        VAULT_ROLE_ID     — AppRole role ID
        VAULT_SECRET_ID   — AppRole secret ID (rotatable)
        VAULT_SECRET_PATH — KV path (default: secret/data/core-defense)
    """

    # Re-authenticate when token has this many seconds remaining
    _TOKEN_REFRESH_BUFFER = 300  # 5 minutes

    def __init__(self):
        import time as _time
        self._time = _time

        try:
            import hvac
        except ImportError:
            raise ImportError(
                "HashiCorp Vault backend requires 'hvac' package.\n"
                "Install: pip install hvac>=2.0.0"
            )

        self._addr = os.getenv("VAULT_ADDR")
        self._role_id = os.getenv("VAULT_ROLE_ID")
        self._secret_id = os.getenv("VAULT_SECRET_ID")
        self._path = os.getenv("VAULT_SECRET_PATH", "core-defense")

        if not all([self._addr, self._role_id, self._secret_id]):
            raise ValueError(
                "Vault backend requires VAULT_ADDR, VAULT_ROLE_ID, and VAULT_SECRET_ID.\n"
                "See: https://developer.hashicorp.com/vault/docs/auth/approle"
            )

        self._client = hvac.Client(url=self._addr)
        self._token_created_at = 0.0
        self._token_ttl = 0
        self._authenticate()
        self._cache = {}

    def _authenticate(self):
        """Authenticate via AppRole and obtain a short-lived token."""
        try:
            response = self._client.auth.approle.login(
                role_id=self._role_id,
                secret_id=self._secret_id,
            )
            # Track token TTL for automatic refresh
            auth_data = response.get("auth", {})
            self._token_ttl = auth_data.get("lease_duration", 3600)
            self._token_created_at = self._time.time()
            logger.info(
                f"[SECRETS] Vault authenticated at {self._addr} "
                f"(token TTL: {self._token_ttl}s)"
            )
        except Exception as e:
            raise ConnectionError(f"Vault authentication failed: {e}")

    def _is_token_expiring(self) -> bool:
        """Check if the current token is within the refresh buffer of expiry."""
        if self._token_ttl <= 0:
            return False  # No TTL info — skip refresh
        elapsed = self._time.time() - self._token_created_at
        remaining = self._token_ttl - elapsed
        return remaining < self._TOKEN_REFRESH_BUFFER

    def _ensure_authenticated(self):
        """Re-authenticate if the token is near expiry."""
        if self._is_token_expiring():
            logger.info("[SECRETS] Vault token near expiry — refreshing via AppRole")
            self._cache = {}  # Clear cache — credentials may have rotated
            self._authenticate()

    def get(self, key: str) -> str:
        self._ensure_authenticated()

        if key in self._cache:
            return self._cache[key]

        try:
            secret = self._client.secrets.kv.read_secret_version(path=self._path)
            data = secret["data"]["data"]
            if key not in data:
                raise ValueError(f"Secret '{key}' not found at path '{self._path}'")
            self._cache = data  # Cache all secrets from this path
            return data[key]
        except Exception as e:
            raise ValueError(f"Failed to read secret '{key}' from Vault: {e}")

    def health_check(self) -> bool:
        try:
            return self._client.is_authenticated()
        except Exception:
            return False

    @property
    def backend_name(self) -> str:
        return f"HashiCorp Vault ({self._addr})"


# =============================================================================
# GCP Secret Manager Backend
# =============================================================================

class GCPSecretsProvider(SecretsProvider):
    """
    GCP Secret Manager.
    
    Required env vars:
        GCP_PROJECT_ID — Google Cloud project ID
        GOOGLE_APPLICATION_CREDENTIALS — Path to service account JSON (standard GCP auth)
    """

    def __init__(self):
        try:
            from google.cloud import secretmanager
        except ImportError:
            raise ImportError(
                "GCP backend requires 'google-cloud-secret-manager' package.\n"
                "Install: pip install google-cloud-secret-manager>=2.0.0"
            )

        self._project_id = os.getenv("GCP_PROJECT_ID")
        if not self._project_id:
            raise ValueError("GCP backend requires GCP_PROJECT_ID env var.")

        self._client = secretmanager.SecretManagerServiceClient()
        logger.info(f"[SECRETS] GCP Secret Manager initialized for project: {self._project_id}")

    def get(self, key: str) -> str:
        from google.cloud import secretmanager
        name = f"projects/{self._project_id}/secrets/{key}/versions/latest"
        try:
            response = self._client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception as e:
            raise ValueError(f"Failed to read secret '{key}' from GCP: {e}")

    def health_check(self) -> bool:
        try:
            # List secrets as a connectivity check
            parent = f"projects/{self._project_id}"
            list(self._client.list_secrets(request={"parent": parent, "page_size": 1}))
            return True
        except Exception:
            return False

    @property
    def backend_name(self) -> str:
        return f"GCP Secret Manager ({self._project_id})"


# =============================================================================
# AWS Secrets Manager Backend
# =============================================================================

class AWSSecretsProvider(SecretsProvider):
    """
    AWS Secrets Manager.
    
    Required env vars:
        AWS_REGION — AWS region (default: us-east-1)
        AWS_SECRET_NAME — Secret name (default: core-defense)
        Standard AWS auth (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY or IAM role)
    """

    def __init__(self):
        try:
            import boto3
        except ImportError:
            raise ImportError(
                "AWS backend requires 'boto3' package.\n"
                "Install: pip install boto3>=1.26.0"
            )

        self._region = os.getenv("AWS_REGION", "us-east-1")
        self._secret_name = os.getenv("AWS_SECRET_NAME", "core-defense")
        self._client = boto3.client("secretsmanager", region_name=self._region)
        self._cache = {}
        logger.info(f"[SECRETS] AWS Secrets Manager initialized: region={self._region}")

    def get(self, key: str) -> str:
        if key in self._cache:
            return self._cache[key]

        import json
        try:
            response = self._client.get_secret_value(SecretId=self._secret_name)
            data = json.loads(response["SecretString"])
            if key not in data:
                raise ValueError(f"Secret '{key}' not found in AWS secret '{self._secret_name}'")
            self._cache = data
            return data[key]
        except Exception as e:
            raise ValueError(f"Failed to read secret '{key}' from AWS: {e}")

    def health_check(self) -> bool:
        try:
            self._client.describe_secret(SecretId=self._secret_name)
            return True
        except Exception:
            return False

    @property
    def backend_name(self) -> str:
        return f"AWS Secrets Manager ({self._region}/{self._secret_name})"


# =============================================================================
# Azure Key Vault Backend
# =============================================================================

class AzureSecretsProvider(SecretsProvider):
    """
    Azure Key Vault.
    
    Required env vars:
        AZURE_VAULT_URL — Key Vault URL (e.g., https://my-vault.vault.azure.net/)
        Standard Azure auth (AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID or managed identity)
    """

    def __init__(self):
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential
        except ImportError:
            raise ImportError(
                "Azure backend requires 'azure-keyvault-secrets' and 'azure-identity' packages.\n"
                "Install: pip install azure-keyvault-secrets>=4.0.0 azure-identity>=1.12.0"
            )

        self._vault_url = os.getenv("AZURE_VAULT_URL")
        if not self._vault_url:
            raise ValueError("Azure backend requires AZURE_VAULT_URL env var.")

        credential = DefaultAzureCredential()
        self._client = SecretClient(vault_url=self._vault_url, credential=credential)
        logger.info(f"[SECRETS] Azure Key Vault initialized: {self._vault_url}")

    def get(self, key: str) -> str:
        try:
            # Azure Key Vault uses hyphens, not underscores in secret names
            azure_key = key.replace("_", "-")
            secret = self._client.get_secret(azure_key)
            return secret.value
        except Exception as e:
            raise ValueError(f"Failed to read secret '{key}' from Azure: {e}")

    def health_check(self) -> bool:
        try:
            list(self._client.list_properties_of_secrets(max_page_size=1))
            return True
        except Exception:
            return False

    @property
    def backend_name(self) -> str:
        return f"Azure Key Vault ({self._vault_url})"


# =============================================================================
# Dotenv Backend (Default — Simplest)
# =============================================================================

class DotenvSecretsProvider(SecretsProvider):
    """
    Simple environment variable backend. Reads secrets directly from
    environment variables (loaded via python-dotenv from .env file).

    This is the default backend — no external infrastructure required.
    Just put your API keys in .env and go.

    Expected env var names match secret keys directly:
        gemini_api_key      → GEMINI_API_KEY
        panos_api_key_fw_hq → PANOS_API_KEY_FW_HQ
    """

    def get(self, key: str) -> str:
        # Try exact key first, then uppercase version
        value = os.getenv(key) or os.getenv(key.upper())
        if not value:
            raise ValueError(
                f"Secret '{key}' not found in environment variables. "
                f"Add {key.upper()}=your-value to your .env file."
            )
        return value

    def health_check(self) -> bool:
        # Dotenv is always "healthy" — it's just env vars
        return True

    @property
    def backend_name(self) -> str:
        return "Environment Variables (.env)"


# =============================================================================
# Factory + Public API
# =============================================================================

_BACKENDS = {
    "dotenv": DotenvSecretsProvider,
    "vault": VaultSecretsProvider,
    "gcp": GCPSecretsProvider,
    "aws": AWSSecretsProvider,
    "azure": AzureSecretsProvider,
}


def _init_provider() -> SecretsProvider:
    """Initialize the secrets provider from SECRETS_BACKEND env var."""
    backend = os.getenv("SECRETS_BACKEND", "dotenv").lower().strip()

    if backend not in _BACKENDS:
        raise RuntimeError(
            f"Unknown SECRETS_BACKEND: '{backend}'. "
            f"Valid options: {', '.join(_BACKENDS.keys())}"
        )

    provider = _BACKENDS[backend]()
    logger.info(f"[SECRETS] Provider initialized: {provider.backend_name}")
    return provider


import threading
_provider_lock = threading.Lock()

def get_provider() -> SecretsProvider:
    """Returns the singleton secrets provider instance."""
    global _provider
    with _provider_lock:
        if _provider is None:
            _provider = _init_provider()
        return _provider


def get_secret(key: str) -> str:
    """
    Retrieve a secret by key from the configured backend.
    
    This is the primary public API. The rest of the codebase calls this function.
    It never needs to know which backend is active.
    
    Args:
        key: Secret identifier (e.g., 'gemini_api_key', 'panos_api_key_fw_hq')
    
    Returns:
        The secret value as a string.
    
    Raises:
        RuntimeError: If no backend is configured.
        ValueError: If the secret is not found.
    """
    return get_provider().get(key)
