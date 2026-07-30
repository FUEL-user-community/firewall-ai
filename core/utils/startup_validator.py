"""
Startup Validator — Boot-Time Safety Checks

Runs before any model or firewall connection is attempted.
Hard-fails with actionable error messages if configuration is invalid.

Usage:
    from core.utils.startup_validator import validate_startup
    validate_startup()  # Call in server.py __main__ before anything else
"""

import os
import logging

logger = logging.getLogger(__name__)


def validate_startup():
    """
    Validates all critical configuration before the agent boots.
    Raises RuntimeError with clear instructions if anything is misconfigured.
    """
    errors = []

    # --- 1. Secrets Backend ---
    backend = os.getenv("SECRETS_BACKEND", "dotenv").strip().lower()
    valid_backends = ("dotenv", "vault", "gcp", "aws", "azure")
    if backend not in valid_backends:
        errors.append(
            f"SECRETS_BACKEND='{backend}' is not valid.\n"
            f"  Valid options: {', '.join(valid_backends)}"
        )

    # --- 2. Backend-Specific Checks ---
    if backend.lower() == "vault":
        for var in ["VAULT_ADDR", "VAULT_ROLE_ID", "VAULT_SECRET_ID"]:
            if not os.getenv(var):
                errors.append(f"Vault backend requires {var} to be set.")

    elif backend.lower() == "gcp":
        if not os.getenv("GCP_PROJECT_ID"):
            errors.append("GCP backend requires GCP_PROJECT_ID to be set.")

    elif backend.lower() == "azure":
        if not os.getenv("AZURE_VAULT_URL"):
            errors.append("Azure backend requires AZURE_VAULT_URL to be set.")

    # --- 3. Non-Sensitive Config ---
    if not os.getenv("PANOS_HOSTNAME") and not os.getenv("PAN_IP"):
        errors.append(
            "No firewall hostname configured.\n"
            "  Set PANOS_HOSTNAME in .env (e.g., 192.168.1.254)"
        )

    # --- 4. Prompt Integrity ---
    if not os.getenv("PROMPTS_YAML_SHA"):
        logger.warning("[STARTUP] PROMPTS_YAML_SHA not set — prompt integrity check disabled.")

    # --- Report ---
    if errors:
        error_block = "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(errors))
        raise RuntimeError(
            "\n\n"
            "═══════════════════════════════════════════════════════════\n"
            "  [FATAL] STARTUP VALIDATION FAILED\n"
            "═══════════════════════════════════════════════════════════\n"
            f"\n{error_block}\n\n"
            "  Fix the above issues and restart the agent.\n"
            "  See .env.example for required configuration.\n"
            "═══════════════════════════════════════════════════════════\n"
        )

    logger.info("[STARTUP] All configuration checks passed.")


def validate_secrets_health():
    """
    Validates that the secrets backend is reachable and can serve secrets.
    Call after validate_startup() to confirm live connectivity.
    """
    try:
        from core.integrations.secrets import get_provider
        provider = get_provider()

        if not provider.health_check():
            raise RuntimeError(
                f"Secrets backend '{provider.backend_name}' is not healthy.\n"
                "  Check connectivity, credentials, and permissions."
            )

        logger.info(f"[STARTUP] Secrets backend healthy: {provider.backend_name}")

    except ImportError:
        raise RuntimeError("Failed to import secrets provider. Check core/integrations/secrets.py.")
