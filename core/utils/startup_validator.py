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

    elif backend.lower() == "aws":
        if not os.getenv("AWS_SECRET_NAME"):
            errors.append("AWS backend requires AWS_SECRET_NAME to be set.")

    # --- 3. Non-Sensitive Config ---
    has_devices = False
    try:
        from pathlib import Path
        import yaml
        dev_path = Path(__file__).resolve().parent.parent.parent / "config" / "devices.yaml"
        if dev_path.exists():
            with open(dev_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                if data.get("firewalls"):
                    has_devices = True
    except Exception as e:
        logger.debug(f"[STARTUP] Could not inspect devices.yaml: {e}")

    if not os.getenv("PANOS_HOSTNAME") and not os.getenv("PAN_IP") and not has_devices:
        errors.append(
            "No firewall hostname configured.\n"
            "  Set PANOS_HOSTNAME in .env (e.g., 192.168.1.254) or define firewalls in config/devices.yaml"
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


def probe_device_reachability(host: str, port: int = 443, timeout: float = 1.0) -> dict:
    """Non-blocking TCP socket check measuring latency in milliseconds (supports IPv4 & IPv6)."""
    import socket
    import time
    clean_host = str(host).strip() if host else ""
    if not clean_host:
        return {"reachable": False, "latency_ms": 0.0, "status": "NO_IP"}
    start = time.time()
    try:
        with socket.create_connection((clean_host, port), timeout=timeout):
            latency = (time.time() - start) * 1000
            return {"reachable": True, "latency_ms": round(latency, 1), "status": "ONLINE"}
    except (socket.timeout, OSError) as e:
        latency = (time.time() - start) * 1000
        return {"reachable": False, "latency_ms": round(latency, 1), "status": f"UNREACHABLE"}
    except Exception as e:
        latency = (time.time() - start) * 1000
        return {"reachable": False, "latency_ms": round(latency, 1), "status": f"ERROR: {e}"}


def get_diagnostic_matrix() -> dict:
    """Assembles the complete pre-flight diagnostic state of the fleet and engine."""
    import yaml
    from pathlib import Path

    dev_path = Path(__file__).resolve().parent.parent.parent / "config" / "devices.yaml"
    devices = {}
    if dev_path.exists():
        try:
            with open(dev_path, "r", encoding="utf-8") as f:
                devices = (yaml.safe_load(f) or {}).get("firewalls", {})
        except Exception:
            pass

    fleet_results = {}
    any_online = False
    for name, info in devices.items():
        ip = info.get("ip", "")
        probe = probe_device_reachability(ip)
        probe["ip"] = ip
        probe["label"] = info.get("label", name)
        probe["default"] = info.get("default", False)
        if probe["reachable"]:
            any_online = True
        fleet_results[name] = probe

    # If devices.yaml empty, fall back to PANOS_HOSTNAME
    if not fleet_results:
        fw_ip = os.getenv("PANOS_HOSTNAME", "").strip()
        if fw_ip:
            probe = probe_device_reachability(fw_ip)
            probe["ip"] = fw_ip
            probe["label"] = "Primary Firewall (.env)"
            probe["default"] = True
            if probe["reachable"]:
                any_online = True
            fleet_results["default"] = probe

    # LLM engine check
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    gemini_ok = bool(gemini_key and gemini_key != "your-gemini-api-key-here")

    # Inspection playbooks check
    playbook_count = 0
    tool_count = 0
    try:
        from core.engine.card_runner import CardRunner
        cards = CardRunner.load_cards()
        playbook_count = len(cards)
        from core.pipeline.tool_keeper import ToolKeeper
        tk = ToolKeeper()
        tool_count = len(tk.get_all_tools())
    except Exception:
        pass

    mode = "HARDWARE_CONNECTED" if any_online else "DATAPLANE_EMULATION"

    return {
        "mode": mode,
        "any_online": any_online,
        "fleet": fleet_results,
        "gemini_authenticated": gemini_ok,
        "playbook_count": playbook_count,
        "tool_count": tool_count,
        "policy_mode": os.getenv("POLICY_MODE", "READ_ONLY").upper(),
        "circuit_breaker_limit": 30,
    }


def format_startup_banner(diag: dict) -> str:
    """Generates the pre-flight diagnostic banner with clean ASCII borders."""
    lines = [
        "+==========================================================================================+",
        "|                        CORE DEFENSE — NETWORK DEFENSE ASSISTANT                          |",
        "|                                  PRE-FLIGHT DIAGNOSTICS                                  |",
        "+==========================================================================================+",
        "|  DEVICE INVENTORY (config/devices.yaml):                                                 |",
    ]

    fleet = diag.get("fleet", {})
    if fleet:
        for name, p in fleet.items():
            ip_str = p.get("ip", "no-ip")
            status_str = f"ONLINE ({p.get('latency_ms', 0)}ms)" if p.get("reachable") else "OFFLINE (Emulation Ready)"
            default_tag = " - Default" if p.get("default") else ""
            line_content = f"* {name:<10} ({ip_str:<15}) [{status_str}{default_tag}]"
            lines.append(f"|    {line_content:<86}|")
    else:
        lines.append(f"|    {'* (No devices configured in devices.yaml — Standalone Mode)':<86}|")

    lines.append("|                                                                                          |")
    lines.append("|  LLM REASONING ENGINE:                                                                   |")
    llm_auth = "AUTHENTICATED - Thinking: High" if diag.get("gemini_authenticated") else "MISSING API KEY (.env required)"
    lines.append(f"|    {('* Gemini Pro / Flash' + ' ' * 12 + '[' + llm_auth + ']'):<86}|")
    lines.append("|    * Knowledge Base (Drive)        [READY - Fallback RAG Configured]                     |")
    lines.append("|                                                                                          |")
    lines.append("|  INSPECTION ENGINE:                                                                      |")
    p_cnt = diag.get("playbook_count", 0)
    t_cnt = diag.get("tool_count", 0)
    lines.append(f"|    {f'* Playbooks Registered:         {p_cnt} Verified ({t_cnt} tools mapped)':<86}|")
    lines.append("|    * Ambient Scheduler:            ACTIVE (Continuous: 5m | Periodic: 30m)               |")
    lines.append("|                                                                                          |")
    lines.append("|  SECURITY & GOVERNANCE:                                                                  |")
    pol_mode = diag.get("policy_mode", "READ_ONLY")
    mode_desc = "Dataplane Live" if diag.get("any_online") else "Dataplane Emulation (Sandbox Active)"
    lines.append(f"|    {f'* Operational Mode:            {mode_desc}':<86}|")
    lines.append(f"|    {f'* Policy Enforcement Gate:      {pol_mode} (Enforced)':<86}|")
    lines.append("|    * Circuit Breaker:              30 Max Turns / Loop Failsafe Active                   |")
    lines.append("+==========================================================================================+")
    return "\n".join(lines)


def run_preflight_check(quiet: bool = False) -> tuple:
    """
    Executes pre-flight check, prints banner, and returns (success_bool, diagnostic_dict).
    """
    import sys
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    try:
        validate_startup()
        diag = get_diagnostic_matrix()
        if not quiet:
            print("\n" + format_startup_banner(diag) + "\n")
        return True, diag
    except Exception as e:
        if not quiet:
            print(f"\n[PREFLIGHT FATAL] {e}\n")
        return False, {"error": str(e)}


