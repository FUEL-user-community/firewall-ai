"""
PromptAssembler — System Prompt Loading, Integrity Verification, and Assembly.

Single responsibility: load config/prompts.yaml, verify its SHA-256 integrity,
and assemble the ordered sections into a single system prompt string.

No SDK dependencies. No runtime state. Pure functions + constants.
"""

import os
import hashlib
import logging
import threading
import yaml
from pathlib import Path

logger = logging.getLogger(__name__)

# Module-level constant: resolved once, visible in tracebacks.
_PROMPTS_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "prompts.yaml"
# _CARD_PROMPTS_PATH retired

# SHA-256 integrity pin. Set via .env to guard against prompt tampering.
_PROMPTS_EXPECTED_SHA = os.getenv("PROMPTS_YAML_SHA", "")


def verify_prompt_integrity(path: Path = None) -> None:
    """
    Fail-fast if prompts.yaml has been modified without updating the SHA pin.
    If PROMPTS_YAML_SHA is not set in .env, logs a warning and skips.
    """
    path = path or _PROMPTS_PATH
    if not _PROMPTS_EXPECTED_SHA:
        logger.warning("[INTEGRITY] PROMPTS_YAML_SHA not set in .env — skipping checksum verification.")
        return
    actual_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_sha != _PROMPTS_EXPECTED_SHA:
        raise RuntimeError(
            f"CRITICAL: prompts.yaml checksum mismatch. "
            f"Expected: {_PROMPTS_EXPECTED_SHA[:16]}... Got: {actual_sha[:16]}... "
            "File may have been tampered with. Update PROMPTS_YAML_SHA in .env after intentional changes."
        )


# Controls the order sections are injected into the LLM context window.
# Immune to YAML key reordering. Acts as a schema contract — missing sections
# cause a hard KeyError at startup rather than a silent lobotomized prompt.
PROMPT_ASSEMBLY_ORDER = [
    "identity",
    "the_deterministic_loop",
    "strict_grounding",
    "tool_execution",
    "fleet_awareness",             # Multi-FW: target_device grounding
    "cross_correlation",       # §3 — Shared key scanning across tool outputs
    "adversarial_reasoning",   # §4 — Attack path analysis from config data
    "drive_workflow",
    "output_structure",
]


def load_system_prompt(persona: str = "neo") -> str:
    """
    Loads and assembles the system prompt from config/prompts.yaml.

    Each section must be a YAML literal block scalar (|) so yaml.safe_load
    returns a plain str — verbatim, ready to inject. No serializer needed.

    Fails fast on:
      - Missing YAML file
      - Malformed YAML
      - Unknown persona key
      - Missing required section
    """
    if not _PROMPTS_PATH.exists():
        raise FileNotFoundError(
            f"CRITICAL: System prompt config missing at {_PROMPTS_PATH}. "
            "CoreBrain cannot initialize without a persona definition."
        )

    # Verify file integrity before parsing
    verify_prompt_integrity(_PROMPTS_PATH)

    with open(_PROMPTS_PATH, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"CRITICAL: YAML parse error in {_PROMPTS_PATH}: {e}")

    if persona not in data:
        raise KeyError(
            f"CRITICAL: Persona '{persona}' not found in {_PROMPTS_PATH}. "
            f"Available: {list(data.keys())}"
        )

    persona_data = data[persona]

    
    assembled = []

    for key in PROMPT_ASSEMBLY_ORDER:
        if key not in persona_data:

            raise KeyError(
                f"CRITICAL: Required section '{key}' missing from persona '{persona}'. "
                f"Found: {list(persona_data.keys())}"
            )
        # Literal block scalars parse as str — .strip() removes trailing newline only.
        assembled.append(persona_data[key].strip())

    return "\n\n".join(assembled)

def load_range_prompt(persona: str = "neo") -> str:
    """
    Loads the Range Simulation specific prompt extensions dynamically.
    """
    range_path = _PROMPTS_PATH.parent / "range_prompts.yaml"
    if not range_path.exists():
        raise FileNotFoundError(f"CRITICAL: {range_path} is missing.")
        
    with open(range_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        
    if persona not in data or "range_simulation" not in data[persona]:
        raise KeyError(f"CRITICAL: 'range_simulation' not found for persona '{persona}' in {range_path}.")
        
    return data[persona]["range_simulation"].strip()

# Lazy-loaded system prompt — avoids crash at import time if prompts.yaml is missing.
_SYSTEM_PROMPT_CACHE = None
_prompt_lock = threading.Lock()

def get_system_prompt() -> str:
    """Returns the assembled system prompt, loading on first call in a thread-safe manner."""
    global _SYSTEM_PROMPT_CACHE
    if _SYSTEM_PROMPT_CACHE is None:
        with _prompt_lock:
            if _SYSTEM_PROMPT_CACHE is None:
                _SYSTEM_PROMPT_CACHE = load_system_prompt()
    return _SYSTEM_PROMPT_CACHE


def reset_system_prompt_cache() -> None:
    """Invalidates the system prompt cache for testing or runtime configuration reload."""
    global _SYSTEM_PROMPT_CACHE
    with _prompt_lock:
        _SYSTEM_PROMPT_CACHE = None


class _LazyPromptProxy:
    """Proxy that defers prompt loading until first access with transparent string delegation."""

    def __str__(self):
        return get_system_prompt()

    def __repr__(self):
        return repr(get_system_prompt())

    def __add__(self, other):
        return get_system_prompt() + str(other)

    def __radd__(self, other):
        return str(other) + get_system_prompt()

    def __len__(self):
        return len(get_system_prompt())

    def __contains__(self, item):
        return item in get_system_prompt()

    def __eq__(self, other):
        return get_system_prompt() == str(other)

    def __hash__(self):
        return hash(get_system_prompt())

    def __bool__(self):
        return bool(get_system_prompt())

    def __getitem__(self, item):
        return get_system_prompt()[item]

    def __getattr__(self, name):
        """Delegates all standard string methods (.startswith, .split, .replace, .strip, etc.)."""
        return getattr(get_system_prompt(), name)


# Backward compatible — existing code uses `SYSTEM_PROMPT` as a string constant.
SYSTEM_PROMPT = _LazyPromptProxy()


# =============================================================================
# Prompt Directives & Safety Constants
# =============================================================================

CIRCUIT_BREAKER_REFLECTION_PROMPT = (
    "[SYSTEM: LOOP DETECTED. Your investigation is being terminated for safety. "
    "Before shutdown, produce a PARTIAL REPORT: "
    "1) WHAT_TRIED: List every tool you called and key findings. "
    "2) WHY_STALLED: One sentence on why you were repeating actions. "
    "3) RECOMMENDATION: What the human should investigate manually.]"
)

BUDGET_EXCEEDED_PROMPT = (
    "[SYSTEM: Budget limit reached. Produce a PARTIAL REPORT from the data "
    "you have gathered so far. Include all findings and recommendations.]"
)


# =============================================================================
# Dynamic Fleet & Reality Prompt Assembly
# =============================================================================

_DEVICES_CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "devices.yaml"
_devices_cache: dict = {}
_devices_last_mtime: float = 0.0
_devices_lock = threading.Lock()


def load_devices_config() -> dict:
    """Loads devices.yaml with mtime caching to eliminate disk I/O on hot query paths."""
    global _devices_cache, _devices_last_mtime
    if not _DEVICES_CONFIG_PATH.exists():
        return {}
    try:
        current_mtime = _DEVICES_CONFIG_PATH.stat().st_mtime
        if current_mtime != _devices_last_mtime:
            with _devices_lock:
                if current_mtime != _devices_last_mtime:
                    with open(_DEVICES_CONFIG_PATH, "r", encoding="utf-8") as f:
                        _devices_cache = yaml.safe_load(f) or {}
                    _devices_last_mtime = current_mtime
        return _devices_cache
    except Exception as e:
        logger.warning(f"[FLEET] Error reading devices config: {e}")
        return _devices_cache


def build_fleet_context() -> str:
    """
    Produces a structured fleet inventory string for injection into the LLM context.
    Uses mtime caching so changes to devices.yaml are picked up without restart.
    """
    try:
        data = load_devices_config()
        if not data and not _DEVICES_CONFIG_PATH.exists():
            return "FLEET_INVENTORY: Single device mode (no devices.yaml found)."

        firewalls = data.get("firewalls", {}) if data else {}
        if not firewalls:
            return "FLEET_INVENTORY: No firewalls configured."

        lines = ["FLEET_INVENTORY: Managed devices:"]
        for name, info in firewalls.items():
            label = info.get("label", "")
            is_default = info.get("default", False)
            marker = " <- DEFAULT" if is_default else ""
            lines.append(f"  - {name}: {label}{marker}")

        lines.append('Use target_device="<alias>" in tool calls to target a specific device.')
        return "\n".join(lines)
    except Exception as e:
        logger.warning(f"[FLEET] Failed to build fleet context: {e}")
        return "FLEET_INVENTORY: Unable to load (using default device)."


def resolve_target_device(user_query: str, explicit_device: str = None) -> str:
    """Resolves target device alias from explicit parameter or query text."""
    if explicit_device:
        return explicit_device
    try:
        import re
        fw_dict = load_devices_config().get("firewalls", {})
        for fw_alias in fw_dict:
            pattern = r'(?<![a-zA-Z0-9_-])' + re.escape(fw_alias.lower()) + r'(?![a-zA-Z0-9_-])'
            if re.search(pattern, user_query.lower()):
                return fw_alias
    except Exception as ex:
        logger.debug(f"[PROMPT] Device resolution failed: {ex}")
    return None


def build_reality_prompt(
    user_query: str,
    manifest_str: str,
    fleet_context: str = "",
    license_context: str = "",
    thinking_level: str = "high",
    target_mode: str = "default",
) -> str:
    """Builds grounded reality anchor string including fleet inventory and diagnostic parameters."""
    fleet = fleet_context or build_fleet_context()

    if target_mode == "advisory":
        reality_check = (
            "REALITY_CHECK: You are operating in ARCHITECTURAL ADVISORY MODE.\n"
            f"You only have access to official documentation: [{manifest_str}].\n"
            "Live firewall execution tools are disabled for safety.\n"
            "Deliver strategic guidance, best practices, and candidate configurations.\n"
            "Ground recommendations in official PAN-OS manuals, hardening blueprints, and CVE data.\n"
            "Prefix any candidate configuration CLI blocks with:\n"
            "# [ADVISORY SPECIFICATION - VALIDATE IN LAB BEFORE PRODUCTION COMMIT]\n\n"
            f"{fleet}"
        )
    else:
        reality_check = (
            f"REALITY_CHECK: You only have these tools: [{manifest_str}].\n"
            "Verify tool names against this list before every call.\n\n"
            f"{fleet}"
        )

    if license_context:
        reality_check += f"\n\n{license_context}"

    reality_check += f"\n\n[SYSTEM COGNITIVE BOUNDS: Execute with {thinking_level.upper()} reasoning depth.]"
    return reality_check


def get_ceiling_directive(target_mode: str, turn: int, outward_receipts_count: int, range_probe_limit: int = 7) -> str:
    """
    Returns forced terminal synthesis directive if turn or evidence ceilings are reached.
    Guarantees graceful report emission before reaching hard agent loop boundaries.
    """
    if target_mode == "range" and turn >= range_probe_limit - 1:
        return (
            f"\n\n[SYSTEM: SIMULATION PROBE BUDGET REACHED (Turn {turn+1} of {range_probe_limit})]\n"
            "You have comprehensive empirical telemetry across candidate ingress, lateral, and policy boundaries.\n"
            "Do NOT execute any further tool calls.\n"
            "Proceed directly to Step 3 (TOPOLOGY SYNTHESIS) and emit your terminal pure JSON payload NOW."
        )
    elif target_mode != "range" and outward_receipts_count >= 14:
        return (
            f"\n\n[SYSTEM: TRIAD EVIDENCE CEILING REACHED ({outward_receipts_count} outward tools executed)]\n"
            "You have sufficient empirical telemetry across candidate ingress, lateral, and policy boundaries.\n"
            "Do NOT execute any further tool calls.\n"
            "Proceed directly to SYNTHESIS and emit your final executive diagnostic report NOW."
        )
    return None

