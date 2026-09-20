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
_CARD_PROMPTS_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "card_prompts.yaml"

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
    "card_awareness",              # §2.75 — Autonomous Defense Deck context (from card_prompts.yaml)
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

    # Merge card_prompts.yaml sections if available
    if _CARD_PROMPTS_PATH.exists():
        try:
            with open(_CARD_PROMPTS_PATH, "r", encoding="utf-8") as cf:
                card_data = yaml.safe_load(cf)
            if card_data and persona in card_data:
                for key, value in card_data[persona].items():
                    if key not in persona_data:  # Card prompts don't override core prompts
                        persona_data[key] = value
                        logger.info(f"[PROMPT] Merged card prompt section: '{key}'")
        except Exception as e:
            logger.warning(f"[PROMPT] Failed to load card_prompts.yaml: {e} — card awareness disabled.")
    else:
        logger.debug("[PROMPT] card_prompts.yaml not found — card awareness section skipped.")

    assembled = []

    for key in PROMPT_ASSEMBLY_ORDER:
        if key not in persona_data:
            # Card awareness is optional — skip gracefully if missing
            if key == "card_awareness":
                logger.debug("[PROMPT] card_awareness section not available — skipping.")
                continue
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
