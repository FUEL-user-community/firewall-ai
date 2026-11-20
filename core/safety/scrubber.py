"""
PII Scrubbing Layer
Masks hardware serial numbers while preserving real IP addresses for accurate diagnostics.
"""
import base64
import os
import re
import hmac
import hashlib
import logging
import secrets
import threading
import urllib.parse

logger = logging.getLogger(__name__)

__all__ = [
    "scrub",
    "register_runtime_secret",
    "scrub_registered_secrets",
    "clear_registered_secrets",
]

SCRUB_PII = os.getenv("SCRUB_PII", "true").lower() == "true"

# Token width: 12 hex = 48 bits. Birthday bound n50 = sqrt(2 * 2^48 * ln2) ~ 19.8M distinct
# values (was 6 hex = 24 bits -> ~4.8k, i.e. ~3% collision odds at just 1k serials).
_TOKEN_HEX = 12

# Keyed HMAC so a masked token can't be checked against a guessed serial offline.
# Set SCRUBBER_SEED (or the shared SANITIZER_SEED) for tokens stable across restarts;
# otherwise share a persistent .state/shared seed or process-wide ephemeral seed with ToxicXmlSanitizer.
def _load_shared_hmac_key() -> bytes:
    explicit = os.getenv("SCRUBBER_SEED") or os.getenv("SANITIZER_SEED")
    if explicit:
        return explicit.encode("utf-8")
    try:
        from pathlib import Path
        seed_file = Path(__file__).resolve().parent.parent.parent / ".state" / "shared" / ".hmac_seed"
        if seed_file.is_file():
            raw = seed_file.read_text(encoding="utf-8").strip()
            if len(raw) >= 32:
                return bytes.fromhex(raw)
    except Exception:
        pass
    shared_hex = os.environ.setdefault("_NEO_EPHEMERAL_HMAC_SEED", secrets.token_hex(32))
    return bytes.fromhex(shared_hex)


_SCRUB_KEY = _load_shared_hmac_key()


def _deterministic_token(value: str, prefix: str = "ENTITY") -> str:
    short_hash = hmac.new(_SCRUB_KEY, value.encode(), hashlib.sha256).hexdigest()[:_TOKEN_HEX]
    return f"[{prefix}_{short_hash}]"


_SECRET_LOCK = threading.Lock()
_REGISTERED_SECRET_VARIANTS: list[str] = []


def register_runtime_secret(secret_value: str) -> None:
    """
    Register an active runtime credential (raw + base64 + hex + URL-encoded + reversed)
    so it can NEVER leave in any tool output, receipt, or Drive artifact—even if
    encoded by mutated code. Ignores strings shorter than 8 chars to avoid prose collisions.
    """
    if not secret_value or not isinstance(secret_value, str):
        return
    clean = secret_value.strip()
    if len(clean) < 8:
        return

    raw_bytes = clean.encode("utf-8", errors="ignore")
    b64_full = base64.b64encode(raw_bytes).decode("ascii")
    b64_nopad = b64_full.rstrip("=")
    hex_low = raw_bytes.hex()
    url_enc = urllib.parse.quote(clean, safe="")
    rev = clean[::-1]

    candidates = [clean, rev, b64_full, b64_nopad, hex_low, hex_low.upper(), url_enc]
    for line in clean.splitlines():
        ln = line.strip()
        if len(ln) >= 16 and not ln.startswith("-----"):
            candidates.append(ln)
            candidates.append(ln[::-1])

    with _SECRET_LOCK:
        existing = set(_REGISTERED_SECRET_VARIANTS)
        for cand in candidates:
            if len(cand) >= 8 and cand not in existing:
                _REGISTERED_SECRET_VARIANTS.append(cand)
                existing.add(cand)
        _REGISTERED_SECRET_VARIANTS.sort(key=len, reverse=True)


def clear_registered_secrets() -> None:
    """Clear registered runtime secret variants (used in unit test teardown)."""
    with _SECRET_LOCK:
        _REGISTERED_SECRET_VARIANTS.clear()


def scrub_registered_secrets(text: str) -> str:
    """Exact substring redaction of registered runtime credentials (safe on code/diffs/SHAs)."""
    if not text:
        return ""
    out = text if isinstance(text, str) else str(text)
    with _SECRET_LOCK:
        variants = list(_REGISTERED_SECRET_VARIANTS)
    for variant in variants:
        if variant in out:
            out = out.replace(variant, "[REDACTED_RUNTIME_SECRET]")
    out = re.sub(r"\bAIza[0-9A-Za-z_\-]{35}\b", "[REDACTED_GEMINI_KEY]", out)
    out = re.sub(r"\bLUFRPT[a-zA-Z0-9+/=]{16,}", "[REDACTED_API_KEY]", out)
    return out


def scrub(text: str) -> str:
    """
    Masks registered runtime credentials, hardware serial numbers, private keys,
    API keys, password hashes, and pre-shared keys while preserving real IP addresses.
    """
    if not isinstance(text, str):
        text = str(text)

    # Always strip registered runtime secrets even if SCRUB_PII is toggled off
    text = scrub_registered_secrets(text)

    if not SCRUB_PII:
        return text

    # 1. Private cryptographic keys
    text = re.sub(
        r'-----BEGIN [A-Z0-9_\- ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9_\- ]*PRIVATE KEY-----',
        '[REDACTED_PRIVATE_KEY]',
        text,
        flags=re.IGNORECASE
    )

    # 2. Sensitive XML configuration elements (phash, password, pre-shared-key, secret, passphrase, bind-password)
    text = re.sub(
        r'<(?P<tag>phash|password|pre-shared-key|secret|passphrase|private-key|bind-password)>(?:(?!<\/(?P=tag)>)[\s\S])*?<\/(?P=tag)>',
        r'<\g<tag>>[REDACTED_\g<tag>]</\g<tag>>',
        text,
        flags=re.IGNORECASE
    )

    # 3. Sensitive YAML / CLI configuration fields (require explicit ':' or '=' so natural prose is preserved)
    text = re.sub(
        r'\b(?P<field>phash|password|pre-shared-key|secret|passphrase|bind-password)\s*[:=]\s*[\'\"`]?([^\s\'\"`\n\[]+)[\'\"`]?',
        r'\g<field>: [REDACTED]',
        text,
        flags=re.IGNORECASE
    )

    # 4. PAN-OS API Keys (LUFRPT...)
    text = re.sub(
        r'\bLUFRPT[a-zA-Z0-9+/=]{16,}',
        '[REDACTED_API_KEY]',
        text
    )

    # 5. Bearer tokens and generic API key assignments
    text = re.sub(
        r'\bBearer\s+[a-zA-Z0-9_\-\.]{20,}\b',
        'Bearer [REDACTED_TOKEN]',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r'\b(api[_-]?key|secret[_-]?key)\s*[:=]\s*[\'"]?[a-zA-Z0-9_\-]{16,}[\'"]?',
        r'\1=[REDACTED_KEY]',
        text,
        flags=re.IGNORECASE
    )

    # 6. Serial numbers in XML (<serial>123456789012</serial>)
    text = re.sub(
        r'<serial>(?![{\[])([A-Z0-9]{10,})<\/serial>',
        lambda m: f"<serial>{_deterministic_token(m.group(1), 'SN')}</serial>",
        text,
        flags=re.IGNORECASE
    )

    # 7. Serial numbers in YAML / CLI / text (handles optional quotes and colons; skips already-masked {{SERIAL_*}})
    text = re.sub(
        r'(?<!\{\{)(?:serial(?:[ -]?number)?[:\s]+[\'\"`]?)(?![{\[])((?=[A-Z0-9]*\d)[A-Z0-9]{10,})[\'\"`]?',
        lambda m: f"serial: {_deterministic_token(m.group(1), 'SN')}",
        text,
        flags=re.IGNORECASE
    )

    return text

