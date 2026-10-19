"""
PII Scrubbing Layer
Masks hardware serial numbers while preserving real IP addresses for accurate diagnostics.
"""
import os
import re
import hashlib
import logging

logger = logging.getLogger(__name__)

__all__ = ["scrub"]

SCRUB_PII = os.getenv("SCRUB_PII", "true").lower() == "true"


def _deterministic_token(value: str, prefix: str = "ENTITY") -> str:
    short_hash = hashlib.sha256(value.encode()).hexdigest()[:6]
    return f"[{prefix}_{short_hash}]"


def scrub(text: str) -> str:
    """
    Masks hardware serial numbers, private keys, API keys, password hashes,
    and pre-shared keys in tool output while preserving real IP addresses.
    """
    if not SCRUB_PII:
        return text

    if not isinstance(text, str):
        text = str(text)

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

    # 3. Sensitive YAML / CLI configuration fields (phash, password, pre-shared-key, secret, etc.)
    text = re.sub(
        r'\b(?P<field>phash|password|pre-shared-key|secret|passphrase|bind-password)[:=\s]+[\'\"`]?([^\s\'\"`\n\[]+)[\'\"`]?',
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
        r'\b(api[_-]?key|secret[_-]?key)[:=\s]+[\'"]?[a-zA-Z0-9_\-]{16,}[\'"]?',
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

