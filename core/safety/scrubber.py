"""
PII Scrubbing Layer
Masks sensitive IPs and serials while preserving standard infrastructure constants (M2).
"""
import os
import re
import hashlib
import logging

logger = logging.getLogger(__name__)

__all__ = ["scrub"]

SCRUB_PII = os.getenv("SCRUB_PII", "true").lower() == "true"

# Allowlist standard non-sensitive network constants to keep route tables readable (M2)
STANDARD_EXCLUSIONS = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
}


def _deterministic_token(value: str, prefix: str = "ENTITY") -> str:
    short_hash = hashlib.sha256(value.encode()).hexdigest()[:6]
    return f"[{prefix}_{short_hash}]"


def _is_valid_ipv4(ip_str: str) -> bool:
    """Validate 4-octet IPv4 range 0-255."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
        if len(p) > 1 and p.startswith('0'):
            return False
    return True


def scrub(text: str) -> str:
    """
    Masks PII patterns in tool output.
    Preserves default routes and DNS constants from over-masking (M2).
    """
    if not SCRUB_PII:
        return text

    if not isinstance(text, str):
        text = str(text)

    def _replace_ip(match):
        full = match.group(0)
        raw_ip = full.split('/', 1)[0] if '/' in full else full

        if not _is_valid_ipv4(raw_ip) or raw_ip in STANDARD_EXCLUSIONS:
            return full

        if '/' in full:
            ip, cidr = full.split('/', 1)
            return _deterministic_token(ip, "IP") + '/' + cidr
        return _deterministic_token(full, "IP")

    text = re.sub(
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?\b',
        _replace_ip,
        text
    )

    # Serial numbers (skip already-masked {{SERIAL_*}} format)
    text = re.sub(
        r'(?<!\{\{)(?:serial(?:[ -]?number)?[:\s]+)([A-Z0-9]{10,})\b',
        lambda m: m.group(0).replace(m.group(1), _deterministic_token(m.group(1), "SN")),
        text,
        flags=re.IGNORECASE
    )

    return text
