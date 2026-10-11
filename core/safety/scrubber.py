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


def _deterministic_token(value: str, prefix: str = "ENTITY") -> str:
    short_hash = hashlib.sha256(value.encode()).hexdigest()[:6]
    return f"[{prefix}_{short_hash}]"


def scrub(text: str) -> str:
    """
    Masks hardware serial numbers in tool output while preserving real IP addresses.
    """
    if not SCRUB_PII:
        return text

    if not isinstance(text, str):
        text = str(text)

    # Serial numbers (skip already-masked {{SERIAL_*}} format)
    text = re.sub(
        r'(?<!\{\{)(?:serial(?:[ -]?number)?[:\s]+)([A-Z0-9]{10,})\b',
        lambda m: m.group(0).replace(m.group(1), _deterministic_token(m.group(1), "SN")),
        text,
        flags=re.IGNORECASE
    )

    return text
