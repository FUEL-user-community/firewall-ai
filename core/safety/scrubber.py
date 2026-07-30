"""
PII Scrubbing Layer

Activated via SCRUB_PII=true in .env. Runs on tool OUTPUT before injection
into LLM context. Masks IPs, serials, and usernames with deterministic tokens
so the LLM can still correlate entities across tool calls.

Design: Same real value always maps to the same token via SHA-256 prefix.
e.g., "10.0.0.1" → "[IP_a1b2c3]" consistently across all tool outputs.
"""
import os
import re
import hashlib
import logging

logger = logging.getLogger(__name__)

# SECURITY: Enable PII scrubbing by default to prevent leaking IPs/Serials to LLM providers
SCRUB_PII = os.getenv("SCRUB_PII", "true").lower() == "true"

if not SCRUB_PII:
    logger.warning("[SCRUBBER] ⚠️ PII Scrubbing is DISABLED. Sensitive data will be sent to the LLM in plaintext.")


def _deterministic_token(value: str, prefix: str = "ENTITY") -> str:
    """
    Generates a consistent token for the same input value.
    Same IP always maps to same token — preserves cross-tool correlation.
    """
    short_hash = hashlib.sha256(value.encode()).hexdigest()[:6]
    return f"[{prefix}_{short_hash}]"


def scrub(text: str) -> str:
    """
    Masks PII patterns in tool output. No-op when SCRUB_PII is disabled.
    
    Patterns masked:
    - IPv4 addresses (preserves /CIDR suffix)
    - Serial numbers (skips already-masked {{SERIAL_*}} format)
    """
    if not SCRUB_PII:
        return text
    
    if not isinstance(text, str):
        text = str(text)
    
    # IPv4 addresses (with optional CIDR)
    def _replace_ip(match):
        full = match.group(0)
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
    
    scrub_count = text.count("[IP_") + text.count("[SN_")
    if scrub_count > 0:
        logger.info(f"[SCRUB] Masked {scrub_count} PII tokens in tool output.")
    
    return text
