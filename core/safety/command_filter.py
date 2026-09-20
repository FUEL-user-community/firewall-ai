"""
Command Filter — CLI Operation Allowlist
Validates generated commands against explicit blocks and prefix allowlists
to prevent autonomous firewall modification or lateral movement.
"""
import re
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

__all__ = ["CommandFilter"]


class CommandFilter:
    """
    Allowlist for PAN-OS operational commands to prevent autonomous exploitation.
    Enforces strict word boundary pattern matching to prevent false-positive blocks.
    """

    ALLOWED_PREFIXES = (
        "show ",
        "test ",
        "ping ",
        "traceroute ",
    )

    ALLOWED_EXACT = (
        "show",
        "test",
        "request license info",
        "request system software check",
        "request system info",
    )

    # Strict word boundaries eliminate false-positive substring blocking (H1)
    BLOCKED_PATTERNS = (
        r"\brequest\s+restart\b",
        r"\brequest\s+system\s+private-data-reset\b",
        r"\bdebug\b",
        r"^\s*set\b",
        r"\bset\s+",
        r"^\s*delete\b",
        r"\bdelete\s+",
        r"^\s*configure\b",
        r"\bconfigure\s+",
        r"\btest\s+vpn\b",
    )

    @classmethod
    def is_allowed(cls, cmd: str) -> Tuple[bool, str]:
        """
        Check if a command is allowed to be executed on the firewall.
        Returns (is_allowed: bool, reason: str)
        """
        if not cmd or not isinstance(cmd, str):
            return False, "Command must be a non-empty string."

        cmd_clean = cmd.strip()
        cmd_lower = cmd_clean.lower()

        # Reject XML tags to prevent command / XML smuggling
        if '<' in cmd_lower or '>' in cmd_lower:
            logger.warning(f"[CMDFILTER] BLOCKED XML in command: {cmd_clean[:80]}")
            return False, "Commands must not contain XML tags."

        # Check explicit blocks with word boundaries first
        for pattern in cls.BLOCKED_PATTERNS:
            if re.search(pattern, cmd_lower):
                logger.warning(f"[CMDFILTER] BLOCKED: {cmd_clean[:80]} (matched: {pattern})")
                return False, f"Command contains blocked pattern: {pattern}"

        # Check exact matches
        if cmd_lower in cls.ALLOWED_EXACT:
            logger.info(f"[CMDFILTER] ALLOWED (exact): {cmd_clean[:80]}")
            return True, "Allowed (exact match)"

        # Check allowlist prefixes
        for prefix in cls.ALLOWED_PREFIXES:
            if cmd_lower.startswith(prefix):
                logger.info(f"[CMDFILTER] ALLOWED (prefix): {cmd_clean[:80]}")
                return True, "Allowed"

        logger.warning(f"[CMDFILTER] DENIED (not in allowlist): {cmd_clean[:80]}")
        return False, "Command prefix not in allowlist (must start with 'show', 'test', etc.)"
