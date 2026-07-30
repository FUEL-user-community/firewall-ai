"""
Command Filter — CLI Operation Allowlist
Validates generated commands against explicit blocks and prefix allowlists
to prevent autonomous firewall modification or lateral movement.
"""
import re
import logging

logger = logging.getLogger(__name__)

class CommandFilter:
    """
    Allowlist for PAN-OS operational commands to prevent autonomous exploitation.
    """
    
    ALLOWED_PREFIXES = [
        "show",
        "test",
    ]
    
    # Exact-match commands (not prefix-match)
    ALLOWED_EXACT = [
        "request license info",
        "request system software check",
    ]
    
    BLOCKED_PATTERNS = [
        r"request restart",
        r"request system private-data-reset",
        r"debug",
        r"set",
        r"delete",
        r"configure"
    ]

    @classmethod
    def is_allowed(cls, cmd: str) -> tuple[bool, str]:
        """
        Check if a command is allowed to be executed on the firewall.
        Returns (is_allowed: bool, reason: str)
        """
        cmd_lower = cmd.lower().strip()
        
        # Reject any XML in commands to prevent XML smuggling
        if '<' in cmd_lower or '>' in cmd_lower:
            logger.warning(f"[CMDFILTER] BLOCKED XML in command: {cmd[:80]}")
            return False, "Commands must not contain XML tags."
        
        # Check explicit blocks first
        for pattern in cls.BLOCKED_PATTERNS:
            if re.search(pattern, cmd_lower):
                logger.warning(f"[CMDFILTER] BLOCKED: {cmd[:80]} (pattern: {pattern})")
                return False, f"Command contains blocked pattern: {pattern}"
                
        # Check exact matches
        if cmd_lower in cls.ALLOWED_EXACT:
            logger.info(f"[CMDFILTER] ALLOWED (exact): {cmd[:80]}")
            return True, "Allowed (exact match)"
            
        # Check allowlist
        for prefix in cls.ALLOWED_PREFIXES:
            if cmd_lower.startswith(prefix):
                logger.info(f"[CMDFILTER] ALLOWED (prefix): {cmd[:80]}")
                return True, "Allowed"
                
        logger.warning(f"[CMDFILTER] DENIED (not in allowlist): {cmd[:80]}")
        return False, "Command prefix not in allowlist (must start with 'show', 'test', etc.)"
