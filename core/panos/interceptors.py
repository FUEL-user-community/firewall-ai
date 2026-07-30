"""
Command Routing & Interceptors
Pattern-based routing for different command types.
"""

import logging
from typing import Tuple, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Enumeration of command types for routing."""
    LOG_QUERY = "log_query"
    REPORT_QUERY = "report_query"
    LIVE_ANALYTICS = "live_analytics"
    OPERATIONAL = "operational"


class CommandRoute:
    """
    Represents a parsed command route.
    
    Attributes:
        type: CommandType enum
        args: Dictionary of parsed arguments
    """
    
    def __init__(self, cmd_type: CommandType, args: Dict[str, Any]):
        self.type = cmd_type
        self.args = args
    
    def __repr__(self):
        return f"CommandRoute(type={self.type.value}, args={self.args})"


class CommandRouter:
    """
    Routes commands to appropriate handlers based on pattern matching.
    
    Analyzes command strings and determines the correct execution path:
    - Log queries (show log <type>)
    - Report queries (show report <type>)
    - Live analytics (show session analytics)
    - Operational commands (default)
    
    Example:
        router = CommandRouter()
        route = router.route("show log traffic")
        # Returns: CommandRoute(type=LOG_QUERY, args={'log_type': 'traffic'})
    """
    
    def route(self, cmd: str) -> CommandRoute:
        """
        Analyze command and return routing information.
        
        Args:
            cmd: Command string to route
        
        Returns:
            CommandRoute object with type and parsed arguments
        
        Examples:
            >>> router.route("show log traffic")
            CommandRoute(type=LOG_QUERY, args={'log_type': 'traffic'})
            
            >>> router.route("show report top-applications")
            CommandRoute(type=REPORT_QUERY, args={'report_type': 'top-applications'})
            
            >>> router.route("show system info")
            CommandRoute(type=OPERATIONAL, args={'cmd': 'show system info'})
        """
        cmd_stripped = cmd.strip()
        
        # Route: show log <type>
        if cmd_stripped.startswith("show log"):
            log_type = self._extract_log_type(cmd_stripped)
            if log_type:
                logger.debug(f"[Router] Routing to LOG_QUERY: {log_type}")
                return CommandRoute(CommandType.LOG_QUERY, {'log_type': log_type})
        
        # Route: show report <type>
        if cmd_stripped.startswith("show report"):
            report_type = self._extract_report_type(cmd_stripped)
            if report_type:
                logger.debug(f"[Router] Routing to REPORT_QUERY: {report_type}")
                return CommandRoute(CommandType.REPORT_QUERY, {'report_type': report_type})
        
        # Route: show session analytics (special case)
        if cmd_stripped == "show session analytics":
            logger.debug("[Router] Routing to LIVE_ANALYTICS")
            return CommandRoute(CommandType.LIVE_ANALYTICS, {})
        
        # Default: operational command
        logger.debug(f"[Router] Routing to OPERATIONAL: {cmd[:30]}...")
        return CommandRoute(CommandType.OPERATIONAL, {'cmd': cmd})
    
    def _extract_log_type(self, cmd: str) -> Optional[str]:
        """
        Extract log type from 'show log <type>' command.
        
        Args:
            cmd: Command string
        
        Returns:
            Log type string or None if invalid
        
        Examples:
            "show log traffic" -> "traffic"
            "show log system" -> "system"
        """
        parts = cmd.strip().split()
        if len(parts) >= 3 and parts[0] == "show" and parts[1] == "log":
            return parts[2]
        return None
    
    def _extract_report_type(self, cmd: str) -> Optional[str]:
        """
        Extract report type from 'show report <type>' command.
        
        Args:
            cmd: Command string
        
        Returns:
            Report type string or None if invalid
        
        Examples:
            "show report top-applications" -> "top-applications"
            "show report predefined" -> "predefined"
        """
        parts = cmd.strip().split()
        if len(parts) >= 3 and parts[0] == "show" and parts[1] == "report":
            return parts[2]
        return None
