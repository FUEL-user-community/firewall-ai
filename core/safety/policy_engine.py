"""
Policy-Gated Tool Execution

All tools are classified as READ or WRITE. The PolicyEngine intercepts
every function_call before execution and checks against the current mode.
Default mode: READ_ONLY — write tools blocked until explicitly elevated.
"""
import os
import logging

logger = logging.getLogger(__name__)


class PolicyViolationError(Exception):
    """Raised when a tool call violates the current execution policy."""
    pass


class DeviceAccessDeniedError(Exception):
    """Raised when a user attempts to access a device they're not authorized for."""
    pass


class PolicyEngine:
    """
    Middleware between LLM function_call and tool execution.
    Default mode: READ_ONLY. Must be explicitly elevated for write operations.
    """
    
    # Tools that only observe — safe for autonomous execution
    READ_TOOLS = {
        # Native Python tools
        "summon_toolkit",
        "search_live_docs",
        "query_forensic_matrix",
        "query_knowledge_base",
        "test_security_policy",
        "test_routing_fib",
        "test_nat_policy",
        "get_live_config",
        "execute_log_query",
        "audit_user_id",                # User-ID investigation tool
        "get_telemetry_snapshot",        # Real-time health metrics
        "get_device_inventory",          # Fleet discovery tool
        "execute_live_app_analytics",    # Session-based app analysis
        # WARNING: execute_operational_command can run ANY show/debug/test command.
        # It is READ (observation-only) but extremely powerful. The CommandRouter
        # interceptor layer (core/panos/interceptors.py) provides secondary defense
        # by stripping dangerous command patterns before API execution.
        "execute_operational_command",
        "execute_report_query",
        "execute_report_discovery",
        "fetch_running_config_xml",      # Full config export for posture assessment
        # YAML macros (#core)
        "hardware_telemetry",
        "network_base",
        "app_telemetry",
        # YAML singles (#core)
        "system_info",
        "system_resources",
        "license_info",
        "admin_sessions",
        "mgmt_clients",
        "interface_all",
        "session_info",
        "ha_status",
        "arp_table",
        "user_ip_mapping",
        "threat_logs",
        "get_active_sessions",
        "app_cache_summary",
        "app_stats",
        "find_command",
        # YAML singles (non-#core, read-only)
        "software_status",
        "disk_space",
        "logdb_quota",
        "clock_status",
        "ntp_status",
        "jobs_processed",
        "all_jobs",
        "job_details",
        "interface_details",
        "interface_hardware",
        "routing_route",
        "routing_static",
        "routing_bgp",
        "routing_bgp_peers",
        "routing_ospf_neighbors",
        "mac_table",
        "global_counters",
        "global_counters_filter",
        "auth_logs",
        "session_meter",
        "session_all",
        "session_filter_source",
        "session_filter_dest",
        "session_filter_app",
        "session_details",
        "vpn_comprehensive_status",
        "ha_deep_audit",
        "userid_infrastructure_health",
        "vpn_flow",
        "vpn_ike_sa",
        "vpn_ipsec_sa",
        "vpn_tunnel_interface",
        "gp_current_users",
        "gp_history",
        "wildfire_status",
        "wildfire_disk_usage",
        "test_wildfire_reg",
        "url_cloud_status",
        "sdwan_status",
        "list_predefined_reports",
        "botnet_report",
        "test_policy_match",
        "test_nat_match",
        "test_routing_lookup",
        "test_url_category",
        "view_pcap",
        "check_user_ip",
        "user_group_members",
        "user_server_monitor",
        "set_xml_output",
    }
    
    # Tools that modify state — require explicit elevation
    WRITE_TOOLS = {
        "clear_interface_counters",   # Resets interface statistics
        "clear_session_id",           # Kills an active session
        "apply_dynamic_tag",          # Tags an IP address into a DAG
        "capture_pcap",               # Triggers live dataplane capture
        "clear_user_cache",           # Flushes User-ID cache
        "test_vpn_ike",               # Forces IKE Phase 1 initiation
        "test_vpn_ipsec",             # Forces IPSec Phase 2 initiation
        "force_wildfire_upload",      # Triggers log upload to WildFire
        "enable_predefined_reports",  # Debug command, changes device state
        "enable_scripting_mode",      # Changes device scripting mode
    }
    
    def __init__(self, mode=None):
        self.mode = mode or os.getenv("POLICY_MODE", "READ_ONLY")
        logger.info(f"[POLICY] Engine initialized: mode={self.mode}")
    
    def check(self, tool_name: str) -> bool:
        """
        Returns True if the tool is allowed under the current policy.
        Raises PolicyViolationError if a WRITE tool is called in READ_ONLY mode.
        Unknown tools default to READ (fail-open for backwards compatibility
        with YAML-defined tools that may not be in the registry).
        """
        if tool_name in self.WRITE_TOOLS:
            if self.mode == "READ_ONLY":
                raise PolicyViolationError(
                    f"Tool '{tool_name}' requires WRITE permission. "
                    f"Current mode: {self.mode}. "
                    "Set POLICY_MODE=READ_WRITE in .env to enable."
                )
            logger.warning(f"[POLICY] WRITE tool '{tool_name}' authorized under {self.mode} mode.")
        
        if tool_name not in self.READ_TOOLS and tool_name not in self.WRITE_TOOLS:
            logger.info(f"[POLICY] Tool '{tool_name}' not in policy registry — defaulting to READ.")
        
        return True
    
    def elevate(self, mode: str = "READ_WRITE"):
        """Temporarily elevate permissions. Log the elevation."""
        old_mode = self.mode
        self.mode = mode
        logger.warning(f"[POLICY] Mode elevated: {old_mode} → {mode}")
    
    def reset(self):
        """Reset to READ_ONLY after elevated operation completes."""
        self.mode = "READ_ONLY"
        logger.info("[POLICY] Mode reset to READ_ONLY.")

    def check_device_access(self, user_context, target_device: str) -> bool:
        """
        Per-device RBAC: verify the user is authorized to access the target device.
        Raises DeviceAccessDeniedError if the user's allowed_devices list
        does not include the target device (and is not wildcard '*').

        Args:
            user_context: UserContext from identity.py (has .can_access_device())
            target_device: Device alias from devices.yaml (e.g., 'fw-hq')

        Returns:
            True if access is allowed.
        """
        if target_device in ("default", "", None):
            # Default device — always allowed (backward compatible)
            return True

        if not hasattr(user_context, 'can_access_device'):
            # Legacy UserContext without device RBAC — allow
            return True

        if not user_context.can_access_device(target_device):
            raise DeviceAccessDeniedError(
                f"User '{user_context.user_id}' (role={user_context.role}) "
                f"is not authorized to access device '{target_device}'. "
                f"Allowed devices: {user_context.allowed_devices}"
            )

        logger.info(f"[POLICY] Device access granted: {user_context.user_id} → {target_device}")
        return True
