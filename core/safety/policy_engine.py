"""
Policy-Gated Tool Execution
All tools are classified as READ or WRITE. The PolicyEngine intercepts
every function_call before execution and checks against the current mode.
Default mode: READ_ONLY — write tools blocked until explicitly elevated.
"""
import os
import logging
import threading
from contextlib import contextmanager
from typing import Optional, Set

logger = logging.getLogger(__name__)

__all__ = ["PolicyEngine", "PolicyViolationError", "DeviceAccessDeniedError"]


class PolicyViolationError(Exception):
    """Raised when a tool call violates the current execution policy."""
    pass


class DeviceAccessDeniedError(Exception):
    """Raised when a user attempts to access a device they're not authorized for."""
    pass


class PolicyEngine:
    """
    Middleware between LLM function_call and tool execution.
    Default mode: READ_ONLY. Scoped via thread-local state to prevent cross-thread leakage (H5).
    """

    READ_TOOLS: Set[str] = {
        "summon_toolkit",
        "search_live_docs",
        "query_forensic_matrix",
        "query_knowledge_base",
        "test_security_policy",
        "test_routing_fib",
        "test_nat_policy",
        "get_live_config",
        "execute_log_query",
        "audit_user_id",
        "get_telemetry_snapshot",
        "get_device_inventory",
        "execute_live_app_analytics",
        "execute_operational_command",
        "execute_report_query",
        "execute_report_discovery",
        "fetch_running_config_xml",
        "hardware_telemetry",
        "network_base",
        "app_telemetry",
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

    WRITE_TOOLS: Set[str] = {
        "clear_interface_counters",
        "clear_session_id",
        "apply_dynamic_tag",
        "capture_pcap",
        "clear_user_cache",
        "test_vpn_ike",
        "test_vpn_ipsec",
        "force_wildfire_upload",
        "enable_predefined_reports",
        "enable_scripting_mode",
    }

    # Fail-closed heuristic: dangerous prefixes on unknown tools default to WRITE (H6)
    WRITE_PREFIXES = (
        "clear_",
        "delete_",
        "set_",
        "apply_",
        "remove_",
        "restart_",
        "force_",
        "kill_",
        "update_",
        "modify_",
    )

    def __init__(self, mode: Optional[str] = None):
        self._default_mode = (mode or os.getenv("POLICY_MODE", "READ_ONLY")).upper()
        self._local = threading.local()
        logger.info(f"[POLICY] Engine initialized: default_mode={self._default_mode}")

    @property
    def mode(self) -> str:
        """Thread-scoped execution mode, falling back to default."""
        return getattr(self._local, "mode", None) or self._default_mode

    @mode.setter
    def mode(self, val: str):
        self._local.mode = val.upper()

    def check(self, tool_name: str) -> bool:
        """
        Validates whether tool_name is permitted under current execution policy.
        Enforces fail-closed write protection on unknown tools (H6).
        """
        if not tool_name or not isinstance(tool_name, str):
            raise PolicyViolationError("Tool name must be a non-empty string.")

        clean_name = tool_name.strip()

        is_write = (
            clean_name in self.WRITE_TOOLS
            or any(clean_name.startswith(p) for p in self.WRITE_PREFIXES)
        )

        if is_write:
            if self.mode == "READ_ONLY":
                raise PolicyViolationError(
                    f"Tool '{clean_name}' requires WRITE permission. "
                    f"Current mode: {self.mode}. "
                    "Set POLICY_MODE=READ_WRITE or elevate permissions."
                )
            logger.warning(f"[POLICY] WRITE tool '{clean_name}' authorized under {self.mode} mode.")
            return True

        if clean_name not in self.READ_TOOLS:
            logger.info(f"[POLICY] Tool '{clean_name}' not in registry — defaulting to READ (heuristic safe).")

        return True

    def elevate(self, mode: str = "READ_WRITE"):
        """Temporarily elevate permissions for the calling thread (H5)."""
        old_mode = self.mode
        self._local.mode = mode.upper()
        logger.warning(f"[POLICY] Thread elevated: {old_mode} -> {self._local.mode}")

    def reset(self):
        """Reset thread-local elevation to default mode."""
        if hasattr(self._local, "mode"):
            del self._local.mode
        logger.info(f"[POLICY] Thread reset to default mode ({self._default_mode}).")

    @contextmanager
    def elevated(self, mode: str = "READ_WRITE"):
        """Context manager for scoped elevation with guaranteed restoration."""
        prev = self.mode
        self.elevate(mode)
        try:
            yield
        finally:
            self.elevate(prev)

    def check_device_access(self, user_context, target_device: str) -> bool:
        """Per-device RBAC: verify user authorization for target device."""
        if target_device in ("default", "", None):
            return True

        if not hasattr(user_context, 'can_access_device'):
            return True

        if not user_context.can_access_device(target_device):
            raise DeviceAccessDeniedError(
                f"User '{user_context.user_id}' (role={user_context.role}) "
                f"is not authorized to access device '{target_device}'. "
                f"Allowed devices: {user_context.allowed_devices}"
            )

        logger.info(f"[POLICY] Device access granted: {user_context.user_id} -> {target_device}")
        return True
