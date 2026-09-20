"""
GoogleDriveObsidianMapper — Edge-to-Cloud Cartographer

Intercepts tool results at the ToolExecutor level and streams
structured Obsidian Markdown to Google Drive.

Routes based on the TOOL NAME (e.g. 'interface_all', 'get_live_config')
not raw CLI strings. This is stable because tool names come from
commands.yaml and native Python function names — they never change.
"""

import os
import re
import yaml
import logging
import io
import atexit
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("core-defense.obsidian")

# Lazy-load Google API client — app runs fine without it
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload
    HAS_DRIVE_API = True
except ImportError:
    HAS_DRIVE_API = False
    logger.warning("[MAPPER] google-api-python-client not installed. Obsidian mapping disabled.")


class GoogleDriveObsidianMapper:
    """
    Singleton Cartographer.

    Receives (tool_name, tool_args, yaml_result) from ToolExecutor,
    parses the YAML into Obsidian Markdown in-memory, and pushes it
    to Google Drive via a background thread pool.

    The LLM investigation loop is NEVER blocked by this class.
    """
    _instance = None
    _lock = threading.Lock()

    # ── Tool-name-based routing table ──────────────────────────────
    # Maps tool names (from commands.yaml / native Python) to parser methods.
    # This is the canonical routing — no string-matching on raw CLI commands.
    TOOL_ROUTES = {
        # Operational commands (from commands.yaml closures)
        "interface_all":        "_parse_interfaces",
        "routing_route":        "_parse_routes",
        "routing_static":       "_parse_routes",
        "session_all":          "_parse_sessions",
        "session_filter_source":"_parse_sessions",
        "session_filter_dest":  "_parse_sessions",
        "session_filter_app":   "_parse_sessions",
        "arp_table":            "_parse_arp",
        "ha_status":            "_parse_ha",
        "ha_state":             "_parse_ha",
        # Native Python tools
        "test_security_policy": "_parse_policy_test",
        "test_nat_policy":      "_parse_nat_test",
        "get_device_inventory": "_parse_inventory",
        # Macros
        "hardware_telemetry":   "_parse_telemetry",
        "vpn_comprehensive_status": "_parse_vpn",
    }

    # get_live_config routes based on xpath substring
    XPATH_ROUTES = {
        "rulebase/security":    "_parse_security_rules",
        "rulebase/nat":         "_parse_nat_rules",
        "zone":                 "_parse_zones",
        "address":              "_parse_address_objects",
        "interface":            "_parse_config_interfaces",
    }

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def reset(cls):
        """Reset singleton cartographer instance and shut down background executor (L2)."""
        with cls._lock:
            if cls._instance is not None:
                if hasattr(cls._instance, '_executor'):
                    try:
                        cls._instance._shutdown()
                    except Exception:
                        pass
            cls._instance = None

    def __init__(self):
        self.enabled = HAS_DRIVE_API and bool(os.getenv("GCP_SERVICE_ACCOUNT_FILE"))
        if not self.enabled:
            logger.warning("[MAPPER] Disabled. Set GCP_SERVICE_ACCOUNT_FILE and OBSIDIAN_DRIVE_FOLDER_ID.")
            return

        self.service_account_file = os.getenv("GCP_SERVICE_ACCOUNT_FILE")
        self.folder_id = os.getenv("OBSIDIAN_DRIVE_FOLDER_ID")

        if not self.folder_id:
            logger.warning("[MAPPER] Missing OBSIDIAN_DRIVE_FOLDER_ID.")
            self.enabled = False
            return

        # Background thread pool — daemon=True so threads die on app exit
        self._executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="obsidian")
        atexit.register(self._shutdown)

        self._drive_service = self._init_drive_service()

        # Thread-safe folder ID cache
        self._folder_cache = {}
        self._folder_cache_lock = threading.Lock()

    def _shutdown(self):
        """Clean shutdown of thread pool on app exit."""
        try:
            self._executor.shutdown(wait=False)
        except Exception:
            pass

    def _init_drive_service(self):
        try:
            scopes = ['https://www.googleapis.com/auth/drive.file']
            creds = service_account.Credentials.from_service_account_file(
                self.service_account_file, scopes=scopes)
            service = build('drive', 'v3', credentials=creds, cache_discovery=False)
            logger.info("[MAPPER] Google Drive API connected.")
            return service
        except Exception as e:
            logger.error(f"[MAPPER] Drive init failed: {e}")
            self.enabled = False
            return None

    # ══════════════════════════════════════════════════════════════
    # PUBLIC API — Called from ToolExecutor._raw_execute()
    # ══════════════════════════════════════════════════════════════

    def map_tool_result(self, tool_name: str, tool_args: dict, result: str):
        """
        Entry point. Called by ToolExecutor after every successful tool execution.
        Immediately returns — all work happens in background threads.
        """
        if not self.enabled:
            return
        if not isinstance(result, str) or len(result) < 10:
            return

        self._executor.submit(self._route_and_parse, tool_name, tool_args, result)

    # ══════════════════════════════════════════════════════════════
    # ROUTING
    # ══════════════════════════════════════════════════════════════

    def _route_and_parse(self, tool_name: str, tool_args: dict, result: str):
        """Routes to the correct parser based on tool name."""
        try:
            # Special case: get_live_config routes by xpath
            if tool_name == "get_live_config":
                xpath = tool_args.get("xpath", "")
                for xpath_fragment, method_name in self.XPATH_ROUTES.items():
                    if xpath_fragment in xpath:
                        parser = getattr(self, method_name, None)
                        if parser:
                            parser(result, tool_args)
                        return
                # Unknown xpath — skip silently
                return

            # Standard routing by tool name
            method_name = self.TOOL_ROUTES.get(tool_name)
            if method_name:
                parser = getattr(self, method_name, None)
                if parser:
                    parser(result, tool_args)

        except Exception as e:
            logger.error(f"[MAPPER] Parse error for '{tool_name}': {e}")

    # ══════════════════════════════════════════════════════════════
    # PARSERS — Each writes structured Markdown to Drive
    # ══════════════════════════════════════════════════════════════

    def _parse_zones(self, yaml_data: str, args: dict):
        """Parses zone config from get_live_config xpath=.../zone"""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            # Walk the dict to find zone entries
            zones = self._find_entries(data, "zone")
            for zone in zones:
                name = zone.get("@name", "unknown")
                network = zone.get("network", {})
                layer3 = network.get("layer3", {}) if isinstance(network, dict) else {}
                members = layer3.get("member", []) if isinstance(layer3, dict) else []
                if isinstance(members, str):
                    members = [members]

                md = f"# Zone: {name}\n\n"
                md += f"- **Type**: Layer3\n"
                md += f"- **Interfaces**:\n"
                for iface in members:
                    md += f"  - [[{iface.replace('/', '_')}]]\n"
                md += f"\n---\n*Mapped: {self._timestamp()}*\n"

                self._push_to_drive("01_Zones", f"{name}.md", md)

        except Exception as e:
            logger.error(f"[MAPPER] Zone parse failed: {e}")

    def _parse_interfaces(self, yaml_data: str, args: dict):
        """Parses operational interface_all output."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            # interface_all returns a list of interface entries
            interfaces = self._find_entries(data, "ifnet")
            if not interfaces:
                interfaces = self._find_entries(data, "entry")
            for iface in interfaces:
                name = iface.get("name", iface.get("@name", "unknown"))
                zone = iface.get("zone", "unzoned")
                ip = iface.get("ip", iface.get("addr", "N/A"))
                status = iface.get("status", iface.get("state", "unknown"))

                safe_name = name.replace("/", "_")
                md = f"# Interface: {name}\n\n"
                md += f"- **IP**: `{ip}`\n"
                md += f"- **Zone**: [[{zone}]]\n"
                md += f"- **Status**: {status}\n"
                md += f"\n---\n*Mapped: {self._timestamp()}*\n"

                self._push_to_drive("02_Interfaces", f"{safe_name}.md", md)

        except Exception as e:
            logger.error(f"[MAPPER] Interface parse failed: {e}")

    def _parse_security_rules(self, yaml_data: str, args: dict):
        """Parses security rulebase from get_live_config."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            rules = self._find_entries(data, "entry")
            for rule in rules:
                name = rule.get("@name", "unnamed-rule")
                action = rule.get("action", "unknown")
                from_zones = self._flatten(rule.get("from", {}).get("member", []))
                to_zones = self._flatten(rule.get("to", {}).get("member", []))
                apps = self._flatten(rule.get("application", {}).get("member", []))
                services = self._flatten(rule.get("service", {}).get("member", []))
                src = self._flatten(rule.get("source", {}).get("member", []))
                dst = self._flatten(rule.get("destination", {}).get("member", []))

                md = f"# Rule: {name}\n\n"
                md += f"- **Action**: `{action}`\n"
                md += f"- **From Zones**: {', '.join(f'[[{z}]]' for z in from_zones)}\n"
                md += f"- **To Zones**: {', '.join(f'[[{z}]]' for z in to_zones)}\n"
                md += f"- **Source**: {', '.join(src)}\n"
                md += f"- **Destination**: {', '.join(dst)}\n"
                md += f"- **Applications**: {', '.join(apps)}\n"
                md += f"- **Services**: {', '.join(services)}\n"

                # Check for missing security profiles (Red Team signal)
                profile_setting = rule.get("profile-setting")
                if not profile_setting:
                    md += f"\n> [!WARNING] No security profile group attached.\n"

                md += f"\n---\n*Mapped: {self._timestamp()}*\n"

                safe_name = re.sub(r'[<>:"/\\|?*]', '_', name)
                self._push_to_drive("03_Rules", f"{safe_name}.md", md)

        except Exception as e:
            logger.error(f"[MAPPER] Security rule parse failed: {e}")

    def _parse_policy_test(self, yaml_data: str, args: dict):
        """Parses test_security_policy simulation results."""
        try:
            src = args.get("source", "?")
            dst = args.get("destination", "?")
            port = args.get("port", "?")

            md = f"# Policy Test: {src} → {dst}:{port}\n\n"
            md += f"```yaml\n{yaml_data[:2000]}\n```\n"
            md += f"\n- **Source**: [[{src}]]\n"
            md += f"- **Destination**: [[{dst}]]\n"
            md += f"\n---\n*Tested: {self._timestamp()}*\n"

            safe_name = f"test_{src}_to_{dst}_{port}".replace(".", "-")
            self._push_to_drive("05_Simulations", f"{safe_name}.md", md)

        except Exception as e:
            logger.error(f"[MAPPER] Policy test parse failed: {e}")

    def _parse_nat_test(self, yaml_data: str, args: dict):
        """Parses test_nat_policy simulation results."""
        try:
            src = args.get("source", "?")
            dst = args.get("destination", "?")
            port = args.get("port", "?")

            md = f"# NAT Test: {src} → {dst}:{port}\n\n"
            md += f"```yaml\n{yaml_data[:2000]}\n```\n"
            md += f"\n---\n*Tested: {self._timestamp()}*\n"

            safe_name = f"nat_{src}_to_{dst}_{port}".replace(".", "-")
            self._push_to_drive("05_Simulations", f"{safe_name}.md", md)

        except Exception as e:
            logger.error(f"[MAPPER] NAT test parse failed: {e}")

    def _parse_sessions(self, yaml_data: str, args: dict):
        """Appends session data to host-specific files."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            sessions = self._find_entries(data, "entry")
            # Group sessions by source IP for host-level notes
            hosts = {}
            for sess in sessions[:50]:  # Cap at 50 to prevent Drive API flood
                src = sess.get("source", sess.get("srcip", "unknown"))
                if src not in hosts:
                    hosts[src] = []
                hosts[src].append(sess)

            for host_ip, sess_list in hosts.items():
                entry_block = f"\n## Session Snapshot — {self._timestamp()}\n\n"
                for s in sess_list[:10]:
                    dst = s.get("dst", s.get("dstip", "?"))
                    app = s.get("application", "?")
                    state = s.get("state", "?")
                    entry_block += f"- `{host_ip}` → `{dst}` | App: {app} | State: {state}\n"

                safe_ip = host_ip.replace(".", "_")
                self._append_to_drive("04_Hosts", f"{safe_ip}.md", entry_block,
                                      header=f"# Host: {host_ip}\n\n")

        except Exception as e:
            logger.error(f"[MAPPER] Session parse failed: {e}")

    # ── Full Parser Implementations ──────────────────────────────

    def _parse_routes(self, yaml_data: str, args: dict):
        """Parses routing table (operational or static)."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            entries = self._find_entries(data, "entry")
            if not entries:
                return
            
            md = "# Routing Table\n\n"
            md += "| Destination | Next Hop | Interface | Flags / Type | Metric |\n"
            md += "| --- | --- | --- | --- | --- |\n"
            for entry in entries:
                dest = entry.get("destination", entry.get("ip", "N/A"))
                nh = entry.get("nexthop", entry.get("next-hop", "N/A"))
                iface = entry.get("interface", "N/A")
                flags = entry.get("flags", entry.get("type", "N/A"))
                metric = entry.get("metric", "N/A")
                
                safe_iface = f"[[{iface.replace('/', '_')}]]" if iface != "N/A" and iface else "N/A"
                md += f"| `{dest}` | `{nh}` | {safe_iface} | `{flags}` | `{metric}` |\n"
            
            md += f"\n---\n*Mapped: {self._timestamp()}*\n"
            self._push_to_drive("02_Interfaces", "RoutingTable.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] Route parse failed: {e}")

    def _parse_arp(self, yaml_data: str, args: dict):
        """Parses operational ARP table."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            entries = self._find_entries(data, "entry")
            if not entries:
                return

            md = "# ARP Table\n\n"
            md += "| IP Address | MAC Address | Interface | Status |\n"
            md += "| --- | --- | --- | --- |\n"
            for entry in entries:
                ip = entry.get("ip", "N/A")
                mac = entry.get("mac", "N/A")
                iface = entry.get("interface", "N/A")
                status = entry.get("status", "N/A")

                safe_iface = f"[[{iface.replace('/', '_')}]]" if iface != "N/A" and iface else "N/A"
                md += f"| `{ip}` | `{mac}` | {safe_iface} | `{status}` |\n"

                # Also update/append to individual Host file
                if ip != "N/A" and ip:
                    safe_ip = ip.replace(".", "_").replace(":", "_")
                    host_info = f"\n## Discovery Info — {self._timestamp()}\n\n"
                    host_info += f"- **MAC**: `{mac}`\n"
                    host_info += f"- **Interface**: {safe_iface}\n"
                    host_info += f"- **Status**: `{status}`\n"
                    self._append_to_drive("04_Hosts", f"{safe_ip}.md", host_info, header=f"# Host: {ip}\n\n")

            md += f"\n---\n*Mapped: {self._timestamp()}*\n"
            self._push_to_drive("02_Interfaces", "ARPTable.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] ARP parse failed: {e}")

    def _parse_ha(self, yaml_data: str, args: dict):
        """Parses HA status and state."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            
            md = "# High Availability (HA) Status\n\n"
            
            # Simple recursive search for HA properties
            def check_keys(d, keys):
                res = {}
                if isinstance(d, dict):
                    for k, v in d.items():
                        if k in keys:
                            res[k] = v
                        elif isinstance(v, (dict, list)):
                            res.update(check_keys(v, keys))
                elif isinstance(d, list):
                    for item in d:
                        res.update(check_keys(item, keys))
                return res

            ha_keys = ["enabled", "state", "peer-state", "mode", "group", "local-info", "peer-info"]
            ha_info = check_keys(data, ha_keys)

            md += f"- **Enabled**: `{ha_info.get('enabled', 'unknown')}`\n"
            md += f"- **Local State**: `{ha_info.get('state', 'unknown')}`\n"
            md += f"- **Peer State**: `{ha_info.get('peer-state', 'unknown')}`\n"
            md += f"- **Mode**: `{ha_info.get('mode', 'unknown')}`\n"
            md += f"- **Group ID**: `{ha_info.get('group', 'N/A')}`\n"

            md += f"\n```yaml\n{yaml_data[:2000]}\n```\n"
            md += f"\n---\n*Mapped: {self._timestamp()}*\n"
            self._push_to_drive("01_Zones", "HA_Status.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] HA parse failed: {e}")

    def _parse_inventory(self, yaml_data: str, args: dict):
        """Parses device inventory and system details."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return

            md = "# Device Inventory & System Details\n\n"

            info = {}
            def extract_system_info(d):
                if isinstance(d, dict):
                    for k, v in d.items():
                        if k in ["sw-version", "model", "serial", "uptime", "ip-address", "netmask", "default-gateway", "ipv6-address"]:
                            info[k] = v
                        elif isinstance(v, (dict, list)):
                            extract_system_info(v)
                elif isinstance(d, list):
                    for item in d:
                        extract_system_info(item)

            extract_system_info(data)

            md += f"- **Model**: `{info.get('model', 'unknown')}`\n"
            md += f"- **Software Version**: `{info.get('sw-version', 'unknown')}`\n"
            md += f"- **Serial Number**: `{info.get('serial', 'unknown')}`\n"
            md += f"- **Uptime**: `{info.get('uptime', 'unknown')}`\n"
            md += f"- **Management IP**: `{info.get('ip-address', 'unknown')}`\n"
            md += f"- **Netmask**: `{info.get('netmask', 'unknown')}`\n"
            md += f"- **Gateway**: `{info.get('default-gateway', 'unknown')}`\n"

            md += f"\n```yaml\n{yaml_data[:2000]}\n```\n"
            md += f"\n---\n*Mapped: {self._timestamp()}*\n"
            self._push_to_drive("01_Zones", "DeviceInventory.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] Inventory parse failed: {e}")

    def _parse_telemetry(self, yaml_data: str, args: dict):
        """Parses telemetry snapshot (CPU, Memory, Disk)."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return

            md = "# Telemetry & Performance Snapshot\n\n"

            # Parse CPU, Memory, Load average
            load_avg = None
            cpu_idle = None
            mem_used_pct = None
            filesystems = []

            def find_telemetry(d):
                nonlocal load_avg, cpu_idle, mem_used_pct, filesystems
                if isinstance(d, dict):
                    if "load_average" in d:
                        load_avg = d["load_average"]
                    if "cpu_idle_pct" in d:
                        cpu_idle = d["cpu_idle_pct"]
                    if "memory_used_pct" in d:
                        mem_used_pct = d["memory_used_pct"]
                    if "filesystems" in d:
                        filesystems = d["filesystems"]
                    for v in d.values():
                        if isinstance(v, (dict, list)):
                            find_telemetry(v)
                elif isinstance(d, list):
                    for item in d:
                        find_telemetry(item)

            find_telemetry(data)

            if cpu_idle is not None:
                cpu_used = round(100.0 - float(cpu_idle), 1)
                md += f"- **CPU Usage**: `{cpu_used}%` (Idle: `{cpu_idle}%`)\n"
            if mem_used_pct is not None:
                md += f"- **Memory Usage**: `{mem_used_pct}%`\n"
            if load_avg is not None:
                md += f"- **Load Average**: `{load_avg}`\n"

            if filesystems:
                md += "\n### Disk Utilization\n\n"
                md += "| Filesystem | Usage | Mounted On |\n"
                md += "| --- | --- | --- |\n"
                for fs in filesystems:
                    fs_name = fs.get("filesystem", "unknown")
                    usage = fs.get("usage_pct", "0")
                    mount = fs.get("mounted_on", "/")
                    md += f"| `{fs_name}` | `{usage}%` | `{mount}` |\n"

            md += f"\n```yaml\n{yaml_data[:2000]}\n```\n"
            md += f"\n---\n*Mapped: {self._timestamp()}*\n"
            self._push_to_drive("01_Zones", "Telemetry.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] Telemetry parse failed: {e}")

    def _parse_vpn(self, yaml_data: str, args: dict):
        """Parses VPN tunnels and IKE gateway status."""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return

            md = "# VPN Connections & Tunnels\n\n"
            
            ike_gateways = self._find_entries(data, "ike-gateway")
            ipsec_tunnels = self._find_entries(data, "ipsec-tunnel")
            if not ike_gateways and not ipsec_tunnels:
                ike_gateways = self._find_entries(data.get("ike", {}), "entry")
                ipsec_tunnels = self._find_entries(data.get("ipsec", {}), "entry")

            if ike_gateways:
                md += "### IKE Gateways\n\n"
                md += "| Name | Peer Address | Interface | Proposal | Status |\n"
                md += "| --- | --- | --- | --- | --- |\n"
                for gw in ike_gateways:
                    name = gw.get("@name", gw.get("name", "unknown"))
                    peer = gw.get("peer-address", gw.get("peerip", "N/A"))
                    iface = gw.get("interface", "N/A")
                    prop = gw.get("proposal", "N/A")
                    status = gw.get("status", gw.get("state", "N/A"))
                    safe_iface = f"[[{iface.replace('/', '_')}]]" if iface != "N/A" and iface else "N/A"
                    md += f"| `{name}` | `{peer}` | {safe_iface} | `{prop}` | `{status}` |\n"
                md += "\n"

            if ipsec_tunnels:
                md += "### IPSec Tunnels\n\n"
                md += "| Name | Gateway | Interface | Inner IP | Status |\n"
                md += "| --- | --- | --- | --- | --- |\n"
                for tn in ipsec_tunnels:
                    name = tn.get("@name", tn.get("name", "unknown"))
                    gw = tn.get("ike-gateway", tn.get("gateway", "N/A"))
                    iface = tn.get("interface", "N/A")
                    inner_ip = tn.get("inner-ip", "N/A")
                    status = tn.get("status", tn.get("state", "N/A"))
                    safe_iface = f"[[{iface.replace('/', '_')}]]" if iface != "N/A" and iface else "N/A"
                    md += f"| `{name}` | `{gw}` | {safe_iface} | `{inner_ip}` | `{status}` |\n"

            if not ike_gateways and not ipsec_tunnels:
                md += "*No active IKE Gateways or IPSec Tunnels found or VPN is unconfigured.*\n"

            md += f"\n```yaml\n{yaml_data[:2000]}\n```\n"
            md += f"\n---\n*Mapped: {self._timestamp()}*\n"
            self._push_to_drive("02_Interfaces", "VPNStatus.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] VPN parse failed: {e}")

    def _parse_nat_rules(self, yaml_data: str, args: dict):
        """Parses NAT rules from config xpath=.../rulebase/nat"""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            rules = self._find_entries(data, "entry")
            for rule in rules:
                name = rule.get("@name", "unnamed-nat")
                from_zones = self._flatten(rule.get("from", {}).get("member", []))
                to_zones = self._flatten(rule.get("to", {}).get("member", []))
                src = self._flatten(rule.get("source", {}).get("member", []))
                dst = self._flatten(rule.get("destination", {}).get("member", []))
                service = rule.get("service", "any")

                src_trans = rule.get("source-translation", {})
                dst_trans = rule.get("destination-translation", {})

                md = f"# NAT Rule: {name}\n\n"
                md += f"- **From Zones**: {', '.join(f'[[{z}]]' for z in from_zones)}\n"
                md += f"- **To Zones**: {', '.join(f'[[{z}]]' for z in to_zones)}\n"
                md += f"- **Source**: {', '.join(src)}\n"
                md += f"- **Destination**: {', '.join(dst)}\n"
                md += f"- **Service**: `{service}`\n"

                if src_trans:
                    md += f"- **Source Translation**: `{src_trans}`\n"
                if dst_trans:
                    md += f"- **Destination Translation**: `{dst_trans}`\n"

                md += f"\n---\n*Mapped: {self._timestamp()}*\n"
                safe_name = re.sub(r'[<>:"/\\|?*]', '_', name)
                self._push_to_drive("03_Rules", f"NAT_{safe_name}.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] NAT rule parse failed: {e}")

    def _parse_address_objects(self, yaml_data: str, args: dict):
        """Parses address objects from config xpath=.../address"""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            entries = self._find_entries(data, "entry")
            for entry in entries:
                name = entry.get("@name", "unknown")
                ip_netmask = entry.get("ip-netmask")
                ip_range = entry.get("ip-range")
                fqdn = entry.get("fqdn")
                desc = entry.get("description", "No description")

                md = f"# Address Object: {name}\n\n"
                md += f"- **Description**: {desc}\n"
                if ip_netmask:
                    md += f"- **IP/Netmask**: `{ip_netmask}`\n"
                elif ip_range:
                    md += f"- **IP Range**: `{ip_range}`\n"
                elif fqdn:
                    md += f"- **FQDN**: `{fqdn}`\n"

                md += f"\n---\n*Mapped: {self._timestamp()}*\n"
                safe_name = re.sub(r'[<>:"/\\|?*]', '_', name)
                self._push_to_drive("04_Hosts", f"Obj_{safe_name}.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] Address object parse failed: {e}")

    def _parse_config_interfaces(self, yaml_data: str, args: dict):
        """Parses interface configurations from xpath=.../interface"""
        try:
            data = yaml.safe_load(yaml_data)
            if not data:
                return
            entries = self._find_entries(data, "entry")
            for entry in entries:
                name = entry.get("@name", "unknown")
                comment = entry.get("comment", "")
                
                ip_addrs = []
                layer3 = entry.get("layer3", {})
                if isinstance(layer3, dict):
                    ip_list = layer3.get("ip", {})
                    if isinstance(ip_list, dict):
                        ip_addrs = self._flatten(ip_list.get("entry", []))
                    elif isinstance(ip_list, list):
                        ip_addrs = [i.get("@name", "") if isinstance(i, dict) else str(i) for i in ip_list]

                safe_name = name.replace("/", "_")
                
                md = f"# Interface Config: {name}\n\n"
                if comment:
                    md += f"- **Comment**: *{comment}*\n"
                if ip_addrs:
                    md += f"- **Configured IPs**:\n"
                    for ip in ip_addrs:
                        if ip:
                            md += f"  - `{ip}`\n"
                else:
                    md += "- **Type**: Non-Layer3 or unconfigured IP\n"

                md += f"\n---\n*Mapped: {self._timestamp()}*\n"
                self._push_to_drive("02_Interfaces", f"{safe_name}_config.md", md)
        except Exception as e:
            logger.error(f"[MAPPER] Config interface parse failed: {e}")

    # ══════════════════════════════════════════════════════════════
    # YAML TRAVERSAL HELPERS
    # ══════════════════════════════════════════════════════════════

    @staticmethod
    def _find_entries(data: dict, tag: str, _depth=0) -> list:
        """
        Recursively walks a nested dict/list to find all dicts
        that were keyed under `tag`. Handles the varied nesting
        that ToxicXmlSanitizer produces.
        """
        if _depth > 10:
            return []
        results = []
        if isinstance(data, dict):
            for key, val in data.items():
                if key == tag:
                    if isinstance(val, list):
                        results.extend(v for v in val if isinstance(v, dict))
                    elif isinstance(val, dict):
                        results.append(val)
                elif isinstance(val, (dict, list)):
                    results.extend(GoogleDriveObsidianMapper._find_entries(val, tag, _depth + 1))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    results.extend(GoogleDriveObsidianMapper._find_entries(item, tag, _depth + 1))
        return results

    @staticmethod
    def _flatten(val) -> list:
        """Normalizes a value that might be a string, list, or nested dict into a flat list."""
        if isinstance(val, str):
            return [val]
        if isinstance(val, list):
            return [str(v) for v in val]
        if isinstance(val, dict):
            # PAN-OS sometimes wraps members: {'member': ['a', 'b']}
            members = val.get("member", [])
            if isinstance(members, str):
                return [members]
            return [str(m) for m in members]
        return [str(val)] if val else ["any"]

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ══════════════════════════════════════════════════════════════
    # GOOGLE DRIVE I/O
    # ══════════════════════════════════════════════════════════════

    def _get_or_create_subfolder(self, folder_name: str) -> str:
        """Thread-safe subfolder lookup/creation."""
        with self._folder_cache_lock:
            if folder_name in self._folder_cache:
                return self._folder_cache[folder_name]

        try:
            query = (
                f"'{self.folder_id}' in parents and "
                f"name='{folder_name}' and "
                f"mimeType='application/vnd.google-apps.folder' and "
                f"trashed=false"
            )
            results = self._drive_service.files().list(
                q=query, spaces='drive', fields='files(id, name)'
            ).execute()
            items = results.get('files', [])

            if items:
                folder_id = items[0]['id']
            else:
                file_metadata = {
                    'name': folder_name,
                    'parents': [self.folder_id],
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                folder = self._drive_service.files().create(
                    body=file_metadata, fields='id'
                ).execute()
                folder_id = folder.get('id')

            with self._folder_cache_lock:
                self._folder_cache[folder_name] = folder_id
            return folder_id

        except Exception as e:
            logger.error(f"[MAPPER] Subfolder '{folder_name}' failed: {e}")
            return None

    def _push_to_drive(self, directory_name: str, file_name: str, content: str):
        """Creates or fully replaces a file in Drive."""
        subfolder_id = self._get_or_create_subfolder(directory_name)
        if not subfolder_id:
            return

        try:
            query = f"'{subfolder_id}' in parents and name='{file_name}' and trashed=false"
            results = self._drive_service.files().list(
                q=query, spaces='drive', fields='files(id)'
            ).execute()
            items = results.get('files', [])

            media = MediaIoBaseUpload(
                io.BytesIO(content.encode('utf-8')),
                mimetype='text/markdown', resumable=False
            )

            if items:
                self._drive_service.files().update(
                    fileId=items[0]['id'], media_body=media
                ).execute()
                logger.debug(f"[MAPPER] Updated: {directory_name}/{file_name}")
            else:
                self._drive_service.files().create(
                    body={'name': file_name, 'parents': [subfolder_id]},
                    media_body=media, fields='id'
                ).execute()
                logger.debug(f"[MAPPER] Created: {directory_name}/{file_name}")

        except Exception as e:
            logger.error(f"[MAPPER] Drive push failed for {file_name}: {e}")

    def _append_to_drive(self, directory_name: str, file_name: str,
                         new_content: str, header: str = ""):
        """
        Appends content to an existing file, or creates it with header + content.
        Solves the overwrite bug: threat logs and session snapshots accumulate.
        """
        subfolder_id = self._get_or_create_subfolder(directory_name)
        if not subfolder_id:
            return

        try:
            query = f"'{subfolder_id}' in parents and name='{file_name}' and trashed=false"
            results = self._drive_service.files().list(
                q=query, spaces='drive', fields='files(id)'
            ).execute()
            items = results.get('files', [])

            if items:
                # Download existing content, append, re-upload
                file_id = items[0]['id']
                existing = self._drive_service.files().get_media(fileId=file_id).execute()
                existing_text = existing.decode('utf-8') if isinstance(existing, bytes) else str(existing)
                combined = existing_text + "\n" + new_content
            else:
                file_id = None
                combined = header + new_content

            media = MediaIoBaseUpload(
                io.BytesIO(combined.encode('utf-8')),
                mimetype='text/markdown', resumable=False
            )

            if file_id:
                self._drive_service.files().update(
                    fileId=file_id, media_body=media
                ).execute()
                logger.debug(f"[MAPPER] Appended to: {directory_name}/{file_name}")
            else:
                self._drive_service.files().create(
                    body={'name': file_name, 'parents': [subfolder_id]},
                    media_body=media, fields='id'
                ).execute()
                logger.debug(f"[MAPPER] Created (with header): {directory_name}/{file_name}")

        except Exception as e:
            logger.error(f"[MAPPER] Drive append failed for {file_name}: {e}")
