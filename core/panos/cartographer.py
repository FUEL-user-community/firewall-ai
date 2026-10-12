"""
Cartographer — Deterministic Topology Mapper & Nodal State Compiler
Connects to the PAN-OS firewall to extract the absolute ground truth
(Interfaces, IP Subnets, Zones, Management Plane Overlaps, Content Posture,
Licenses, and Admin Sessions) and constructs a structured Nodal Base Graph.
This prevents the LLM from hallucinating the network canvas or wandering in tool loops.
"""

import json
import logging
import re
import ipaddress
from datetime import datetime
import xml.etree.ElementTree as ET
from typing import Optional, Dict, List, Any

from core.panos.client import PanOSClientPool

logger = logging.getLogger(__name__)

__all__ = ["Cartographer"]


class Cartographer:
    """
    Deterministically compiles PAN-OS network topologies and operational posture
    into structured graph representations.
    """

    def __init__(self, target_device: Optional[str] = None):
        """
        Initializes the Cartographer targeting a specific firewall in PanOSClientPool.
        """
        self.target_device = target_device

    def _fetch_system_info(self, client: Any) -> Dict[str, Any]:
        """
        Queries operational system information via XML API fail-softly.
        """
        try:
            status, xml_out = client.execute_op("<show><system><info></info></system></show>")
            if status != 200 or not xml_out:
                return {}
            root = ET.fromstring(xml_out)
            sys_elem = root.find(".//system")
            if sys_elem is None:
                return {}
            info: Dict[str, Any] = {}
            for child in sys_elem:
                if child.text and child.text.strip():
                    info[child.tag] = child.text.strip()
            return info
        except Exception as e:
            logger.debug(f"[Cartographer] Telemetry system info query skipped or failed: {e}")
            return {}

    def _fetch_license_info(self, client: Any) -> List[Dict[str, Any]]:
        """
        Queries active and expired license state via XML API fail-softly.
        """
        try:
            status, xml_out = client.execute_op("<request><license><info></info></license></request>")
            if status != 200 or not xml_out:
                return []
            root = ET.fromstring(xml_out)
            licenses_elem = root.find(".//licenses")
            if licenses_elem is None:
                return []
            licenses = []
            for entry in licenses_elem.findall("entry"):
                feature = entry.findtext("feature")
                if not feature:
                    continue
                expires = entry.findtext("expires")
                expired_text = (entry.findtext("expired") or "").strip().lower()
                is_expired = expired_text == "yes"
                status_note = entry.findtext("vm-license-status")
                licenses.append({
                    "feature": feature,
                    "expires": expires,
                    "expired": is_expired,
                    "status_note": status_note
                })
            return licenses
        except Exception as e:
            logger.debug(f"[Cartographer] License query skipped or failed: {e}")
            return []

    def _fetch_admin_sessions(self, client: Any) -> List[Dict[str, Any]]:
        """
        Queries active administrative sessions via XML API fail-softly.
        """
        try:
            status, xml_out = client.execute_op("<show><admins></admins></show>")
            if status != 200 or not xml_out:
                return []
            root = ET.fromstring(xml_out)
            admins_elem = root.find(".//admins")
            if admins_elem is None:
                return []
            admins = []
            for entry in admins_elem.findall("entry"):
                admin_user = entry.findtext("admin")
                from_ip = entry.findtext("from")
                access_type = entry.findtext("type")
                idle_for = entry.findtext("idle-for")
                session_expiry = entry.findtext("session-expiry")
                if admin_user:
                    admins.append({
                        "admin": admin_user,
                        "from": from_ip,
                        "type": access_type,
                        "idle_for": idle_for,
                        "session_expiry": session_expiry
                    })
            return admins
        except Exception as e:
            logger.debug(f"[Cartographer] Admin sessions query skipped or failed: {e}")
            return []

    @staticmethod
    def _extract_mgmt_profiles(root: ET.Element) -> Dict[str, List[str]]:
        """
        Extracts interface management profile definitions and enabled services.
        Path: /config/devices/entry/network/profiles/interface-management-profile/entry
        """
        profiles: Dict[str, List[str]] = {}
        for entry in root.findall(".//interface-management-profile/entry"):
            prof_name = entry.get("name")
            if not prof_name:
                continue
            services = []
            for child in entry:
                if child.tag != "name" and child.text and child.text.strip().lower() == "yes":
                    services.append(child.tag)
            profiles[prof_name] = services
        return profiles

    @staticmethod
    def _calculate_stale_days(device_time_str: Optional[str], release_date_str: Optional[str]) -> Optional[int]:
        """
        Calculates content staleness in days comparing release date with device clock.
        """
        if not release_date_str:
            return None
        clean_rel = re.sub(r"\s+[A-Z]{3,4}$", "", release_date_str.strip())
        rel_dt = None
        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
            try:
                rel_dt = datetime.strptime(clean_rel, fmt)
                break
            except ValueError:
                pass
        if not rel_dt:
            return None

        dev_dt = None
        if device_time_str:
            clean_dev = device_time_str.strip()
            for fmt in ("%a %b %d %H:%M:%S %Y", "%Y/%m/%d %H:%M:%S"):
                try:
                    dev_dt = datetime.strptime(clean_dev, fmt)
                    break
                except ValueError:
                    pass
        if not dev_dt:
            dev_dt = datetime.now()

        diff = dev_dt - rel_dt
        return max(0, diff.days)

    @staticmethod
    def _is_version_eol(version_str: Optional[str]) -> bool:
        """
        Evaluates if the PAN-OS release is past official End-of-Life (<= 10.1).
        """
        if not version_str:
            return False
        m = re.match(r"^(\d+)\.(\d+)", version_str.strip())
        if not m:
            return False
        major, minor = int(m.group(1)), int(m.group(2))
        if major < 10:
            return True
        if major == 10 and minor <= 1:
            return True
        return False

    def build_graph(self) -> str:
        """
        Executes the deterministic compilation process and returns a JSON string of the graph.
        """
        # Safe client acquisition handling ValueError and KeyError (H2)
        try:
            pool = PanOSClientPool.get_instance()
            client = pool.get_client(self.target_device)
        except Exception as e:
            logger.error(f"[Cartographer] Failed to acquire PAN-OS client: {e}", exc_info=True)
            return json.dumps({"nodes": [], "edges": [], "error": f"Client acquisition failed: {str(e)}"}, indent=2)

        if not client:
            logger.error("[Cartographer] Failed to acquire PAN-OS client (None returned).")
            return json.dumps({"nodes": [], "edges": [], "error": "Client not found"}, indent=2)

        device_name = getattr(client, "label", None) or getattr(client, "device_name", None) or "default"
        logger.info(f"[Cartographer] Mapping deterministic topology from device '{device_name}'...")

        # 1. Fetch the raw running configuration using operational XML
        try:
            status, xml_response = client.execute_op("<show><config><running></running></config></show>")
        except Exception as e:
            logger.error(f"[Cartographer] Error executing config pull on '{device_name}': {e}", exc_info=True)
            return json.dumps({"nodes": [], "edges": [], "error": f"Connection error: {str(e)}"}, indent=2)

        if status != 200 or not xml_response:
            logger.error(f"[Cartographer] Failed to pull running config from '{device_name}'. HTTP {status}")
            return json.dumps({"nodes": [], "edges": [], "error": f"Failed to pull config (HTTP {status})"}, indent=2)

        # 2. Parse the config XML response
        try:
            root = ET.fromstring(xml_response)
        except (ET.ParseError, Exception) as e:
            logger.error(f"[Cartographer] XML Parse error on config from '{device_name}': {e}", exc_info=True)
            return json.dumps({"nodes": [], "edges": [], "error": f"Invalid XML: {str(e)}"}, indent=2)

        # 3. Pull operational telemetry fail-softly
        sys_info = self._fetch_system_info(client)
        license_info = self._fetch_license_info(client)
        admin_sessions = self._fetch_admin_sessions(client)
        mgmt_profiles_catalog = self._extract_mgmt_profiles(root)

        # 4. Data Structures
        interfaces: Dict[str, List[str]] = {}
        interface_mgmt_profiles: Dict[str, str] = {}
        zones: Dict[str, List[str]] = {}

        # 5. Extract Interfaces & IPs across all PAN-OS interface families
        intf_selectors = [
            (".//interface/ethernet/entry", ".//layer3/ip/entry"),
            (".//interface/ethernet/entry/layer3/units/entry", ".//ip/entry"),
            (".//interface/loopback/units/entry", ".//ip/entry"),
            (".//interface/tunnel/units/entry", ".//ip/entry"),
            (".//interface/vlan/units/entry", ".//ip/entry"),
        ]

        for base_xpath, ip_xpath in intf_selectors:
            for intf_entry in root.findall(base_xpath):
                intf_name = intf_entry.get('name')
                if not intf_name:
                    continue
                ips = []
                for ip_entry in intf_entry.findall(ip_xpath):
                    ip_val = ip_entry.get('name')
                    if ip_val and ip_val.strip():
                        ips.append(ip_val.strip())

                if ips:
                    if intf_name in interfaces:
                        for ip in ips:
                            if ip not in interfaces[intf_name]:
                                interfaces[intf_name].append(ip)
                    else:
                        interfaces[intf_name] = list(dict.fromkeys(ips))

                # Check for bound interface management profile
                prof_elem = intf_entry.find(".//interface-management-profile")
                if prof_elem is not None and prof_elem.text and prof_elem.text.strip():
                    interface_mgmt_profiles[intf_name] = prof_elem.text.strip()

        # 6. Extract Zones & Interface Mappings
        for zone in root.findall(".//zone/entry"):
            zone_name = zone.get('name')
            if not zone_name:
                continue
            members = []
            for member in zone.findall(".//network/layer3/member"):
                if member.text and member.text.strip():
                    clean_member = member.text.strip()
                    if clean_member not in members:
                        members.append(clean_member)

            if members:
                zones[zone_name] = members

        # 7. Build the JSON Base Graph with Node & Edge Deduplication
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_node_ids = set()
        seen_edges = set()

        # Add root node for the Firewall itself
        fw_node_id = "firewall"
        fw_label = getattr(client, "label", None) or "PAN-OS Firewall"
        nodes.append({"id": fw_node_id, "label": fw_label, "type": "firewall"})
        seen_node_ids.add(fw_node_id)

        # Add Zone and Subnet nodes
        for zone_name, intf_list in zones.items():
            safe_zone = zone_name.lower().replace(' ', '_').replace('-', '_')
            zone_id = f"zone_{safe_zone}"
            if zone_id not in seen_node_ids:
                nodes.append({"id": zone_id, "label": f"Zone: {zone_name}", "type": "zone"})
                seen_node_ids.add(zone_id)

            edge_key = (fw_node_id, zone_id, "routes")
            if edge_key not in seen_edges:
                edges.append({"source": fw_node_id, "target": zone_id, "label": "routes"})
                seen_edges.add(edge_key)

            for intf in intf_list:
                ips = interfaces.get(intf, [])
                if ips:
                    subnet_label = f"{intf} ({', '.join(ips)})"
                    safe_intf = intf.replace('/', '_').replace('.', '_').replace(':', '_')
                    subnet_id = f"subnet_{safe_intf}"

                    if subnet_id not in seen_node_ids:
                        prof_name = interface_mgmt_profiles.get(intf)
                        prof_services = mgmt_profiles_catalog.get(prof_name, []) if prof_name else []
                        node_entry: Dict[str, Any] = {
                            "id": subnet_id,
                            "label": subnet_label,
                            "type": "subnet",
                            "interface": intf,
                            "ips": ips
                        }
                        if prof_name:
                            node_entry["mgmt_profile"] = prof_name
                            node_entry["mgmt_services"] = prof_services
                        nodes.append(node_entry)
                        seen_node_ids.add(subnet_id)

                    sub_edge_key = (zone_id, subnet_id, "contains")
                    if sub_edge_key not in seen_edges:
                        edges.append({"source": zone_id, "target": subnet_id, "label": "contains"})
                        seen_edges.add(sub_edge_key)

        # 8. Management Interface & Overlap Detection
        mgmt_ip = sys_info.get("ip-address")
        mgmt_netmask = sys_info.get("netmask")
        mgmt_gateway = sys_info.get("default-gateway")
        mgmt_net = None
        overlap_interfaces: List[str] = []

        if mgmt_ip and mgmt_netmask:
            try:
                mgmt_net = ipaddress.ip_network(f"{mgmt_ip}/{mgmt_netmask}", strict=False)
            except ValueError:
                pass

        if mgmt_ip:
            mgt_node_id = "interface_mgmt"
            cidr_suffix = f"/{mgmt_net.prefixlen}" if mgmt_net else ""
            mgt_label = f"MGT Interface ({mgmt_ip}{cidr_suffix})"
            if mgt_node_id not in seen_node_ids:
                nodes.append({
                    "id": mgt_node_id,
                    "label": mgt_label,
                    "type": "management_interface",
                    "ip": mgmt_ip,
                    "netmask": mgmt_netmask,
                    "gateway": mgmt_gateway
                })
                seen_node_ids.add(mgt_node_id)

            mgt_edge_key = (fw_node_id, mgt_node_id, "managed_by")
            if mgt_edge_key not in seen_edges:
                edges.append({"source": fw_node_id, "target": mgt_node_id, "label": "managed_by"})
                seen_edges.add(mgt_edge_key)

            # Check overlap between management subnet and dataplane interfaces
            if mgmt_net:
                for intf_name, ips in interfaces.items():
                    for ip_cidr in ips:
                        try:
                            iface = ipaddress.ip_interface(ip_cidr)
                            if iface.ip in mgmt_net:
                                overlap_interfaces.append(intf_name)
                                safe_intf = intf_name.replace('/', '_').replace('.', '_').replace(':', '_')
                                sub_id = f"subnet_{safe_intf}"
                                if sub_id in seen_node_ids:
                                    overlap_edge_key = (mgt_node_id, sub_id, "overlaps_subnet")
                                    if overlap_edge_key not in seen_edges:
                                        edges.append({
                                            "source": mgt_node_id,
                                            "target": sub_id,
                                            "label": "overlaps_subnet",
                                            "warning": f"MGT plane ({mgmt_ip}) shares broadcast domain with {intf_name} ({ip_cidr})"
                                        })
                                        seen_edges.add(overlap_edge_key)
                        except ValueError:
                            continue

        # 9. Expired License Nodes
        for lic in license_info:
            if lic.get("expired"):
                feature = lic.get("feature", "Unknown")
                expires = lic.get("expires", "Unknown")
                safe_feat = re.sub(r'[^a-zA-Z0-9_]', '_', feature.lower())
                lic_node_id = f"lic_{safe_feat}"
                if lic_node_id not in seen_node_ids:
                    nodes.append({
                        "id": lic_node_id,
                        "label": f"EXPIRED: {feature} (expired {expires})",
                        "type": "expired_license",
                        "feature": feature,
                        "expires": expires,
                        "status_note": lic.get("status_note")
                    })
                    seen_node_ids.add(lic_node_id)

                lic_edge_key = (fw_node_id, lic_node_id, "license_expired")
                if lic_edge_key not in seen_edges:
                    edges.append({"source": fw_node_id, "target": lic_node_id, "label": "license_expired"})
                    seen_edges.add(lic_edge_key)

        # 10. Active Admin Session Nodes
        for admin in admin_sessions:
            admin_user = admin.get("admin", "admin")
            client_ip = admin.get("from", "unknown")
            access_type = admin.get("type", "Web")
            safe_user = re.sub(r'[^a-zA-Z0-9_]', '_', admin_user.lower())
            safe_ip = re.sub(r'[^a-zA-Z0-9_]', '_', client_ip)
            admin_node_id = f"admin_{safe_user}_{safe_ip}"
            if admin_node_id not in seen_node_ids:
                nodes.append({
                    "id": admin_node_id,
                    "label": f"Active Admin: {admin_user} ({access_type} from {client_ip})",
                    "type": "admin_session",
                    "user": admin_user,
                    "from": client_ip,
                    "access_type": access_type,
                    "idle_for": admin.get("idle_for"),
                    "session_expiry": admin.get("session_expiry")
                })
                seen_node_ids.add(admin_node_id)

            admin_edge_key = (fw_node_id, admin_node_id, "active_admin")
            if admin_edge_key not in seen_edges:
                edges.append({"source": fw_node_id, "target": admin_node_id, "label": "active_admin"})
                seen_edges.add(admin_edge_key)

        # 11. Compile Posture & Metadata
        sw_version = sys_info.get("sw-version")
        threat_rel_date = sys_info.get("threat-release-date")
        dev_time = sys_info.get("time")
        stale_days = self._calculate_stale_days(dev_time, threat_rel_date)
        is_threat_stale = stale_days is not None and stale_days > 7
        is_eol = self._is_version_eol(sw_version)

        expired_lic_names = [l["feature"] for l in license_info if l.get("expired")]
        active_lic_names = [l["feature"] for l in license_info if not l.get("expired")]

        posture = {
            "panos_version": sw_version,
            "model": sys_info.get("model"),
            "hostname": sys_info.get("hostname") or sys_info.get("devicename"),
            "is_eol": is_eol,
            "threat_version": sys_info.get("threat-version"),
            "threat_release_date": threat_rel_date,
            "threat_stale_days": stale_days,
            "is_threat_stale": is_threat_stale,
            "expired_licenses": expired_lic_names,
            "active_licenses": active_lic_names,
            "mgmt_ip": mgmt_ip,
            "mgmt_dataplane_overlap": len(overlap_interfaces) > 0,
            "overlap_interfaces": list(dict.fromkeys(overlap_interfaces)),
            "active_admin_sessions": admin_sessions
        }

        source_label = getattr(client, "label", None) or getattr(client, "device_name", None) or "panos-firewall"
        graph_data = {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": source_label,
                "zones_mapped": len(zones),
                "interfaces_mapped": len(interfaces),
                "posture": posture
            }
        }

        logger.info(
            f"[Cartographer] Base Graph compiled: {len(zones)} zones, {len(interfaces)} interfaces, "
            f"{len(nodes)} nodes, {len(edges)} edges."
        )
        return json.dumps(graph_data, indent=2)
