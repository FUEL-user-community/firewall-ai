"""
Cartographer — Deterministic Topology Mapper
Connects to the PAN-OS firewall to extract the absolute ground truth
(Interfaces, IP Subnets, Zones) and constructs a JSON Base Graph.
This prevents the LLM from hallucinating the physical network canvas.
"""

import json
import logging
import xml.etree.ElementTree as ET
from typing import Optional, Dict, List, Any

from core.panos.client import PanOSClientPool

logger = logging.getLogger(__name__)

__all__ = ["Cartographer"]


class Cartographer:
    """
    Deterministically maps PAN-OS network topologies into graph representations.
    """

    def __init__(self, target_device: Optional[str] = None):
        """
        Initializes the Cartographer targeting a specific firewall in PanOSClientPool.
        """
        self.target_device = target_device

    def build_graph(self) -> str:
        """
        Executes the mapping process and returns a JSON string of the graph.
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

        # 1. Fetch the raw running configuration using exact operational XML
        try:
            status, xml_response = client.execute_op("<show><config><running></running></config></show>")
        except Exception as e:
            logger.error(f"[Cartographer] Error executing config pull on '{device_name}': {e}", exc_info=True)
            return json.dumps({"nodes": [], "edges": [], "error": f"Connection error: {str(e)}"}, indent=2)

        if status != 200 or not xml_response:
            logger.error(f"[Cartographer] Failed to pull running config from '{device_name}'. HTTP {status}")
            return json.dumps({"nodes": [], "edges": [], "error": f"Failed to pull config (HTTP {status})"}, indent=2)

        # 2. Parse the XML response
        try:
            root = ET.fromstring(xml_response)
        except (ET.ParseError, Exception) as e:
            logger.error(f"[Cartographer] XML Parse error on config from '{device_name}': {e}", exc_info=True)
            return json.dumps({"nodes": [], "edges": [], "error": f"Invalid XML: {str(e)}"}, indent=2)

        # 3. Data Structures
        interfaces: Dict[str, List[str]] = {}  # e.g., 'ethernet1/1': ['10.0.0.1/24']
        zones: Dict[str, List[str]] = {}       # e.g., 'Trust': ['ethernet1/1']

        # 4. Extract Interfaces & IPs across all PAN-OS interface families (M1)
        # Covers: physical ethernet, subinterfaces (units), loopback, tunnel, vlan
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

        # 5. Extract Zones & Interface Mappings
        # Path: result/config/devices/entry/vsys/entry/zone/entry
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

        # 6. Build the JSON Base Graph with Node & Edge Deduplication (Self-Audit 1)
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_node_ids = set()
        seen_edges = set()

        # Add a root node for the Firewall itself
        fw_node_id = "firewall"
        fw_label = getattr(client, "label", None) or "PAN-OS Firewall"
        nodes.append({"id": fw_node_id, "label": fw_label, "type": "firewall"})
        seen_node_ids.add(fw_node_id)

        for zone_name, intf_list in zones.items():
            # Add Zone Node if not already present
            safe_zone = zone_name.lower().replace(' ', '_').replace('-', '_')
            zone_id = f"zone_{safe_zone}"
            if zone_id not in seen_node_ids:
                nodes.append({"id": zone_id, "label": f"Zone: {zone_name}", "type": "zone"})
                seen_node_ids.add(zone_id)

            # Link Zone to Firewall
            edge_key = (fw_node_id, zone_id, "routes")
            if edge_key not in seen_edges:
                edges.append({"source": fw_node_id, "target": zone_id, "label": "routes"})
                seen_edges.add(edge_key)

            for intf in intf_list:
                # Add Subnet Node based on Interface IP
                ips = interfaces.get(intf, [])
                if ips:
                    subnet_label = f"{intf} ({', '.join(ips)})"
                    # Safe ID generation
                    safe_intf = intf.replace('/', '_').replace('.', '_').replace(':', '_')
                    subnet_id = f"subnet_{safe_intf}"

                    if subnet_id not in seen_node_ids:
                        nodes.append({"id": subnet_id, "label": subnet_label, "type": "subnet"})
                        seen_node_ids.add(subnet_id)

                    # Link Subnet to Zone
                    sub_edge_key = (zone_id, subnet_id, "contains")
                    if sub_edge_key not in seen_edges:
                        edges.append({"source": zone_id, "target": subnet_id, "label": "contains"})
                        seen_edges.add(sub_edge_key)

        # Return the deterministic graph with anonymized metadata (H1)
        source_label = getattr(client, "label", None) or getattr(client, "device_name", None) or "panos-firewall"
        graph_data = {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": source_label,
                "zones_mapped": len(zones),
                "interfaces_mapped": len(interfaces)
            }
        }

        logger.info(f"[Cartographer] Base Graph built: {len(zones)} zones, {len(interfaces)} interfaces.")
        return json.dumps(graph_data, indent=2)
