"""
Cartographer — Deterministic Topology Mapper
Connects to the PAN-OS firewall to extract the absolute ground truth
(Interfaces, IP Subnets, Zones) and constructs a JSON Base Graph.
This prevents the LLM from hallucinating the physical network canvas.
"""

import xml.etree.ElementTree as ET
import json
import logging
from core.panos.client import PanOSClientPool

logger = logging.getLogger(__name__)

class Cartographer:
    """
    Deterministically maps PAN-OS network topologies.
    """

    def __init__(self, target_device: str = None):
        """
        Initializes the Cartographer using the established PanOSClientPool.
        """
        self.target_device = target_device

    def build_graph(self) -> str:
        """
        Executes the mapping process and returns a JSON string of the graph.
        """
        pool = PanOSClientPool.get_instance()
        client = pool.get_client(self.target_device)
        
        if not client:
            logger.error("[Cartographer] Failed to acquire PAN-OS client.")
            return json.dumps({"nodes": [], "edges": [], "error": "Client not found"})

        logger.info(f"[Cartographer] Mapping deterministic topology from {client.hostname}...")

        # 1. Fetch the raw running configuration using exact XML
        status, xml_response = client.execute_op("<show><config><running></running></config></show>")
        if status != 200:
            logger.error(f"[Cartographer] Failed to pull running config. HTTP {status}")
            return json.dumps({"nodes": [], "edges": [], "error": "Failed to pull config"})

        # 2. Parse the XML
        try:
            root = ET.fromstring(xml_response)
        except ET.ParseError as e:
            logger.error(f"[Cartographer] XML Parse error: {e}")
            return json.dumps({"nodes": [], "edges": [], "error": "Invalid XML"})

        # 3. Data Structures
        interfaces = {}  # e.g., 'ethernet1/1': ['10.0.0.1/24']
        zones = {}       # e.g., 'Trust': ['ethernet1/1']

        # 4. Extract Interfaces & IPs
        # Path: result/config/devices/entry/network/interface/ethernet/entry
        for eth in root.findall(".//interface/ethernet/entry"):
            intf_name = eth.get('name')
            ips = []
            for ip_entry in eth.findall(".//layer3/ip/entry"):
                ips.append(ip_entry.get('name'))
            
            if ips:
                interfaces[intf_name] = ips

        # 5. Extract Zones & Interface Mappings
        # Path: result/config/devices/entry/vsys/entry/zone/entry
        for zone in root.findall(".//zone/entry"):
            zone_name = zone.get('name')
            members = []
            for member in zone.findall(".//network/layer3/member"):
                if member.text:
                    members.append(member.text)
            
            if members:
                zones[zone_name] = members

        # 6. Build the JSON Base Graph
        nodes = []
        edges = []
        
        # Add a node for the Firewall itself
        nodes.append({"id": "firewall", "label": "PAN-OS Firewall", "type": "firewall"})

        for zone_name, intf_list in zones.items():
            # Add Zone Node
            zone_id = f"zone_{zone_name.lower()}"
            nodes.append({"id": zone_id, "label": f"Zone: {zone_name}", "type": "zone"})
            
            # Link Zone to Firewall
            edges.append({"source": "firewall", "target": zone_id, "label": "routes"})
            
            for intf in intf_list:
                # Add Subnet Node based on Interface IP
                ips = interfaces.get(intf, [])
                if ips:
                    subnet_label = f"{intf} ({', '.join(ips)})"
                    # Safe ID generation
                    safe_intf = intf.replace('/', '_').replace('.', '_')
                    subnet_id = f"subnet_{safe_intf}"
                    
                    nodes.append({"id": subnet_id, "label": subnet_label, "type": "subnet"})
                    # Link Subnet to Zone
                    edges.append({"source": zone_id, "target": subnet_id, "label": "contains"})

        # Return the deterministic graph
        graph_data = {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "source": client.hostname,
                "zones_mapped": len(zones),
                "interfaces_mapped": len(interfaces)
            }
        }
        
        logger.info(f"[Cartographer] Base Graph built: {len(zones)} zones, {len(interfaces)} interfaces.")
        return json.dumps(graph_data, indent=2)
