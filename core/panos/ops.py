"""
PAN-OS Operational Commands Module
Extracted from pan_tools.py — uses PanOSClientPool for multi-firewall support.

Contains: execute_operational_command, test_security_policy, test_routing_fib,
          test_nat_policy, test_pbf_policy, test_packet_walk,
          get_telemetry_snapshot, get_device_inventory,
          apply_dynamic_tag, capture_pcap.
"""

import re
import time
import yaml
import logging
import ipaddress
import threading
from typing import Optional
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring
from xml.sax.saxutils import escape

from core.panos.client import PanOSClientPool
from core.panos.metrics import MetricsLogger
from core.panos.interceptors import CommandRouter, CommandType
from core.utils.xml_to_yaml import ToxicXmlSanitizer
from core.safety.command_filter import CommandFilter

__all__ = [
    "execute_operational_command",
    "test_security_policy",
    "test_routing_fib",
    "test_nat_policy",
    "test_pbf_policy",
    "test_packet_walk",
    "get_telemetry_snapshot",
    "get_device_inventory",
    "apply_dynamic_tag",
    "capture_pcap",
    "reset",
]

logger = logging.getLogger(__name__)

# Module-level singletons (thread-safe lazy loaded)
_metrics: Optional[MetricsLogger] = None
_router: Optional[CommandRouter] = None
_init_lock = threading.Lock()


def _get_pool() -> PanOSClientPool:
    """Get the connection pool singleton."""
    return PanOSClientPool.get_instance()


def _get_metrics() -> MetricsLogger:
    """Get or create MetricsLogger singleton with thread safety (H3)."""
    global _metrics
    if _metrics is None:
        with _init_lock:
            if _metrics is None:
                _metrics = MetricsLogger.get_instance()
    return _metrics


def _get_router() -> CommandRouter:
    """Get or create CommandRouter singleton with thread safety (H3)."""
    global _router
    if _router is None:
        with _init_lock:
            if _router is None:
                _router = CommandRouter()
    return _router


def reset() -> None:
    """Reset module-level singletons for clean test isolation."""
    global _metrics, _router
    with _init_lock:
        _metrics = None
        _router = None


def get_device_inventory() -> str:
    """
    Returns the list of managed firewalls and their status.

    Use this when asked: "What firewalls do we have?", "List managed devices",
    "Which firewalls are available?", "Show fleet inventory",
    "What devices can I query?".

    Call this FIRST when the user doesn't specify which firewall to target.
    """
    try:
        pool = _get_pool()
        devices = pool.get_device_info()
    except Exception as e:
        logger.error(f"[Inventory] Failed to load devices: {e}", exc_info=True)
        return f"ERROR: [get_device_inventory] Failed to query device inventory: {str(e)}"

    if not devices:
        return "No firewalls registered. Add devices to config/devices.yaml."

    output = ["--- MANAGED FIREWALL INVENTORY ---"]
    for d in devices:
        status = "CONNECTED" if d.get('connected') else "AVAILABLE"
        default = " (DEFAULT)" if d.get('default') else ""
        output.append(
            f"  {d.get('name', 'unknown')}: {d.get('label', '')} @ {d.get('ip', 'unknown')} [{status}]{default}"
        )
    output.append(f"\nTotal: {len(devices)} device(s)")
    output.append("Use target_device argument to specify which firewall to query.")
    return "\n".join(output)


def test_security_policy(source: str = None, destination: str = None, port: str = "443",
                         protocol: str = "6", from_zone: Optional[str] = None,
                         to_zone: Optional[str] = None, application: Optional[str] = None,
                         target_device: str = None) -> str:
    """
    Simulate a packet against the firewall's Security Policy rulebase.
    Returns which rule would ALLOW or DENY the traffic without sending real packets.

    Use this when asked: "Can X reach Y?", "Is traffic allowed?", "What policy matches?",
    "If I have a rule with X, will traffic be allowed?", "Will port 8080 be blocked?",
    "Would traffic on port 443 be denied?", "What happens if I allow web-browsing?"

    Args:
        source (str): Source IP address (e.g., '10.0.0.5').
        destination (str): Destination IP address (e.g., '192.168.1.1').
        port (str): Destination port number (e.g., '443', '53', '80').
        protocol (str): IP protocol number. Default '6' (TCP). Use '17' for UDP, '1' for ICMP.
        from_zone (str): Ingress security zone (e.g., 'inside', 'trust'). Optional.
        to_zone (str): Egress security zone (e.g., 'outside', 'dmz'). Optional.
        application (str): Application name (e.g., 'web-browsing', 'ssl'). Optional.
        target_device (str): Device name from fleet inventory (e.g., 'fw-hq'). Uses default if not specified.
    """
    if not source or not str(source).strip():
        return "ERROR: [test_security_policy] source IP address is required."
    if not destination or not str(destination).strip():
        return "ERROR: [test_security_policy] destination IP address is required."
    source_clean = source.strip()
    destination_clean = destination.strip()
    port_clean = str(port).strip() if port else "443"

    for ip_val, label in ((source_clean, "source"), (destination_clean, "destination")):
        try:
            ipaddress.ip_address(ip_val)
        except ValueError:
            return f"ERROR: [test_security_policy] Invalid {label} IP address '{ip_val}'."

    proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
    proto_raw = str(protocol).strip().lower() if protocol else "6"
    protocol_clean = proto_map.get(proto_raw, proto_raw)
    if not re.match(r"^\d+$", protocol_clean) or not (1 <= int(protocol_clean) <= 255):
        return f"ERROR: [test_security_policy] Invalid protocol '{protocol}'. Must be 1-255 or 'tcp'/'udp'/'icmp'."

    # Input validation (H1)
    if not re.match(r'^\d+$', port_clean) or not (1 <= int(port_clean) <= 65535):
        return f"ERROR: [test_security_policy] Invalid port number '{port_clean}'. Must be 1-65535."

    root = Element("test")
    spm = SubElement(root, "security-policy-match")
    if from_zone and str(from_zone).strip():
        SubElement(spm, "from").text = str(from_zone).strip()
    if to_zone and str(to_zone).strip():
        SubElement(spm, "to").text = str(to_zone).strip()
    SubElement(spm, "source").text = source_clean
    SubElement(spm, "destination").text = destination_clean
    SubElement(spm, "protocol").text = protocol_clean
    SubElement(spm, "destination-port").text = port_clean
    if application and str(application).strip():
        SubElement(spm, "application").text = str(application).strip()
    xml_cmd = tostring(root, encoding="unicode")

    logger.info(f"[PolicyMath] Testing: {source_clean} → {destination_clean}:{port_clean}/proto={protocol_clean} on {target_device or 'default'}")

    try:
        client = _get_pool().get_client(target_device)
        status, result = client.execute_op(xml_cmd)

        if status == 200:
            sanitizer = ToxicXmlSanitizer()
            try:
                yaml_output, stats = sanitizer.convert_string(result, return_stats=True)
                return yaml_output
            except Exception as e:
                logger.error(f"[PolicyMath] XML→YAML conversion failed: {e}")
                return f"Raw Policy Result: {result[:1000]}"
        else:
            return f"ERROR: [test_security_policy] PAN-OS returned HTTP {status}. {result[:500]}. NO POLICY DATA WAS RETRIEVED."
    except Exception as e:
        return f"ERROR: [test_security_policy] failed. Reason: {str(e)}. NO POLICY DATA WAS RETRIEVED."


def _discover_virtual_router(client, failed_vr: Optional[str] = None) -> Optional[str]:
    """Auto-discovers the active virtual router name from the firewall running config."""
    cached = client._cached_vr if hasattr(client, "_cached_vr") else None
    if cached and cached.lower() != "default" and (not failed_vr or cached != failed_vr):
        return cached

    # Attempt 1: Fetch virtual-router config via sealed execute_get
    try:
        if hasattr(client, "execute_get"):
            _, res_xml = client.execute_get(xpath="/config/devices/entry/network/virtual-router")
        elif hasattr(client, "fw") and hasattr(client.fw, "xapi"):
            client.fw.xapi.get(xpath="/config/devices/entry/network/virtual-router")
            res_xml = client.fw.xapi.xml_result()
        else:
            res_xml = None

        if res_xml is not None:
            root = res_xml if hasattr(res_xml, "findall") else fromstring(str(res_xml))
            for entry in root.findall(".//entry"):
                name = entry.get("name")
                if name and name.strip() and (not failed_vr or name.strip() != failed_vr):
                    client._cached_vr = name.strip()
                    cur_vr = client.virtual_router if hasattr(client, "virtual_router") else None
                    if cur_vr in (None, "default"):
                        client.virtual_router = client._cached_vr
                    return client._cached_vr
    except Exception as e:
        logger.debug(f"[PolicyMath] VR auto-discovery via config failed: {e}")

    # Attempt 2: Operational query show routing route summary
    try:
        status, res_xml = client.execute_op("show routing route summary")
        if status == 200 and res_xml:
            root = fromstring(res_xml)
            for entry in root.findall(".//entry"):
                name = entry.get("name") or (entry.findtext("name") if entry.find("name") is not None else None)
                if name and name.strip() and (not failed_vr or name.strip() != failed_vr):
                    client._cached_vr = name.strip()
                    cur_vr = client.virtual_router if hasattr(client, "virtual_router") else None
                    if cur_vr in (None, "default"):
                        client.virtual_router = client._cached_vr
                    return client._cached_vr
    except Exception as e:
        logger.debug(f"[PolicyMath] VR auto-discovery via op failed: {e}")

    return None


def test_routing_fib(ip: str = None, virtual_router: str = "default", target_device: str = None) -> str:
    """
    Simulate a routing lookup on the firewall to see which interface and next-hop
    will be used to reach a specific IP address.

    Use this when asked: "How does the firewall reach X?", "Is there a route to Y?",
    "Which interface is used for IP Z?", "Verify return route".
    
    Args:
        ip (str): The IP address to test routing for.
        virtual_router (str): The virtual router name (configured in devices.yaml or auto-resolved).
        target_device (str): Device name from fleet inventory.
    """
    if not ip or not str(ip).strip():
        return "ERROR: [test_routing_fib] IP address cannot be empty."
    ip_clean = ip.strip()
    if not ip_clean:
        return "ERROR: [test_routing_fib] IP address cannot be empty."

    try:
        client = _get_pool().get_client(target_device)

        # Priority: explicit non-default argument -> devices.yaml virtual_router -> cached VR -> "default"
        raw_vr = (client.virtual_router if hasattr(client, "virtual_router") else None) or (
            client._cached_vr if hasattr(client, "_cached_vr") else None
        )
        configured_vr = raw_vr if isinstance(raw_vr, str) else None
        if virtual_router and isinstance(virtual_router, str) and virtual_router.strip() and virtual_router.strip().lower() != "default":
            vr_clean = virtual_router.strip()
        elif configured_vr and configured_vr.strip():
            vr_clean = configured_vr.strip()
        else:
            vr_clean = "default"

        root = Element("test")
        routing = SubElement(root, "routing")
        fib = SubElement(routing, "fib-lookup")
        SubElement(fib, "virtual-router").text = vr_clean
        SubElement(fib, "ip").text = ip_clean
        xml_cmd = tostring(root, encoding="unicode")

        logger.info(f"[PolicyMath] Testing routing FIB: IP={ip_clean} VR={vr_clean} on {target_device or 'default'}")
        status, result = client.execute_op(xml_cmd)

        # Auto-heal: If VR was rejected by PAN-OS as invalid, discover the real VR and re-execute
        if status != 200 and ("invalid virtual-router" in result.lower() or "virtual-router is invalid" in result.lower()):
            discovered_vr = _discover_virtual_router(client, failed_vr=vr_clean)
            if discovered_vr and discovered_vr != vr_clean:
                logger.info(f"[PolicyMath] Auto-resolved virtual-router '{discovered_vr}' (was '{vr_clean}')")
                retry_root = Element("test")
                retry_routing = SubElement(retry_root, "routing")
                retry_fib = SubElement(retry_routing, "fib-lookup")
                SubElement(retry_fib, "virtual-router").text = discovered_vr
                SubElement(retry_fib, "ip").text = ip_clean
                retry_cmd = tostring(retry_root, encoding="unicode")
                status, result = client.execute_op(retry_cmd)

        if status == 200:
            sanitizer = ToxicXmlSanitizer()
            try:
                yaml_output, stats = sanitizer.convert_string(result, return_stats=True)
                return yaml_output
            except Exception as e:
                logger.error(f"[PolicyMath] XML→YAML conversion failed: {e}")
                return f"Raw Routing Result: {result[:1000]}"
        else:
            return f"ERROR: [test_routing_fib] PAN-OS returned HTTP {status}. {result[:500]}. NO ROUTE DATA WAS RETRIEVED."
    except Exception as e:
        return f"ERROR: [test_routing_fib] failed. Reason: {str(e)}. NO ROUTE DATA WAS RETRIEVED."


def test_pbf_policy(
    source: str = None,
    destination: str = None,
    destination_port: str = "443",
    protocol: str = "6",
    from_zone: Optional[str] = None,
    application: Optional[str] = None,
    target_device: Optional[str] = None
) -> str:
    """
    Simulates a packet against the Policy-Based Forwarding (PBF) rulebase.
    PBF rules evaluate BEFORE the Virtual Router FIB lookup. If a PBF rule matches,
    it overrides standard routing table forwarding and forces egress via a specific
    interface or next-hop.

    Use this when:
    - Verifying SD-WAN or multi-ISP egress paths
    - Diagnosing unexpected egress interfaces or asymmetric return drops
    - Determining if traffic bypasses the default FIB route table

    Args:
        source (str): Source IP address (e.g., '10.0.1.5'). Required.
        destination (str): Destination IP address (e.g., '172.16.20.10'). Required.
        destination_port (int or str): Destination port (e.g., 443, 80). Default: 443.
        protocol (int or str): IP protocol number (6=TCP, 17=UDP). Default: 6.
        from_zone (str): Ingress security zone (e.g., 'trust', 'lan'). Optional.
        application (str): App-ID name (e.g., 'web-browsing', 'ssl'). Optional.
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    if not source or not str(source).strip():
        return "ERROR: [test_pbf_policy] source IP address is required."
    if not destination or not str(destination).strip():
        return "ERROR: [test_pbf_policy] destination IP address is required."

    source_clean = source.strip()
    destination_clean = destination.strip()
    port_clean = str(destination_port).strip() if destination_port else "443"

    # Counter-logic defense: PBF match tests a single flow, so each side must be one host address
    for ip_val, name in [(source_clean, "source"), (destination_clean, "destination")]:
        try:
            ipaddress.ip_address(ip_val)
        except ValueError:
            return f"ERROR: [test_pbf_policy] Invalid {name} IP address '{ip_val}'."

    # Counter-logic defense: map named protocols ('tcp', 'udp', 'icmp') to numbers
    proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
    proto_raw = str(protocol).strip().lower() if protocol else "6"
    protocol_clean = proto_map.get(proto_raw, proto_raw)

    if not re.match(r'^\d+$', protocol_clean) or not (1 <= int(protocol_clean) <= 255):
        return f"ERROR: [test_pbf_policy] Invalid protocol '{protocol}'. Must be a valid protocol number (1-255) or name ('tcp', 'udp', 'icmp')."

    # Port validation
    if not re.match(r'^\d+$', port_clean) or not (1 <= int(port_clean) <= 65535):
        return f"ERROR: [test_pbf_policy] Invalid port number '{port_clean}'. Must be 1-65535."

    root = Element("test")
    pbf = SubElement(root, "pbf-policy-match")
    if from_zone and str(from_zone).strip():
        SubElement(pbf, "from").text = str(from_zone).strip()
    SubElement(pbf, "source").text = source_clean
    SubElement(pbf, "destination").text = destination_clean
    SubElement(pbf, "protocol").text = protocol_clean
    SubElement(pbf, "destination-port").text = port_clean
    if application and str(application).strip():
        SubElement(pbf, "application").text = str(application).strip()

    xml_cmd = tostring(root, encoding="unicode")
    logger.info(f"[PBFMath] Testing: {source_clean} → {destination_clean}:{port_clean}/proto={protocol_clean} on {target_device or 'default'}")

    try:
        client = _get_pool().get_client(target_device)
        status, result = client.execute_op(xml_cmd)

        if status == 200:
            if "No rule matched" in result or "no rule" in result.lower():
                return "PBF Policy Match: No PBF rule matched. Traffic falls through to standard Virtual Router FIB routing."
            sanitizer = ToxicXmlSanitizer()
            try:
                yaml_output, stats = sanitizer.convert_string(result, return_stats=True)
                return yaml_output
            except Exception as e:
                logger.error(f"[PBFMath] XML→YAML conversion failed: {e}")
                return f"Raw PBF Result: {result[:1000]}"
        else:
            return f"ERROR: [test_pbf_policy] PAN-OS returned HTTP {status}. {result[:500]}. NO PBF DATA WAS RETRIEVED."
    except Exception as e:
        return f"ERROR: [test_pbf_policy] failed. Reason: {str(e)}. NO PBF DATA WAS RETRIEVED."


def test_nat_policy(source: str, destination: str, port: str,
                    protocol: str = "6", from_zone: Optional[str] = None,
                    to_interface: Optional[str] = None,
                    target_device: str = None) -> str:
    """
    Simulate a packet against the firewall's NAT Policy rulebase.
    Returns which NAT rule would apply and the translated addresses.

    Use this when asked: "What NAT rule applies?", "How is this traffic translated?"

    Args:
        source (str): Source IP address (e.g., '10.0.0.5').
        destination (str): Destination IP address (e.g., '8.8.8.8').
        port (str): Destination port number (e.g., '443').
        protocol (str): IP protocol number. Default '6' (TCP). Use '17' for UDP.
        from_zone (str): Ingress security zone (e.g., 'outside'). Optional.
        to_interface (str): Egress interface (e.g., 'ethernet1/1'). Optional.
        target_device (str): Device name from fleet inventory (e.g., 'fw-hq'). Uses default if not specified.
    """
    if not source or not str(source).strip():
        return "ERROR: [test_nat_policy] source IP address is required."
    if not destination or not str(destination).strip():
        return "ERROR: [test_nat_policy] destination IP address is required."

    source_clean = str(source).strip()
    destination_clean = str(destination).strip()
    port_clean = str(port).strip() if port else "443"

    for ip_val, label in ((source_clean, "source"), (destination_clean, "destination")):
        try:
            ipaddress.ip_address(ip_val)
        except ValueError:
            return f"ERROR: [test_nat_policy] Invalid {label} IP address '{ip_val}'."

    proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
    proto_raw = str(protocol).strip().lower() if protocol else "6"
    protocol_clean = proto_map.get(proto_raw, proto_raw)
    if not re.match(r"^\d+$", protocol_clean) or not (1 <= int(protocol_clean) <= 255):
        return f"ERROR: [test_nat_policy] Invalid protocol '{protocol}'. Must be 1-255 or 'tcp'/'udp'/'icmp'."

    # Input validation (H1)
    if not re.match(r'^\d+$', port_clean) or not (1 <= int(port_clean) <= 65535):
        return f"ERROR: [test_nat_policy] Invalid port number '{port_clean}'. Must be 1-65535."

    root = Element("test")
    npm = SubElement(root, "nat-policy-match")
    if from_zone and str(from_zone).strip():
        SubElement(npm, "from").text = str(from_zone).strip()
    SubElement(npm, "source").text = source_clean
    SubElement(npm, "destination").text = destination_clean
    SubElement(npm, "destination-port").text = port_clean
    SubElement(npm, "protocol").text = protocol_clean
    if to_interface and str(to_interface).strip():
        SubElement(npm, "to-interface").text = str(to_interface).strip()
    xml_cmd = tostring(root, encoding="unicode")

    logger.info(f"[NATMath] Testing: {source_clean} → {destination_clean}:{port_clean}/proto={protocol_clean} on {target_device or 'default'}")

    try:
        client = _get_pool().get_client(target_device)
        status, result = client.execute_op(xml_cmd)

        if status == 200:
            sanitizer = ToxicXmlSanitizer()
            try:
                yaml_output, stats = sanitizer.convert_string(result, return_stats=True)
                return yaml_output
            except Exception as e:
                logger.error(f"[NATMath] XML→YAML conversion failed: {e}")
                return f"Raw NAT Result: {result[:1000]}"
        else:
            return f"ERROR: [test_nat_policy] PAN-OS returned HTTP {status}. {result[:500]}. NO NAT DATA WAS RETRIEVED."
    except Exception as e:
        return f"ERROR: [test_nat_policy] failed. Reason: {str(e)}. NO NAT DATA WAS RETRIEVED."


def _find_yaml_val(obj, key: str):
    """Depth-first helper to find the first scalar/dict value for key in parsed YAML."""
    if isinstance(obj, dict):
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
        for v in obj.values():
            found = _find_yaml_val(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_yaml_val(item, key)
            if found is not None:
                return found
    return None


def _extract_dnat_ip(obj, source_ip: str, dest_ip: str) -> Optional[str]:
    """
    Extract Destination NAT (DNAT) translated IP while explicitly skipping
    `source-translation` / `src-translation` subtrees so outbound SNAT egress IPs
    are never misclassified as DNAT.
    """
    _SNAT_SKIP_KEYS = frozenset({
        "source-translation",
        "src-translation",
        "source_translation",
        "dynamic-ip-and-port",
        "translated-source",
        "source",
        "src",
    })
    _DNAT_TARGET_KEYS = ("translated-destination", "destination-translation", "destination", "dst", "ip")

    def _walk(node) -> Optional[str]:
        if isinstance(node, dict):
            # Prefer explicit destination-translation containers first
            for dkey in _DNAT_TARGET_KEYS:
                if dkey in node and isinstance(node[dkey], str):
                    ip_cand = node[dkey].split(":")[0].split("/")[0].strip()
                    try:
                        ipaddress.ip_address(ip_cand)
                        if ip_cand != dest_ip and ip_cand != source_ip:
                            return ip_cand
                    except ValueError:
                        pass
            for k, v in node.items():
                if str(k).lower() in _SNAT_SKIP_KEYS:
                    continue
                found = _walk(v)
                if found:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = _walk(item)
                if found:
                    return found
        return None

    return _walk(obj)


def _fetch_interface_zone_map(target_device: Optional[str] = None) -> dict:
    """Queries <show><interface>all</interface></show> fail-softly to map interface -> zone."""
    if_to_zone = {}
    try:
        client = _get_pool().get_client(target_device)
        status, xml_out = client.execute_op("<show><interface>all</interface></show>")
        if status == 200 and xml_out:
            root = fromstring(xml_out)
            for entry in root.findall(".//ifnet/entry"):
                name = entry.findtext("name")
                zone = entry.findtext("zone")
                if name and zone and name.strip() and zone.strip():
                    if_to_zone[name.strip()] = zone.strip()
    except Exception as e:
        logger.debug(f"[PacketWalk] Interface-to-zone lookup skipped: {e}")
    return if_to_zone


def test_packet_walk(
    source: str = None,
    destination: str = None,
    port: str = "443",
    protocol: str = "6",
    from_zone: Optional[str] = None,
    to_zone: Optional[str] = None,
    application: Optional[str] = None,
    virtual_router: str = "default",
    target_device: Optional[str] = None,
    include_candidate: bool = False,
) -> str:
    """
    Executes a complete, deterministic PAN-OS Single-Pass Parallel Processing (SP3)
    packet walk across Ingress FIB, Policy-Based Forwarding (PBF), Pre-NAT Routing FIB,
    NAT Policy Evaluation, Post-DNAT Re-Routing, and Security Policy Evaluation.
    When uncommitted `[edit]` candidate edits exist (or `include_candidate=True`),
    also simulates the uncommitted candidate `<config>` XML side-by-side before `commit`.

    Counter-Logic Enforced:
    - Resolves Ingress Zone automatically from source IP FIB lookup if from_zone is omitted.
    - Evaluates PBF before Virtual Router FIB.
    - If Destination NAT (DNAT) mutates the destination IP, re-runs FIB lookup on the
      translated destination IP to resolve the true Post-NAT Egress Interface and Post-NAT Zone.
    - Evaluates Security Policy against the Pre-NAT Destination IP and Post-NAT Destination Zone.

    Args:
        source (str): Source IP address (e.g., '10.0.1.5'). Required.
        destination (str): Destination IP address (e.g., '203.0.113.20'). Required.
        port (str): Destination port number (1-65535). Default '443'.
        protocol (str): IP protocol ('6' or 'tcp', '17' or 'udp', '1' or 'icmp'). Default '6'.
        from_zone (str): Optional ingress security zone override.
        to_zone (str): Optional egress security zone override.
        application (str): Optional App-ID name (e.g., 'web-browsing', 'ssl').
        virtual_router (str): Virtual router name (auto-discovered if 'default').
        target_device (str): Target firewall alias from fleet inventory.
    """
    if not source or not str(source).strip():
        return "ERROR: [test_packet_walk] source IP address is required."
    if not destination or not str(destination).strip():
        return "ERROR: [test_packet_walk] destination IP address is required."

    source_clean = str(source).strip()
    destination_clean = str(destination).strip()
    port_clean = str(port).strip() if port else "443"

    for ip_val, label in ((source_clean, "source"), (destination_clean, "destination")):
        try:
            ipaddress.ip_address(ip_val)
        except ValueError:
            return f"ERROR: [test_packet_walk] Invalid {label} IP address '{ip_val}'."

    proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
    proto_raw = str(protocol).strip().lower() if protocol else "6"
    protocol_clean = proto_map.get(proto_raw, proto_raw)
    if not re.match(r"^\d+$", protocol_clean) or not (1 <= int(protocol_clean) <= 255):
        return f"ERROR: [test_packet_walk] Invalid protocol '{protocol}'."

    if not re.match(r"^\d+$", port_clean) or not (1 <= int(port_clean) <= 65535):
        return f"ERROR: [test_packet_walk] Invalid port number '{port_clean}'. Must be 1-65535."

    if_to_zone = _fetch_interface_zone_map(target_device)

    # 1. Ingress Zone & Interface Resolution
    ingress_fib_raw = test_routing_fib(ip=source_clean, virtual_router=virtual_router, target_device=target_device)
    ingress_fib_data = yaml.safe_load(ingress_fib_raw) if not ingress_fib_raw.startswith("ERROR:") else None
    ingress_intf = _find_yaml_val(ingress_fib_data, "interface") or _find_yaml_val(ingress_fib_data, "egress-interface")
    resolved_from_zone = (from_zone.strip() if from_zone and str(from_zone).strip() else None) or (
        if_to_zone.get(str(ingress_intf)) if ingress_intf else None
    )

    # 2. PBF Lookup (evaluates before VR FIB)
    pbf_raw = test_pbf_policy(
        source=source_clean,
        destination=destination_clean,
        destination_port=port_clean,
        protocol=protocol_clean,
        from_zone=resolved_from_zone,
        application=application,
        target_device=target_device,
    )
    pbf_data = yaml.safe_load(pbf_raw) if not pbf_raw.startswith(("ERROR:", "PBF Policy Match: No PBF")) else None
    pbf_rule = _find_yaml_val(pbf_data, "rule") if isinstance(pbf_data, dict) else None
    pbf_egress_intf = _find_yaml_val(pbf_data, "egress-interface") if isinstance(pbf_data, dict) else None

    # 3. Pre-NAT FIB Lookup on Destination IP
    pre_fib_raw = test_routing_fib(ip=destination_clean, virtual_router=virtual_router, target_device=target_device)
    if pre_fib_raw.startswith("ERROR:"):
        return pre_fib_raw
    pre_fib_data = yaml.safe_load(pre_fib_raw)
    pre_fib_intf = _find_yaml_val(pre_fib_data, "interface") or _find_yaml_val(pre_fib_data, "egress-interface")
    pre_fib_nh = _find_yaml_val(pre_fib_data, "next-hop") or _find_yaml_val(pre_fib_data, "nexthop")
    effective_pre_nat_intf = str(pbf_egress_intf or pre_fib_intf or "") or None
    pre_nat_to_zone = if_to_zone.get(effective_pre_nat_intf) if effective_pre_nat_intf else None

    # 4. NAT Policy Evaluation
    nat_raw = test_nat_policy(
        source=source_clean,
        destination=destination_clean,
        port=port_clean,
        protocol=protocol_clean,
        from_zone=resolved_from_zone,
        to_interface=effective_pre_nat_intf,
        target_device=target_device,
    )
    nat_data = yaml.safe_load(nat_raw) if not nat_raw.startswith("ERROR:") else None
    nat_rule = _find_yaml_val(nat_data, "rule") if isinstance(nat_data, dict) else None
    if not nat_rule and isinstance(nat_data, dict):
        rules_block = _find_yaml_val(nat_data, "rules")
        if isinstance(rules_block, dict):
            nat_rule = rules_block.get("entry") or rules_block.get("rule")
        elif isinstance(rules_block, str):
            nat_rule = rules_block

    # Detect Destination NAT (DNAT) translated IP while ignoring SNAT source-translation
    translated_dst_ip = _extract_dnat_ip(nat_data, source_clean, destination_clean) if isinstance(nat_data, dict) else None

    # 5. Post-DNAT Re-Routing (SP3 Counter-Logic: if DNAT mutated destination IP, re-evaluate FIB for Post-NAT Zone)
    post_fib_intf = effective_pre_nat_intf
    post_fib_nh = pre_fib_nh
    if translated_dst_ip:
        post_fib_raw = test_routing_fib(ip=translated_dst_ip, virtual_router=virtual_router, target_device=target_device)
        if not post_fib_raw.startswith("ERROR:"):
            post_fib_data = yaml.safe_load(post_fib_raw)
            post_fib_intf = (
                _find_yaml_val(post_fib_data, "interface")
                or _find_yaml_val(post_fib_data, "egress-interface")
                or effective_pre_nat_intf
            )
            post_fib_nh = (
                _find_yaml_val(post_fib_data, "next-hop")
                or _find_yaml_val(post_fib_data, "nexthop")
                or pre_fib_nh
            )

    resolved_to_zone = (to_zone.strip() if to_zone and str(to_zone).strip() else None) or (
        if_to_zone.get(str(post_fib_intf)) if post_fib_intf else pre_nat_to_zone
    )

    # 6. Security Policy Evaluation (Pre-NAT Destination IP + Post-NAT Destination Zone)
    sec_raw = test_security_policy(
        source=source_clean,
        destination=destination_clean,
        port=port_clean,
        protocol=protocol_clean,
        from_zone=resolved_from_zone,
        to_zone=resolved_to_zone,
        application=application,
        target_device=target_device,
    )
    if sec_raw.startswith("ERROR:"):
        return sec_raw
    sec_data = yaml.safe_load(sec_raw)
    sec_rule = _find_yaml_val(sec_data, "rule") or _find_yaml_val(sec_data, "rules")
    sec_action = _find_yaml_val(sec_data, "action")
    sec_index = _find_yaml_val(sec_data, "index") or _find_yaml_val(sec_data, "rule-idx")

    walk_summary = {
        "packet_walk": {
            "flow": {
                "source": source_clean,
                "destination": destination_clean,
                "effective_post_nat_destination": translated_dst_ip or destination_clean,
                "port": port_clean,
                "protocol": protocol_clean,
                "application": application or "any",
            },
            "ingress_stage": {
                "ingress_interface": ingress_intf or "unknown",
                "from_zone": resolved_from_zone or "any",
            },
            "pbf_stage": {
                "matched_rule": pbf_rule or "none",
                "override_egress_interface": pbf_egress_intf or "none",
            },
            "pre_nat_fib_stage": {
                "egress_interface": pre_fib_intf or "unknown",
                "next_hop": pre_fib_nh or "0.0.0.0",
                "egress_zone": pre_nat_to_zone or "unknown",
            },
            "nat_stage": {
                "rule": nat_rule,
                "translated_destination": translated_dst_ip,
                "dnat_detected": bool(translated_dst_ip),
            },
            "post_nat_routing_stage": {
                "post_nat_fib_performed": bool(translated_dst_ip),
                "egress_interface": post_fib_intf or "unknown",
                "next_hop": post_fib_nh or "0.0.0.0",
                "final_to_zone": resolved_to_zone or "any",
            },
            "security_policy_stage": {
                "evaluated_from_zone": resolved_from_zone or "any",
                "evaluated_to_zone": resolved_to_zone or "any",
                "evaluated_destination_ip": destination_clean,
                "rule": sec_rule or "interzone-default/unmatched",
                "action": sec_action or "unknown",
                "index": sec_index,
            },
        }
    }
    try:
        from core.panos.client import PanOSClient
        from core.panos.sanctuary import evaluate_candidate_packet_walk, get_pending_candidate_changes

        live_client = _get_pool().get_client(target_device)
        pending_edits = (
            get_pending_candidate_changes(target_device=target_device)
            if (include_candidate or isinstance(live_client, PanOSClient))
            else []
        )
        if pending_edits or include_candidate:
            if pending_edits:
                walk_summary["packet_walk"]["candidate_config_warning"] = (
                    f"UNCOMMITTED CANDIDATE EDITS ({len(pending_edits)}) IN [edit] — "
                    "see 'candidate_edit_walk' below for pre-commit simulation."
                )

            def _fib_cb(lookup_ip: str) -> dict:
                f_raw = test_routing_fib(ip=lookup_ip, virtual_router=virtual_router, target_device=target_device)
                if f_raw.startswith("ERROR:"):
                    return {}
                f_data = yaml.safe_load(f_raw)
                return {
                    "interface": str(_find_yaml_val(f_data, "interface") or _find_yaml_val(f_data, "egress-interface") or ""),
                    "next_hop": str(_find_yaml_val(f_data, "next-hop") or _find_yaml_val(f_data, "nexthop") or "0.0.0.0"),
                }

            seed_routes = {
                source_clean: {"interface": str(ingress_intf or ""), "next_hop": "0.0.0.0"},
                destination_clean: {"interface": str(pre_fib_intf or ""), "next_hop": str(pre_fib_nh or "0.0.0.0")},
            }
            if translated_dst_ip:
                seed_routes[translated_dst_ip] = {
                    "interface": str(post_fib_intf or ""),
                    "next_hop": str(post_fib_nh or "0.0.0.0"),
                }

            cand_walk = evaluate_candidate_packet_walk(
                source=source_clean,
                destination=destination_clean,
                port=port_clean,
                protocol=protocol_clean,
                from_zone=from_zone,
                to_zone=to_zone,
                application=application,
                virtual_router=virtual_router,
                target_device=target_device,
                live_if_to_zone=if_to_zone,
                live_routing_fallback=seed_routes,
                fib_lookup_fn=_fib_cb,
            )
            walk_summary["candidate_edit_walk"] = cand_walk
            run_act = str(sec_action or "unknown").lower()
            cand_act = str(cand_walk.get("action") or "unknown").lower()
            cand_status = str(cand_walk.get("verdict_status") or "DETERMINED")
            walk_summary["running_vs_candidate_delta"] = {
                "pending_edit_count": len(pending_edits),
                "running_verdict": f"{run_act.upper()} via '{sec_rule or 'interzone-default'}' (to_zone={resolved_to_zone or 'any'})",
                "candidate_verdict_status": cand_status,
                "candidate_verdict": (
                    f"{cand_act.upper()} via '{cand_walk.get('security_rule')}' "
                    f"(to_zone={cand_walk.get('final_to_zone')})"
                ),
                "verdict_changed": (
                    "indeterminate"
                    if cand_status == "INDETERMINATE"
                    else (
                        run_act != cand_act
                        or str(sec_rule or "") != str(cand_walk.get("security_rule") or "")
                        or str(translated_dst_ip or "") != str(cand_walk.get("translated_destination") or "")
                        or str(resolved_to_zone or "") != str(cand_walk.get("final_to_zone") or "")
                    )
                ),
            }
    except Exception as exc:
        logger.debug(f"[PacketWalk] Candidate [edit] overlay skipped: {exc}")
    return yaml.safe_dump(walk_summary, sort_keys=False)


def execute_operational_command(
    cmd: str,
    target_device: str = None,
    hitl_approved: bool = False
) -> str:
    """
    Executes a PAN-OS operational (show/debug/test) command and returns sanitized output.
    This is the general-purpose command executor — use it for any 'show' command
    not covered by a specialized tool.

    Use this when asked: "Run 'show system info'", "Execute 'show session all'",
    "What does 'show application name facebook-chat' return?",
    "Show me the routing table", "Run this CLI command".

    Args:
        cmd (str): The PAN-OS CLI command or raw XML to execute.
            Examples: 'show system info', 'show session all filter source 10.0.0.5',
            'show application name web-browsing', 'show running security-policy'.
        target_device (str): Device name from fleet inventory (e.g., 'fw-hq'). Uses default if not specified.
        hitl_approved (bool): Explicit operator authorization token from HITL gate. Default: False.
    """
    if not cmd or not isinstance(cmd, str):
        return "ERROR: [execute_operational_command] Command cannot be empty."

    # Lazy imports for log/report routing
    from core.panos.logs import execute_log_query, execute_report_query, execute_report_discovery, execute_live_app_analytics

    # SECURITY GATE: Enforce command allowlist
    is_allowed, reason = CommandFilter.is_allowed(cmd)
    if not is_allowed:
        logger.warning(f"BLOCKED COMMAND: '{cmd}' Reason: {reason}")
        return f"ERROR: Security Policy Block - Command '{cmd}' is not allowed. Reason: {reason}"

    # ROUTE: Determine handler based on command pattern
    route = _get_router().route(cmd)

    # DELEGATE: Route to appropriate handler
    if route.type == CommandType.LOG_QUERY:
        return execute_log_query(
            log_type=route.args['log_type'],
            filter_query=route.args.get('filter_query'),
            target_device=target_device,
        )

    elif route.type == CommandType.REPORT_QUERY:
        report_type = route.args['report_type']
        if report_type == "predefined":
            return execute_report_discovery(target_device=target_device)
        return execute_report_query(report_type, target_device=target_device)

    elif route.type == CommandType.LIVE_ANALYTICS:
        return execute_live_app_analytics(target_device=target_device, hitl_approved=hitl_approved)

    # OPERATIONAL: Execute standard operational command
    effective_cmd = cmd.strip()

    # Management Plane Protection: Guard against unbounded session dumps (DoS risk on high-throughput firewalls)
    # Counter-logic defense: handle multiple spaces/tabs, empty filter arguments, and word boundaries
    cmd_lower = effective_cmd.lower()
    if re.search(r'\bshow\s+session\s+all\b', cmd_lower):
        has_valid_filter = bool(re.search(r'\bfilter\s+\S+', cmd_lower))
        if not has_valid_filter:
            if not hitl_approved:
                logger.warning(f"[Ops] Blocked unbounded '{effective_cmd}' to prevent management plane CPU exhaustion.")
                return (
                    "SAFETY INTERCEPTOR: Unbounded 'show session all' is blocked to protect firewall "
                    "management plane CPU (mgmtsrvr) and prevent HA heartbeat failover on production chassis. "
                    "Please provide a filter, e.g.: 'show session all filter source <ip>', 'show session all filter destination <ip>', "
                    "'show session all filter application <app>', or request operator approval (HITL) to override."
                )
            logger.warning(f"[Ops] Unbounded session dump '{effective_cmd}' executed under explicit operator HITL override.")


    logger.info(f"Executing OP on {target_device or 'default'}: {effective_cmd}")

    try:
        client = _get_pool().get_client(target_device)
        status, result = client.execute_op(effective_cmd)

        if status == 200:
            if 'status="success"' in result or 'status="pass"' in result:
                pass
            else:
                logger.warning(f"API Returned 200 but status not success: {result[:200]}")

            sanitizer = ToxicXmlSanitizer()
            try:
                yaml_output, stats = sanitizer.convert_string(result, return_stats=True)
            except ValueError as e:
                logger.error(f"XML→YAML conversion failed: {e}")
                return f"Conversion Error: {result[:500]}"
            except Exception as e:
                logger.error(f"Unexpected conversion error: {e}")
                return f"Conversion Error: {str(e)}"

            try:
                _get_metrics().log(effective_cmd, stats)
            except Exception as e:
                logger.debug(f"Conversion metrics logging skipped: {e}")

            return yaml_output

        else:
            return f"PAN-OS API Error: HTTP {status} - {result[:200]}"

    except Exception as e:
        return f"ERROR: [execute_operational_command] for '{cmd}' failed. Reason: {str(e)}. NO OPERATIONAL DATA WAS RETRIEVED."


def get_telemetry_snapshot(target_device: str = None) -> dict:
    """
    Captures a real-time snapshot of device health metrics.

    Queries raw XML directly from the client to reliably parse session and resource
    statistics (fixing H2 where regex was searching for XML tags in converted YAML).

    Args:
        target_device (str): Device name from fleet inventory. Uses default if not specified.

    Returns dict with: active_sessions, mgmt_cpu, data_cpu, cps, throughput_kbps.
    """
    stats = {
        'active_sessions': 0,
        'mgmt_cpu': 0.0,
        'data_cpu': 0.0,
        'cps': 0,
        'throughput_kbps': 0
    }

    try:
        client = _get_pool().get_client(target_device)

        # 1. Query raw session info XML directly (H2 fix)
        sess_status, sess_xml = client.execute_op("show session info")
        if sess_status == 200 and sess_xml:
            try:
                root = fromstring(sess_xml)
                num_active = root.find(".//num-active")
                if num_active is not None and num_active.text:
                    stats['active_sessions'] = int(num_active.text.strip())

                cps = root.find(".//cps")
                if cps is not None and cps.text:
                    stats['cps'] = int(cps.text.strip())

                kbps = root.find(".//kbps")
                if kbps is not None and kbps.text:
                    stats['throughput_kbps'] = int(kbps.text.strip())
            except Exception as e:
                logger.debug(f"[Telemetry] ElementTree parse failed, falling back to regex: {e}")
                m = re.search(r'<num-active>\s*(\d+)\s*</num-active>', sess_xml)
                if m: stats['active_sessions'] = int(m.group(1))

                m_cps = re.search(r'<cps>\s*(\d+)\s*</cps>', sess_xml)
                if m_cps: stats['cps'] = int(m_cps.group(1))

                m_kbps = re.search(r'<kbps>\s*(\d+)\s*</kbps>', sess_xml)
                if m_kbps: stats['throughput_kbps'] = int(m_kbps.group(1))

        # 2. Query system resources for management CPU / load average
        res_status, res_out = client.execute_op("show system resources")
        if res_status == 200 and res_out:
            matches = re.findall(r'load average:\s*(\d+\.\d+)', res_out)
            if matches:
                stats['mgmt_cpu'] = float(matches[0])

            # Fallback MGT user CPU% if dataplane resource-monitor is unavailable
            dp_matches = re.findall(r'Cpu\(s\):\s*(\d+\.\d+)%us', res_out)
            if dp_matches:
                stats['data_cpu'] = float(dp_matches[0])

        # 3. Query real PAN-OS dataplane CPU when connected to a live PanOSClient
        from core.panos.client import PanOSClient
        if isinstance(client, PanOSClient):
            dp_status, dp_xml = client.execute_op(
                "<show><running><resource-monitor><second><last>1</last></second></resource-monitor></running></show>"
            )
            if dp_status == 200 and dp_xml:
                try:
                    dp_root = fromstring(dp_xml)
                    vals = [
                        float(v.text.strip())
                        for v in dp_root.findall(".//cpu-load-average/entry/value")
                        if v.text and v.text.strip().replace(".", "", 1).isdigit()
                    ]
                    if vals:
                        stats['data_cpu'] = round(max(vals), 1)
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"[Telemetry] Snapshot Failed: {e}", exc_info=True)

    return stats


def _resolve_effective_policy():
    from core.safety.policy_engine import PolicyEngine

    env_policy = PolicyEngine()
    if env_policy.mode == "READ_WRITE":
        return env_policy
    try:
        from core.brain import get_active_brain
        active_brain = get_active_brain()
        if active_brain is not None and active_brain.policy is not None:
            return active_brain.policy
    except Exception:
        pass
    return env_policy


def apply_dynamic_tag(ip: str, tag: str, target_device: str = None) -> str:
    """
    Dynamically register an IP address with a specific tag via the User-ID API.
    This throws the IP into a Dynamic Address Group (DAG) for zero-trust containment.
    
    Use this when asked to: "contain the attacker", "quarantine the IP", 
    "tag this user", or when you decide an IP needs to be blocked at the network level.
    
    Args:
        ip (str): The suspicious IP address.
        tag (str): The tag name (e.g., 'NEO-Containment-L1').
        target_device (str): Device name from fleet inventory.
    """
    ip_clean = ip.strip() if ip else ""
    tag_clean = tag.strip() if tag else ""

    # POLICY GATE: Check active PolicyEngine / POLICY_MODE first (C3)
    try:
        from core.safety.policy_engine import PolicyViolationError
        try:
            _resolve_effective_policy().check("apply_dynamic_tag")
        except PolicyViolationError as pve:
            return f"ERROR: Security Policy Block - {pve}"
    except ImportError:
        logger.debug("[Ops] PolicyEngine not available, skipping policy check.")

    # Strict IP validation using ipaddress module (C1, C3)
    try:
        target_ip_obj = ipaddress.ip_address(ip_clean)
    except ValueError:
        return f"ERROR: [apply_dynamic_tag] Invalid IP address '{ip_clean}' for DAG orchestration."

    if target_ip_obj.is_loopback or target_ip_obj.is_unspecified:
        return f"ERROR: Security Policy Block - Sanctuary Law forbids tagging loopback/unspecified IP '{ip_clean}'."

    # Strict Tag validation: alphanumeric + dashes/underscores/dots
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,63}$', tag_clean):
        return f"ERROR: [apply_dynamic_tag] Invalid Tag format '{tag_clean}'. Must be alphanumeric identifier (1-63 chars)."

    try:
        client = _get_pool().get_client(target_device)
        # SANCTUARY GATE: Never allow DAG quarantine of the firewall's MGT IP or an active admin SSH/HTTPS IP
        try:
            fw_host = str(client.hostname or "").strip()
        except AttributeError:
            fw_host = ""
        if fw_host and ip_clean == fw_host:
            return f"ERROR: Security Policy Block - Sanctuary Law forbids tagging firewall management IP '{ip_clean}'."
        from core.panos.client import PanOSClient
        if isinstance(client, PanOSClient):
            from core.panos.cartographer import Cartographer
            for adm in Cartographer(target_device=target_device)._fetch_admin_sessions(client):
                if str(adm.get("from") or "").strip() == ip_clean:
                    return (
                        f"ERROR: Security Policy Block - Sanctuary Law forbids tagging active admin session IP '{ip_clean}'."
                    )
    except Exception:
        client = None

    root = Element("uid-message")
    SubElement(root, "type").text = "update"
    payload = SubElement(root, "payload")
    register = SubElement(payload, "register")
    entry = SubElement(register, "entry", ip=ip_clean)
    tag_node = SubElement(entry, "tag")
    SubElement(tag_node, "member").text = tag_clean
    xml_cmd = tostring(root, encoding="unicode")

    logger.info(f"[DAG Orchestration] Applying Tag: {tag_clean} to IP {ip_clean} on {target_device or 'default'}")

    try:
        client = client or _get_pool().get_client(target_device)
        status, result = client.execute_user_id(xml_cmd)
        
        if status == 200:
            return f"SUCCESS: Tag '{tag_clean}' applied to {ip_clean}. IP is now in the DAG."
        else:
            return f"ERROR: [apply_dynamic_tag] Failed to apply tag. Status {status}. {result[:500]}"
    except Exception as e:
        return f"ERROR: [apply_dynamic_tag] failed. Reason: {str(e)}"


def capture_pcap(source_ip: str = "10.0.0.1", dest_ip: str = "8.8.8.8", duration_sec: int = 5, target_device: str = None) -> str:
    """
    Actively triggers a packet capture on the firewall for a specific IP pair,
    waits for the duration, downloads the PCAP, and returns an ASCII payload dump.
    
    Use this when you are highly suspicious of a flow but need empirical evidence
    from the raw packets (e.g. checking for cleartext passwords, SQL injections, or C2 beacons).
    
    Args:
        source_ip (str): Source IP of the suspicious flow.
        dest_ip (str): Destination IP of the suspicious flow.
        duration_sec (int): How long to run the capture (1-30s max, default 5s).
        target_device (str): Device name from fleet inventory.
    """
    # POLICY GATE: Check active PolicyEngine / POLICY_MODE first (C2)
    try:
        from core.safety.policy_engine import PolicyViolationError
        try:
            _resolve_effective_policy().check("capture_pcap")
        except PolicyViolationError as pve:
            return f"ERROR: Security Policy Block - {pve}"
    except ImportError:
        logger.debug("[Ops] PolicyEngine not available, skipping policy check.")

    source_clean = source_ip.strip() if source_ip else "10.0.0.1"
    dest_clean = dest_ip.strip() if dest_ip else "8.8.8.8"

    # Strict IP validation to prevent XML / command injection (C1)
    try:
        ipaddress.ip_address(source_clean)
        ipaddress.ip_address(dest_clean)
    except ValueError as e:
        return f"ERROR: [capture_pcap] Invalid IP address: {e}"

    # Cap duration safely between 1 and 30 seconds (C2, M3)
    try:
        duration = max(1, min(int(duration_sec), 30))
    except (ValueError, TypeError):
        duration = 5

    logger.info(f"[PCAP Engine] Starting {duration}s capture for {source_clean} -> {dest_clean}")

    client = None
    try:
        client = _get_pool().get_client(target_device)
        
        # 1. Clear old filters (fail-safe)
        client.execute_op("<clear><debug><dataplane><packet-diag><filter><match><all/></match></filter></packet-diag></dataplane></debug></clear>")
        
        # 2. Set new filter with validated IPs (C1)
        filter_cmd = (
            f"<set><debug><dataplane><packet-diag><filter><match>"
            f"<source>{escape(source_clean)}</source><destination>{escape(dest_clean)}</destination>"
            f"</match></filter></packet-diag></dataplane></debug></set>"
        )
        client.execute_op(filter_cmd)
        
        # 3. Enable capture
        on_cmd = "<set><debug><dataplane><packet-diag><set><capture><stage><firewall><file>rx.pcap</file></firewall></stage></capture></set></packet-diag></dataplane></debug></set>"
        client.execute_op(on_cmd)
        client.execute_op("<set><debug><dataplane><packet-diag><set><capture><on/></capture></set></packet-diag></dataplane></debug></set>")
        
        # 4. Wait for traffic
        time.sleep(duration)

        # 5. Stop capture and export
        client.execute_op("<set><debug><dataplane><packet-diag><set><capture><off/></capture></set></packet-diag></dataplane></debug></set>")
        
        # 6. Export PCAP securely via sealed client execute_export
        from core.panos.client import PanOSClient
        if isinstance(client, PanOSClient):
            _, data = client.execute_export(category="pcap", **{"from": "rx.pcap"})
        else:
            client.fw.xapi.export(category="pcap", **{"from": "rx.pcap"})
            try:
                data = client.fw.xapi.export_result
            except AttributeError:
                data = b""
        
        # 7. Basic ASCII parsing for the LLM
        data = data[:2048] if data else b""
            
        if not data or len(data) < 24:
            return f"PCAP complete. No packets matched {source_clean} -> {dest_clean} during the {duration}s window."
            
        ascii_chars = ''.join(chr(byte) if 32 <= byte <= 126 or byte == 10 else '.' for byte in data)
        ascii_clean = re.sub(r'\.{4,}', ' [...] ', ascii_chars)
        
        return f"PCAP Capture successful. Extracted Payload Snippet:\n\n{ascii_clean}"
        
    except Exception as e:
        logger.error(f"[PCAP Engine] Capture failed: {e}", exc_info=True)
        return f"ERROR: [capture_pcap] Failed to capture PCAP - {str(e)}"

    finally:
        # Guaranteed cleanup: Always disable capture and clear filters on dataplane (C2)
        if client is not None:
            try:
                client.execute_op("<set><debug><dataplane><packet-diag><set><capture><off/></capture></set></packet-diag></dataplane></debug></set>")
                client.execute_op("<clear><debug><dataplane><packet-diag><filter><match><all/></match></filter></packet-diag></dataplane></debug></clear>")
            except Exception as e:
                logger.debug(f"[PCAP Engine] Cleanup failed: {e}")


def map_home_topology(target_device: Optional[str] = None) -> str:
    """
    Compile the physical and logical topology graph of the firewall (interfaces, subnets,
    zones, virtual-wires, management plane overlap, license entitlements, active admin
    sessions, and rulebase summary) on demand via Cartographer.

    Args:
        target_device (str): Optional fleet device alias; omit for default home appliance.
    """
    try:
        from core.panos.cartographer import Cartographer
        eff_dev = None if target_device in ("", "default", "all", None) else str(target_device).strip()
        return Cartographer(target_device=eff_dev).build_graph()
    except Exception as e:
        logger.error(f"[Cartographer Tool] Topology compile failed: {e}")
        return f"Error compiling home topology: {e}"
