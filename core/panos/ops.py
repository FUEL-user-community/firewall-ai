"""
PAN-OS Operational Commands Module
Extracted from pan_tools.py — uses PanOSClientPool for multi-firewall support.

Contains: execute_operational_command, test_security_policy, test_routing_fib,
          test_nat_policy, get_telemetry_snapshot, get_device_inventory,
          apply_dynamic_tag, capture_pcap.
"""

import re
import time
import logging
import ipaddress
import threading
from typing import Dict, Any, Optional
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


def test_security_policy(source: str, destination: str, port: str,
                         protocol: str = "6", target_device: str = None) -> str:
    """
    Simulate a packet against the firewall's Security Policy rulebase.
    Returns which rule would ALLOW or DENY the traffic without sending real packets.

    Use this when asked: "Can X reach Y?", "Is traffic allowed?", "What policy matches?",
    "If I have a rule with X, will traffic be allowed?", "Will port 8080 be blocked?",
    "Would traffic on port 443 be denied?", "What happens if I allow web-browsing?"

    If the user does NOT provide source/destination IPs, use these defaults:
        source: 10.0.0.5
        destination: 8.8.8.8

    Args:
        source (str): Source IP address (e.g., '10.0.0.5').
        destination (str): Destination IP address (e.g., '8.8.8.8').
        port (str): Destination port number (e.g., '443', '53', '80').
        protocol (str): IP protocol number. Default '6' (TCP). Use '17' for UDP, '1' for ICMP.
        target_device (str): Device name from fleet inventory (e.g., 'fw-hq'). Uses default if not specified.
    """
    source_clean = source.strip() if source else "10.0.0.5"
    destination_clean = destination.strip() if destination else "8.8.8.8"
    port_clean = str(port).strip() if port else "443"
    protocol_clean = str(protocol).strip() if protocol else "6"

    # Input validation (H1)
    if not re.match(r'^\d+$', port_clean) or not (1 <= int(port_clean) <= 65535):
        return f"ERROR: [test_security_policy] Invalid port number '{port_clean}'. Must be 1-65535."

    root = Element("test")
    spm = SubElement(root, "security-policy-match")
    SubElement(spm, "source").text = source_clean
    SubElement(spm, "destination").text = destination_clean
    SubElement(spm, "protocol").text = protocol_clean
    SubElement(spm, "destination-port").text = port_clean
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


def _discover_virtual_router(client) -> Optional[str]:
    """Auto-discovers the active virtual router name from the firewall running config."""
    cached = getattr(client, "_cached_vr", None)
    if cached:
        return cached

    # Attempt 1: Fetch virtual-router config via xapi
    try:
        if hasattr(client, "fw") and hasattr(client.fw, "xapi"):
            client.fw.xapi.get(xpath="/config/devices/entry/network/virtual-router")
            res_xml = client.fw.xapi.xml_result()
            if res_xml is not None:
                root = res_xml if hasattr(res_xml, "findall") else fromstring(str(res_xml))
                for entry in root.findall(".//entry"):
                    name = entry.get("name")
                    if name and name.strip():
                        client._cached_vr = name.strip()
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
                if name and name.strip():
                    client._cached_vr = name.strip()
                    return client._cached_vr
    except Exception as e:
        logger.debug(f"[PolicyMath] VR auto-discovery via op failed: {e}")

    return None


def test_routing_fib(ip: str, virtual_router: str = "default", target_device: str = None) -> str:
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
    ip_clean = ip.strip() if ip else ""
    if not ip_clean:
        return "ERROR: [test_routing_fib] IP address cannot be empty."

    try:
        client = _get_pool().get_client(target_device)

        # Priority: explicit non-default argument -> devices.yaml virtual_router -> cached VR -> "default"
        configured_vr = getattr(client, "virtual_router", None) or getattr(client, "_cached_vr", None)
        if virtual_router and virtual_router.strip() and virtual_router.strip().lower() != "default":
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
        if status != 200 and "invalid virtual-router" in result.lower():
            discovered_vr = _discover_virtual_router(client)
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


def test_nat_policy(source: str, destination: str, port: str,
                    protocol: str = "6", target_device: str = None) -> str:
    """
    Simulate a packet against the firewall's NAT Policy rulebase.
    Returns which NAT rule would apply and the translated addresses.

    Use this when asked: "What NAT rule applies?", "How is this traffic translated?"

    Args:
        source (str): Source IP address (e.g., '10.0.0.5').
        destination (str): Destination IP address (e.g., '8.8.8.8').
        port (str): Destination port number (e.g., '443').
        protocol (str): IP protocol number. Default '6' (TCP). Use '17' for UDP.
        target_device (str): Device name from fleet inventory (e.g., 'fw-hq'). Uses default if not specified.
    """
    source_clean = source.strip() if source else "10.0.0.5"
    destination_clean = destination.strip() if destination else "8.8.8.8"
    port_clean = str(port).strip() if port else "443"
    protocol_clean = str(protocol).strip() if protocol else "6"

    # Input validation (H1)
    if not re.match(r'^\d+$', port_clean) or not (1 <= int(port_clean) <= 65535):
        return f"ERROR: [test_nat_policy] Invalid port number '{port_clean}'. Must be 1-65535."

    root = Element("test")
    npm = SubElement(root, "nat-policy-match")
    SubElement(npm, "source").text = source_clean
    SubElement(npm, "destination").text = destination_clean
    SubElement(npm, "destination-port").text = port_clean
    SubElement(npm, "protocol").text = protocol_clean
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


def execute_operational_command(cmd: str, target_device: str = None) -> str:
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
        return execute_live_app_analytics(target_device=target_device)

    # OPERATIONAL: Execute standard operational command
    # Enforce actual routing limit to prevent token overflow (M1)
    effective_cmd = cmd.strip()
    if "show routing route" in effective_cmd and "type" not in effective_cmd and "destination" not in effective_cmd and "count" not in effective_cmd:
        logger.info("[Ops] Appending count 50 to unbounded routing query to prevent token overflow.")
        effective_cmd = f"{effective_cmd} count 50"

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

            # Dataplane CPU regex if available
            dp_matches = re.findall(r'Cpu\(s\):\s*(\d+\.\d+)%us', res_out)
            if dp_matches:
                stats['data_cpu'] = float(dp_matches[0])

    except Exception as e:
        logger.error(f"[Telemetry] Snapshot Failed: {e}", exc_info=True)

    return stats


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

    # POLICY GATE: Check write authorization (C3)
    try:
        from core.safety.policy_engine import PolicyEngine, PolicyViolationError
        try:
            PolicyEngine().check("apply_dynamic_tag")
        except PolicyViolationError as pve:
            return f"ERROR: Security Policy Block - {pve}"
    except ImportError:
        logger.debug("[Ops] PolicyEngine not available, skipping policy check.")

    # Strict IP validation using ipaddress module (C1, C3)
    try:
        ipaddress.ip_address(ip_clean)
    except ValueError:
        return f"ERROR: [apply_dynamic_tag] Invalid IP address '{ip_clean}' for DAG orchestration."

    # Strict Tag validation: alphanumeric + dashes/underscores/dots
    if not re.match(r'^[a-zA-Z0-9_\-\.]{1,63}$', tag_clean):
        return f"ERROR: [apply_dynamic_tag] Invalid Tag format '{tag_clean}'. Must be alphanumeric identifier (1-63 chars)."

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
        client = _get_pool().get_client(target_device)
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
    # POLICY GATE: Check write authorization (C2)
    try:
        from core.safety.policy_engine import PolicyEngine, PolicyViolationError
        try:
            PolicyEngine().check("capture_pcap")
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
        
        # 6. Export PCAP securely via pan-os-python SDK (avoids API key in URL logs)
        client.fw.xapi.export(category="pcap", **{"from": "rx.pcap"})
        data = getattr(client.fw.xapi, "export_result", b"")
        
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
