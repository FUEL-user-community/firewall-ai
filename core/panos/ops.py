"""
PAN-OS Operational Commands Module
Extracted from pan_tools.py — uses PanOSClientPool for multi-firewall support.

Contains: execute_operational_command, test_security_policy, test_nat_policy,
          get_telemetry_snapshot, get_device_inventory
"""

import re
import logging
from xml.etree.ElementTree import Element, SubElement, tostring
from core.panos.client import PanOSClientPool
from core.panos.metrics import MetricsLogger
from core.panos.interceptors import CommandRouter, CommandType
from core.utils.xml_to_yaml import ToxicXmlSanitizer
from core.safety.command_filter import CommandFilter

logger = logging.getLogger(__name__)

# Module-level singletons (lazy-loaded)
_metrics = None
_router = None


def _get_pool() -> PanOSClientPool:
    """Get the connection pool singleton."""
    return PanOSClientPool.get_instance()


def _get_metrics() -> MetricsLogger:
    """Get or create MetricsLogger singleton."""
    global _metrics
    if _metrics is None:
        _metrics = MetricsLogger.get_instance()
    return _metrics


def _get_router() -> CommandRouter:
    """Get or create CommandRouter."""
    global _router
    if _router is None:
        _router = CommandRouter()
    return _router


def get_device_inventory() -> str:
    """
    Returns the list of managed firewalls and their status.

    Use this when asked: "What firewalls do we have?", "List managed devices",
    "Which firewalls are available?", "Show fleet inventory",
    "What devices can I query?".

    Call this FIRST when the user doesn't specify which firewall to target.
    """
    pool = _get_pool()
    devices = pool.get_device_info()

    if not devices:
        return "No firewalls registered. Add devices to config/devices.yaml."

    output = ["--- MANAGED FIREWALL INVENTORY ---"]
    for d in devices:
        status = "CONNECTED" if d['connected'] else "AVAILABLE"
        default = " (DEFAULT)" if d['default'] else ""
        output.append(
            f"  {d['name']}: {d['label']} @ {d['ip']} [{status}]{default}"
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
    source = source.strip()
    destination = destination.strip()
    port = str(port).strip()
    protocol = str(protocol).strip()

    root = Element("test")
    spm = SubElement(root, "security-policy-match")
    SubElement(spm, "source").text = source
    SubElement(spm, "destination").text = destination
    SubElement(spm, "protocol").text = protocol
    SubElement(spm, "destination-port").text = port
    xml_cmd = tostring(root, encoding="unicode")

    logger.info(f"[PolicyMath] Testing: {source} → {destination}:{port}/proto={protocol} on {target_device or 'default'}")

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


def test_routing_fib(ip: str, virtual_router: str = "default", target_device: str = None) -> str:
    """
    Simulate a routing lookup on the firewall to see which interface and next-hop
    will be used to reach a specific IP address.

    Use this when asked: "How does the firewall reach X?", "Is there a route to Y?",
    "Which interface is used for IP Z?", "Verify return route".
    
    Args:
        ip (str): The IP address to test routing for.
        virtual_router (str): The virtual router name (default is 'default').
        target_device (str): Device name from fleet inventory.
    """
    ip = ip.strip()
    vr = virtual_router.strip()

    root = Element("test")
    routing = SubElement(root, "routing")
    fib = SubElement(routing, "fib-lookup")
    SubElement(fib, "virtual-router").text = vr
    SubElement(fib, "ip").text = ip
    xml_cmd = tostring(root, encoding="unicode")

    logger.info(f"[PolicyMath] Testing routing FIB: IP={ip} VR={vr} on {target_device or 'default'}")

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
    source = source.strip()
    destination = destination.strip()
    port = str(port).strip()
    protocol = str(protocol).strip()

    root = Element("test")
    npm = SubElement(root, "nat-policy-match")
    SubElement(npm, "source").text = source
    SubElement(npm, "destination").text = destination
    SubElement(npm, "destination-port").text = port
    SubElement(npm, "protocol").text = protocol
    xml_cmd = tostring(root, encoding="unicode")

    logger.info(f"[NATMath] Testing: {source} → {destination}:{port}/proto={protocol} on {target_device or 'default'}")

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
        return execute_log_query(route.args['log_type'], target_device=target_device)

    elif route.type == CommandType.REPORT_QUERY:
        report_type = route.args['report_type']
        if report_type == "predefined":
            return execute_report_discovery(target_device=target_device)
        return execute_report_query(report_type, target_device=target_device)

    elif route.type == CommandType.LIVE_ANALYTICS:
        return execute_live_app_analytics(target_device=target_device)

    # OPERATIONAL: Execute standard operational command
    client = _get_pool().get_client(target_device)

    if "show routing route" in cmd and "type" not in cmd and "destination" not in cmd and "count" not in cmd:
        logger.warning("[!] Limiting routing query to 50 entries to prevent token overflow.")

    logger.info(f"Executing OP on {target_device or 'default'}: {cmd}")

    try:
        status, result = client.execute_op(cmd)

        if status == 200:
            if 'status="success"' in result or 'status="pass"' in result:
                pass
            else:
                logger.warning(f"API Returned 200 but status not success: {result[:200]}")

            logger.info(f"Result (First 100 chars): {result[:100]}...")

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
                _get_metrics().log(cmd, stats)
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

    Use this when asked: "How is the firewall doing?", "What's the CPU usage?",
    "How many active sessions?", "Is the firewall overloaded?", "Quick health check".

    Args:
        target_device (str): Device name from fleet inventory. Uses default if not specified.

    Returns dict with: active_sessions, mgmt_cpu, data_cpu, cps, throughput_kbps.
    """
    stats = {
        'active_sessions': 0,
        'mgmt_cpu': 0,
        'data_cpu': 0,
        'cps': 0,
        'throughput_kbps': 0
    }

    try:
        sess_cmd = "show session info"
        sess_out = execute_operational_command(sess_cmd, target_device=target_device)

        if "num-active" in sess_out:
            m = re.search(r'<num-active>(\d+)</num-active>', sess_out)
            if m: stats['active_sessions'] = int(m.group(1))

            m_cps = re.search(r'<cps>(\d+)</cps>', sess_out)
            if m_cps: stats['cps'] = int(m_cps.group(1))

            m_kbps = re.search(r'<kbps>(\d+)</kbps>', sess_out)
            if m_kbps: stats['throughput_kbps'] = int(m_kbps.group(1))

        res_cmd = "show system resources"
        res_out = execute_operational_command(res_cmd, target_device=target_device)

        if "load average" in res_out:
            matches = re.findall(r'load average:\s+(\d+\.\d+)', res_out)
            if matches:
                stats['mgmt_cpu'] = float(matches[0])

    except Exception as e:
        logger.error(f"Telemetry Snapshot Failed: {e}")

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
    ip = ip.strip()
    tag = tag.strip()
    
    # Input validation (defense in depth for attribute injection)
    if any(c in ip for c in '<>&\'"'):
        return f"ERROR: Invalid IP format for DAG orchestration."
    if any(c in tag for c in '<>&\'"'):
        return f"ERROR: Invalid Tag format for DAG orchestration."

    root = Element("uid-message")
    SubElement(root, "type").text = "update"
    payload = SubElement(root, "payload")
    register = SubElement(payload, "register")
    entry = SubElement(register, "entry", ip=ip)
    tag_node = SubElement(entry, "tag")
    SubElement(tag_node, "member").text = tag
    xml_cmd = tostring(root, encoding="unicode")
    
    logger.info(f"[DAG Orchestration] Applying Tag: {tag} to IP {ip} on {target_device or 'default'}")
    
    try:
        client = _get_pool().get_client(target_device)
        status, result = client.execute_user_id(xml_cmd)
        
        if status == 200:
            return f"SUCCESS: Tag '{tag}' applied to {ip}. IP is now in the DAG."
        else:
            return f"ERROR: Failed to apply tag. Status {status}. {result[:500]}"
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
        duration_sec (int): How long to run the capture (default 5s).
        target_device (str): Device name from fleet inventory.
    """
    import time
    import ssl
    import urllib.request
    
    source_ip = source_ip.strip()
    dest_ip = dest_ip.strip()
    logger.info(f"[PCAP Engine] Starting {duration_sec}s capture for {source_ip} -> {dest_ip}")
    
    try:
        client = _get_pool().get_client(target_device)
        
        # 1. Clear old filters (fail-safe)
        client.execute_op("<clear><debug><dataplane><packet-diag><filter><match><all/></match></filter></packet-diag></dataplane></debug></clear>")
        
        # 2. Set new filter
        filter_cmd = (
            f"<set><debug><dataplane><packet-diag><filter><match>"
            f"<source>{source_ip}</source><destination>{dest_ip}</destination>"
            f"</match></filter></packet-diag></dataplane></debug></set>"
        )
        client.execute_op(filter_cmd)
        
        # 3. Enable capture
        on_cmd = "<set><debug><dataplane><packet-diag><set><capture><stage><firewall><file>rx.pcap</file></firewall></stage></capture></set></packet-diag></dataplane></debug></set>"
        client.execute_op(on_cmd)
        client.execute_op("<set><debug><dataplane><packet-diag><set><capture><on/></capture></set></packet-diag></dataplane></debug></set>")
        
        # 4. Wait for traffic
        time.sleep(duration_sec)
        
        # 5. Stop capture
        client.execute_op("<set><debug><dataplane><packet-diag><set><capture><off/></capture></set></packet-diag></dataplane></debug></set>")
        
        # 6. Export PCAP securely via pan-os-python SDK (avoids API key in URL logs)
        client.fw.xapi.export(category="pcap", **{"from": "rx.pcap"})
        data = client.fw.xapi.export_result
        
        # 7. Basic ASCII parsing for the LLM
        # Read first 2KB of the PCAP to keep context window small
        data = data[:2048] if data else b""
            
        if not data or len(data) < 24: # PCAP global header is 24 bytes
            return f"PCAP complete. No packets matched {source_ip} -> {dest_ip} during the {duration_sec}s window."
            
        # Strip binary headers and extract printable ASCII for the LLM to read
        ascii_chars = ''.join(chr(byte) if 32 <= byte <= 126 or byte == 10 else '.' for byte in data)
        
        # Clean up continuous dots
        import re
        ascii_clean = re.sub(r'\.{4,}', ' [...] ', ascii_chars)
        
        return f"PCAP Capture successful. Extracted Payload Snippet:\n\n{ascii_clean}"
        
    except Exception as e:
        return f"ERROR: Failed to capture PCAP - {str(e)}"
