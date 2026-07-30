"""
PAN-OS Log & Report Query Module
Extracted from pan_tools.py — uses PanOSClientPool for multi-firewall support.

Contains: execute_log_query, execute_report_query, execute_report_discovery, execute_live_app_analytics
"""

import logging
import xml.etree.ElementTree as ET
from collections import Counter
from core.panos.client import PanOSClientPool
from core.utils.xml_to_yaml import ToxicXmlSanitizer

logger = logging.getLogger(__name__)


def _get_pool() -> PanOSClientPool:
    """Get the connection pool singleton."""
    return PanOSClientPool.get_instance()


def execute_log_query(log_type: str, filter_query: str = None, target_device: str = None) -> str:
    """
    Queries the firewall's log database and returns matching entries.
    Handles async job polling automatically.

    Use this when asked: "Show me traffic logs", "What was denied?", "Show denied traffic",
    "What got blocked in the last hour?", "Search logs for 10.0.0.5",
    "Show me threat logs", "What applications were seen?",
    "Show me logs where the app is not-applicable", "Find dropped connections".

    Args:
        log_type (str): The log type to query. Common values:
            'traffic' — firewall traffic logs (allowed, denied, dropped)
            'threat'  — threat prevention logs (IPS, antivirus, anti-spyware)
            'system'  — system events (commits, HA, auth)
            'config'  — configuration change audit trail
        filter_query (str): Optional PAN-OS log filter expression. Examples:
            '( app eq not-applicable )'
            '( addr.src eq 10.0.0.5 ) and ( dport eq 443 )'
            '( action eq deny )'
            '( app eq unknown-tcp )'
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    client = _get_pool().get_client(target_device)

    try:
        status, result = client.execute_log(query=filter_query or "", nlogs=20)

        if status == 200:
            sanitizer = ToxicXmlSanitizer()
            return sanitizer.convert_string(result)
        else:
            return f"Log Query Failed: {result[:200]}"

    except Exception as e:
        return f"Log Query Logic Failed: {e}"


def execute_report_query(report_type: str, target_device: str = None) -> str:
    """
    Executes a report query using PanOSClient.

    Args:
        report_type (str): Report name to query.
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    client = _get_pool().get_client(target_device)

    try:
        status, result = client.execute_report(report_type)

        if status == 200:
            sanitizer = ToxicXmlSanitizer()
            return sanitizer.convert_string(result)
        else:
            return f"Report Query Failed: {result[:200]}"

    except Exception as e:
        return f"Report Query Logic Failed: {e}"


def execute_report_discovery(target_device: str = None) -> str:
    """
    Since PAN-OS XML API has no native 'list reports' function,
    we brute-force check common names to simulate discovery.

    Args:
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    candidates = [
        "top-applications", "top-application-categories", "top-apps",
        "top-users", "top-attackers", "top-threats",
        "bandwidth-trend", "risk-trend", "botnet", "spyware-infected-hosts"
    ]

    valid_reports = []
    client = _get_pool().get_client(target_device)
    log_output = ["--- PREDEFINED REPORT DISCOVERY ---"]

    for report in candidates:
        try:
            status, result = client.execute_report(report)

            if "Illegal value" in result or "Invalid" in result:
                pass
            else:
                valid_reports.append(report)
                log_output.append(f"[+] FOUND: {report}")
        except Exception as e:
            log_output.append(f"[!] ERROR: {report} -> {str(e)[:50]}")

    if not valid_reports:
        return "Discovery Failed: No predefined reports returned valid responses."

    return "\n".join(log_output) + "\n\nUse: 'show report <name>' to retrieve."


def execute_live_app_analytics(target_device: str = None) -> str:
    """
    Analyzes live sessions to generate a 'Top Applications' report
    by counting active sessions in the session table.
    Bypasses the Report Engine (which is disabled on VM-50).

    Args:
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    client = _get_pool().get_client(target_device)
    cmd = "<show><session><all></all></session></show>"

    try:
        status, result = client.execute_op(cmd)

        if status != 200:
            return f"Live Analytics Failed: HTTP {status}"

        root = ET.fromstring(result)
        apps = []
        for entry in root.findall(".//entry"):
            app_node = entry.find("application")
            if app_node is not None and app_node.text:
                apps.append(app_node.text)

        if not apps:
            return "No active applications found in session table (0 sessions)."

        counts = Counter(apps).most_common(20)

        output = ["--- LIVE TOP APPLICATIONS (Active Sessions) ---"]
        output.append(f"Total Sessions Analyzed: {len(apps)}")
        output.append(f"{'APPLICATION':<25} {'SESSIONS':<10}")
        output.append("-" * 35)

        for app, count in counts:
            output.append(f"{app:<25} {count:<10}")

        return "\n".join(output)

    except Exception as e:
        return f"Live Analytics Failed: {e}"
