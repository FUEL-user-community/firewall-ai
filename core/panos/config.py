"""
PAN-OS Configuration Read Module
Extracted from pan_tools.py — uses PanOSClientPool for multi-firewall support.

Contains: get_live_config, audit_user_id, fetch_running_config_xml
"""

import logging
import xml.etree.ElementTree as ET
from core.panos.client import PanOSClientPool
from core.utils.xml_to_yaml import ToxicXmlSanitizer

logger = logging.getLogger(__name__)


def _get_pool() -> PanOSClientPool:
    """Get the connection pool singleton."""
    return PanOSClientPool.get_instance()


def get_live_config(xpath: str, target_device: str = None):
    """
    Fetches a section of the firewall's running configuration using an XPath expression.
    Returns the config as sanitized YAML. Use this to inspect rules, objects, profiles, and zones.

    Use this when asked: "Show me the security rules", "What rules use application-default?",
    "Show me the NAT rulebase", "What address objects exist?", "Show the URL filtering profiles",
    "What zones are configured?", "Show me the security profiles", "Show the decryption policy".

    Common XPath expressions:
        Security Rules:  /config/devices/entry/vsys/entry/rulebase/security
        NAT Rules:       /config/devices/entry/vsys/entry/rulebase/nat
        Address Objects: /config/devices/entry/vsys/entry/address
        Service Objects: /config/devices/entry/vsys/entry/service
        App Groups:      /config/devices/entry/vsys/entry/application-group
        Security Profiles: /config/devices/entry/vsys/entry/profile-group
        Zones:           /config/devices/entry/vsys/entry/zone
        URL Filtering:   /config/devices/entry/vsys/entry/profiles/url-filtering
        Decryption:      /config/devices/entry/vsys/entry/rulebase/decryption
        Interfaces:      /config/devices/entry/network/interface

    Args:
        xpath (str): The XPath to the configuration branch.
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    client = _get_pool().get_client(target_device)
    logger.info(f"Fetching config for xpath: {xpath} on {target_device or 'default'}")
    try:
        client.fw.xapi.get(xpath=xpath)
        result = client.fw.xapi.xml_result()
        if not result:
            return "Error: No data returned from firewall."

        sanitizer = ToxicXmlSanitizer()
        return sanitizer.convert_string(result)

    except Exception as e:
        logger.error(f"Error fetching config: {e}")
        return f"ERROR: [get_live_config] failed to retrieve XML from '{xpath}'. Reason: {str(e)}. NO CONFIGURATION DATA WAS RETRIEVED."


def audit_user_id(user_name: str, target_device: str = None):
    """
    Audits User-ID mapping for a specific user to verify IP-to-user associations.

    Use this when asked: "Who is logged in as this IP?", "What user is mapped to 10.0.0.5?",
    "Check the User-ID for alice", "Is this user authenticated?", "Audit user mappings".

    Args:
        user_name (str): The username to check (e.g., 'lab\\\\alice').
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    client = _get_pool().get_client(target_device)
    logger.info(f"Auditing User-ID for: {user_name} on {target_device or 'default'}")

    op_cmd = f"<show><user><ip-user-mapping><user>{user_name}</user></ip-user-mapping></user></show>"

    try:
        client.fw.xapi.op(cmd=op_cmd, cmd_xml=True)
        result = client.fw.xapi.xml_result()

        raw_size = len(result)
        if raw_size > 30000:
            logger.warning(f"[!] Large response detected ({raw_size} bytes). Summarizing for Gemini.")

            if "<entry" in result and "virtual-router" in result:
                try:
                    root = ET.fromstring(result)
                    entries = root.findall(".//entry")
                    total_count = len(entries)

                    summary_lines = [
                        f"Routing Table Summary: {total_count} total routes (truncated for analysis)",
                        "Sample routes:"
                    ]

                    for i, entry in enumerate(entries[:10]):
                        dest = entry.find('destination')
                        nexthop = entry.find('nexthop')
                        vr = entry.find('virtual-router')
                        summary_lines.append(
                            f"  - {dest.text if dest is not None else 'N/A'} via "
                            f"{nexthop.text if nexthop is not None else 'N/A'} "
                            f"(VR: {vr.text if vr is not None else 'N/A'})"
                        )

                    if total_count > 10:
                        summary_lines.append(f"  ... ({total_count - 15} routes omitted) ...")
                        for entry in entries[-5:]:
                            dest = entry.find('destination')
                            nexthop = entry.find('nexthop')
                            vr = entry.find('virtual-router')
                            summary_lines.append(
                                f"  - {dest.text if dest is not None else 'N/A'} via "
                                f"{nexthop.text if nexthop is not None else 'N/A'} "
                                f"(VR: {vr.text if vr is not None else 'N/A'})"
                            )

                    result = "\n".join(summary_lines)
                    logger.info(f"Condensed {raw_size} bytes -> {len(result)} bytes")
                except Exception as e:
                    logger.error(f"Failed to summarize routing table: {e}")
                    result = result[:5000] + f"\n\n... (truncated {raw_size - 5000} bytes)"

        if not result:
            return f"No mapping found for user: {user_name}"

        sanitizer = ToxicXmlSanitizer()
        return f"User-ID Mapping Status:\n{sanitizer.convert_string(result)}"

    except Exception as e:
        return f"ERROR: [audit_user_id] failed for user '{user_name}'. Reason: {str(e)}. NO USER-ID DATA WAS RETRIEVED."


def fetch_running_config_xml(target_device: str = None) -> str:
    """
    Fetches the raw running-config.xml using PanOSClient.
    Returns the XML string or raises an Error.

    Args:
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    try:
        client = _get_pool().get_client(target_device)
        client.fw.xapi.export(category="configuration")
        result = client.fw.xapi.xml_result()
        if result:
            return result
        return "Error: No configuration data returned."
    except Exception as e:
        return f"Connection Failed: {str(e)}"
