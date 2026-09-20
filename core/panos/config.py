"""
PAN-OS Configuration Read Module
Extracted from pan_tools.py — uses PanOSClientPool for multi-firewall support.

Contains: get_live_config, audit_user_id, fetch_running_config_xml
"""

import re
import logging
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring
from typing import Optional, Tuple

from core.panos.client import PanOSClientPool
from core.utils.xml_to_yaml import ToxicXmlSanitizer

logger = logging.getLogger(__name__)

__all__ = [
    "get_live_config",
    "audit_user_id",
    "fetch_running_config_xml",
]

# Safe configuration XPath prefixes allowed for live inspection (C2)
SAFE_XPATH_PREFIXES = (
    "/config/devices/entry/vsys/entry/rulebase",
    "/config/devices/entry/vsys/entry/address",
    "/config/devices/entry/vsys/entry/address-group",
    "/config/devices/entry/vsys/entry/service",
    "/config/devices/entry/vsys/entry/service-group",
    "/config/devices/entry/vsys/entry/application",
    "/config/devices/entry/vsys/entry/application-group",
    "/config/devices/entry/vsys/entry/zone",
    "/config/devices/entry/vsys/entry/profiles",
    "/config/devices/entry/vsys/entry/profile-group",
    "/config/devices/entry/vsys/entry/tag",
    "/config/devices/entry/network/interface",
    "/config/devices/entry/network/virtual-router",
    "/config/devices/entry/network/tunnel",
    "/config/devices/entry/network/ike",
    "/config/devices/entry/network/profiles",
    "/config/shared/rulebase",
    "/config/shared/address",
    "/config/shared/address-group",
    "/config/shared/service",
    "/config/shared/service-group",
    "/config/shared/application",
    "/config/shared/application-group",
    "/config/shared/profiles",
    "/config/shared/profile-group",
    "/config/shared/tag",
)

# Sensitive subtrees and keyword fragments strictly blocked from retrieval (C2)
DISALLOWED_XPATH_KEYWORDS = (
    "mgt-config",
    "users",
    "password",
    "phash",
    "private-key",
    "secret",
    "pre-shared-key",
    "bind-password",
    "community",
    "passphrase",
    "certificate",
)


def _get_pool() -> PanOSClientPool:
    """Get the connection pool singleton."""
    return PanOSClientPool.get_instance()


def _validate_xpath(xpath: str) -> Tuple[bool, str]:
    """
    Validate that an XPath query conforms to security allowlists (C2).
    Blocks access to administrative credentials, certificate private keys,
    and management plane configuration.
    """
    if not xpath or not isinstance(xpath, str):
        return False, "XPath expression cannot be empty."

    clean_xpath = xpath.strip()
    if not clean_xpath.startswith("/"):
        return False, f"XPath must be absolute and start with '/', got: '{clean_xpath}'"

    lower_xpath = clean_xpath.lower()
    for kw in DISALLOWED_XPATH_KEYWORDS:
        if kw in lower_xpath:
            return False, f"XPath contains disallowed sensitive branch or keyword '{kw}'."

    if not any(clean_xpath.startswith(prefix) for prefix in SAFE_XPATH_PREFIXES):
        return False, f"XPath '{clean_xpath}' is not in the safe configuration allowlist."

    return True, clean_xpath


def _redact_sensitive_xml(xml_content: str) -> str:
    """
    Scrub sensitive credentials, hashes, and private keys from configuration XML (M1).
    """
    if not xml_content or not isinstance(xml_content, str):
        return ""
    sensitive_tags = (
        "phash",
        "private-key",
        "pre-shared-key",
        "secret",
        "bind-password",
        "passphrase",
        "community",
    )
    pattern = r"(<(?:%s)>)(.*?)(</(?:%s)>)" % ("|".join(sensitive_tags), "|".join(sensitive_tags))
    return re.sub(pattern, r"\1[REDACTED]\3", xml_content, flags=re.DOTALL | re.IGNORECASE)


def get_live_config(xpath: str, target_device: str = None) -> str:
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
    # XPath Security Validation (C2)
    is_valid, reason_or_clean = _validate_xpath(xpath)
    if not is_valid:
        logger.warning(f"[Config] Blocked XPath access: {xpath} - Reason: {reason_or_clean}")
        return f"ERROR: Security Policy Block - XPath '{xpath}' is not permitted. Reason: {reason_or_clean}"

    clean_xpath = reason_or_clean

    try:
        client = _get_pool().get_client(target_device)
        logger.info(f"Fetching config for xpath: {clean_xpath} on {target_device or 'default'}")
        
        client.fw.xapi.get(xpath=clean_xpath)
        result = client.fw.xapi.xml_result()
        if not result:
            return "Error: No data returned from firewall."

        # Redact any sensitive child nodes before YAML conversion (M1)
        sanitized_xml = _redact_sensitive_xml(result)

        sanitizer = ToxicXmlSanitizer()
        return sanitizer.convert_string(sanitized_xml)

    except Exception as e:
        logger.error(f"Error fetching config for '{clean_xpath}': {e}", exc_info=True)
        return f"ERROR: [get_live_config] failed to retrieve XML from '{clean_xpath}'. Reason: {str(e)}. NO CONFIGURATION DATA WAS RETRIEVED."


def audit_user_id(user_name: str, target_device: str = None) -> str:
    """
    Audits User-ID mapping for a specific user to verify IP-to-user associations.

    Use this when asked: "Who is logged in as this IP?", "What user is mapped to 10.0.0.5?",
    "Check the User-ID for alice", "Is this user authenticated?", "Audit user mappings".

    Args:
        user_name (str): The username to check (e.g., 'lab\\\\alice').
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    if not user_name or not isinstance(user_name, str) or not user_name.strip():
        return "ERROR: [audit_user_id] Username cannot be empty."

    user_clean = user_name.strip()

    # Construct XML safely using ElementTree to eliminate XML injection (C1)
    root = Element("show")
    u_node = SubElement(root, "user")
    ium_node = SubElement(u_node, "ip-user-mapping")
    SubElement(ium_node, "user").text = user_clean
    op_cmd = tostring(root, encoding="unicode")

    logger.info(f"Auditing User-ID for: {user_clean} on {target_device or 'default'}")

    try:
        client = _get_pool().get_client(target_device)
        
        # Execute OP with pre-constructed XML (H1 fix: use execute_op with cmd_xml=False)
        status, result = client.execute_op(op_cmd)
        if status != 200:
            return f"ERROR: [audit_user_id] PAN-OS returned HTTP {status}. {result[:500]}."

        raw_size = len(result)
        if raw_size > 30000:
            logger.warning(f"[!] Large response detected ({raw_size} bytes). Summarizing for model context.")

            try:
                tree_root = ET.fromstring(result)
                entries = tree_root.findall(".//entry")
                total_count = len(entries)

                if total_count > 0:
                    summary_lines = [
                        f"User-ID Mapping Summary: {total_count} total entries (truncated for analysis)",
                        "Sample mappings:"
                    ]

                    # Display first 10 entries
                    for entry in entries[:10]:
                        ip_elem = entry.find('ip') or entry.attrib.get('ip')
                        ip_val = ip_elem.text if hasattr(ip_elem, 'text') else str(ip_elem or 'N/A')
                        usr = entry.find('user')
                        usr_val = usr.text if usr is not None else user_clean
                        summary_lines.append(f"  - User: {usr_val} -> IP: {ip_val}")

                    # Fix H2 off-by-5 error: only omit when total_count > 15
                    if total_count > 15:
                        omitted = total_count - 15
                        summary_lines.append(f"  ... ({omitted} entries omitted) ...")
                        for entry in entries[-5:]:
                            ip_elem = entry.find('ip') or entry.attrib.get('ip')
                            ip_val = ip_elem.text if hasattr(ip_elem, 'text') else str(ip_elem or 'N/A')
                            usr = entry.find('user')
                            usr_val = usr.text if usr is not None else user_clean
                            summary_lines.append(f"  - User: {usr_val} -> IP: {ip_val}")
                    elif total_count > 10:
                        # For 11-15 entries, display remaining without omission
                        for entry in entries[10:]:
                            ip_elem = entry.find('ip') or entry.attrib.get('ip')
                            ip_val = ip_elem.text if hasattr(ip_elem, 'text') else str(ip_elem or 'N/A')
                            usr = entry.find('user')
                            usr_val = usr.text if usr is not None else user_clean
                            summary_lines.append(f"  - User: {usr_val} -> IP: {ip_val}")

                    result = "\n".join(summary_lines)
                    logger.info(f"Condensed {raw_size} bytes -> {len(result)} bytes")
                    return f"User-ID Mapping Status:\n{result}"
            except Exception as e:
                logger.error(f"Failed to summarize entries: {e}")
                result = result[:5000] + f"\n\n... (truncated {raw_size - 5000} bytes)"
                return f"User-ID Mapping Status (Truncated):\n{result}"

        if not result:
            return f"No mapping found for user: {user_clean}"

        sanitizer = ToxicXmlSanitizer()
        try:
            return f"User-ID Mapping Status:\n{sanitizer.convert_string(result)}"
        except Exception as e:
            logger.debug(f"XML→YAML conversion failed in audit_user_id: {e}")
            return f"User-ID Mapping Status:\n{result}"

    except Exception as e:
        logger.error(f"Error auditing User-ID for '{user_clean}': {e}", exc_info=True)
        return f"ERROR: [audit_user_id] failed for user '{user_clean}'. Reason: {str(e)}. NO USER-ID DATA WAS RETRIEVED."


def fetch_running_config_xml(target_device: str = None) -> str:
    """
    Fetches the raw running-config.xml using PanOSClient with sensitive credentials redacted.
    Returns the sanitized XML string or an error description.

    Args:
        target_device (str): Device name from fleet inventory. Uses default if not specified.
    """
    # Policy check to verify observation privileges (M1)
    try:
        from core.safety.policy_engine import PolicyEngine, PolicyViolationError
        try:
            PolicyEngine().check("fetch_running_config_xml")
        except PolicyViolationError as pve:
            return f"ERROR: Security Policy Block - {pve}"
    except ImportError:
        logger.debug("[Config] PolicyEngine not available, proceeding.")

    try:
        client = _get_pool().get_client(target_device)
        client.fw.xapi.export(category="configuration")
        result = client.fw.xapi.xml_result()
        if result:
            # Redact password hashes, private keys, and pre-shared secrets (M1)
            return _redact_sensitive_xml(result)
        return "Error: No configuration data returned from firewall."
    except Exception as e:
        logger.error(f"[Config] Failed to fetch running config XML: {e}", exc_info=True)
        return f"ERROR: [fetch_running_config_xml] Connection Failed: {str(e)}"
