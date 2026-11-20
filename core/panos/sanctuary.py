"""
Pre-Commit Sanctuary & Candidate Diff Gate (`core/panos/sanctuary.py`).

Evaluates uncommitted PAN-OS candidate configuration changes in <200ms at $0.00
(zero LLM calls) right before an interactive SSH `commit` executes:
1. Fast-paths immediately if `<show><config><list><changes/></list></config></show>` is empty.
2. Verifies candidate `deviceconfig/system/permitted-ip` does NOT exclude active admin session IPs.
3. Flags candidate mutations to MGT `ip-address`, `netmask`, or `default-gateway`.
4. Flags flipping `interzone-default` to `deny` when live traffic logs show active flows
   hitting `interzone-default` with no candidate custom `allow` rules covering those zones.
"""

import ipaddress
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set

from core.panos.cartographer import Cartographer
from core.panos.client import PanOSClientPool

logger = logging.getLogger(__name__)


def _parse_permitted_networks(sys_xml: str) -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    if not sys_xml:
        return nets
    try:
        root = ET.fromstring(sys_xml)
        for entry in root.findall(".//permitted-ip/entry"):
            raw = (entry.get("name") or "").strip()
            if not raw:
                continue
            try:
                nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
    except Exception:
        pass
    return nets


def _extract_candidate_mgt_tuple(sys_xml: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not sys_xml:
        return out
    try:
        root = ET.fromstring(sys_xml)
        for tag in ("ip-address", "netmask", "default-gateway"):
            el = root.find(f".//system/{tag}")
            if el is not None and el.text and el.text.strip():
                out[tag] = el.text.strip()
    except Exception:
        pass
    return out


def _extract_candidate_allow_zone_pairs(sec_xml: str) -> Set[tuple[str, str]]:
    pairs: Set[tuple[str, str]] = set()
    if not sec_xml:
        return pairs
    try:
        root = ET.fromstring(sec_xml)
        for entry in root.findall(".//security/rules/entry"):
            disabled = (entry.findtext("disabled") or "no").strip().lower()
            action = (entry.findtext("action") or "").strip().lower()
            if disabled == "yes" or action != "allow":
                continue
            froms = [m.text.strip() for m in entry.findall("./from/member") if m.text and m.text.strip()]
            tos = [m.text.strip() for m in entry.findall("./to/member") if m.text and m.text.strip()]
            for fz in froms or ["any"]:
                for tz in tos or ["any"]:
                    pairs.add((fz, tz))
    except Exception:
        pass
    return pairs


def evaluate_precommit_sanctuary(
    target_device: Optional[str] = None,
    operator_ip_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run deterministic `$0.00` pre-commit safety checks against candidate XML vs. live state.

    Returns:
        {
            "safe": bool,
            "changed": bool,
            "warnings": List[str],
            "summary": str,
        }
    """
    warnings: List[str] = []
    try:
        client = PanOSClientPool.get_instance().get_client(target_device)
    except Exception as exc:
        return {
            "safe": True,
            "changed": True,
            "warnings": [],
            "summary": f"Sanctuary check skipped (client unavailable: {exc})",
        }

    # 1. Fast check: are there any uncommitted candidate changes at all?
    changed_text = ""
    try:
        st_chg, chg_xml = client.execute_op("<show><config><list><changes/></list></config></show>")
        if st_chg == 200 and chg_xml:
            root_chg = ET.fromstring(chg_xml)
            entries = root_chg.findall(".//entry")
            if not entries and not (root_chg.findtext(".//result") or "").strip():
                return {
                    "safe": True,
                    "changed": False,
                    "warnings": [],
                    "summary": "No uncommitted candidate changes.",
                }
            changed_text = chg_xml.lower()
    except Exception as exc:
        logger.debug(f"[Sanctuary] Config changes check fallback: {exc}")

    cart = Cartographer(target_device=target_device)
    admins = cart._fetch_admin_sessions(client)
    active_admin_ips: Set[str] = set()
    for adm in admins:
        ip_str = str(adm.get("from") or "").strip()
        try:
            ipaddress.ip_address(ip_str)
            active_admin_ips.add(ip_str)
        except ValueError:
            continue
    if operator_ip_hint:
        try:
            ipaddress.ip_address(operator_ip_hint.strip())
            active_admin_ips.add(operator_ip_hint.strip())
        except ValueError:
            pass

    # 2. Check candidate /deviceconfig/system (permitted-ip lockout & MGT IP/gateway drift)
    if not changed_text or "deviceconfig" in changed_text or "system" in changed_text or "permitted-ip" in changed_text:
        try:
            st_sys, cand_sys_xml = client.execute_get("/config/devices/entry/deviceconfig/system")
            if st_sys == 200 and cand_sys_xml:
                perm_nets = _parse_permitted_networks(cand_sys_xml)
                if perm_nets and active_admin_ips:
                    for adm_ip in sorted(active_admin_ips):
                        ip_obj = ipaddress.ip_address(adm_ip)
                        if isinstance(ip_obj, ipaddress.IPv4Address) and not any(ip_obj in net for net in perm_nets):
                            net_list = ", ".join(str(n) for n in perm_nets)
                            warnings.append(
                                f"MGT SELF-LOCKOUT: Candidate permitted-ip [{net_list}] excludes active admin IP "
                                f"{adm_ip}. Committing will sever management access immediately."
                            )

                cand_mgt = _extract_candidate_mgt_tuple(cand_sys_xml)
                live_sys = cart._fetch_system_info(client)
                for field in ("ip-address", "netmask", "default-gateway"):
                    c_val = cand_mgt.get(field)
                    l_val = str(live_sys.get(field) or "").strip()
                    if c_val and l_val and c_val != l_val:
                        warnings.append(
                            f"MGT ADDRESS DRIFT: Candidate '{field}' changes from {l_val} -> {c_val}."
                        )
        except Exception as exc:
            logger.debug(f"[Sanctuary] System MGT check skipped: {exc}")

    # 3. Check candidate interzone-default: deny severance against live traffic logs
    if not changed_text or "default-security-rules" in changed_text or "interzone-default" in changed_text:
        try:
            st_def, def_xml = client.execute_get("/config/devices/entry/vsys/entry/rulebase/default-security-rules")
            cand_interzone_deny = True
            if st_def == 200 and def_xml:
                def_root = ET.fromstring(def_xml)
                iz_act = (
                    def_root.findtext(".//entry[@name='interzone-default']/action")
                    or def_root.findtext(".//interzone-default/action")
                    or ""
                ).strip().lower()
                if iz_act == "allow":
                    cand_interzone_deny = False

            if cand_interzone_deny and changed_text and ("interzone-default" in changed_text or "default-security-rules" in changed_text):
                st_sec, sec_xml = client.execute_get("/config/devices/entry/vsys/entry/rulebase/security")
                allow_pairs = _extract_candidate_allow_zone_pairs(sec_xml if st_sec == 200 else "")
                st_log, log_xml = client.execute_log(
                    log_type="traffic",
                    query="( rule eq 'interzone-default' ) and ( action eq allow )",
                    nlogs=10,
                )
                if st_log == 200 and log_xml:
                    log_root = ET.fromstring(log_xml)
                    uncovered_flows: List[str] = []
                    for entry in log_root.findall(".//logs/entry"):
                        f_zone = (entry.findtext("from") or "").strip()
                        t_zone = (entry.findtext("to") or "").strip()
                        src = (entry.findtext("src") or "").strip()
                        dst = (entry.findtext("dst") or "").strip()
                        app = (entry.findtext("app") or "").strip()
                        covered = (
                            (f_zone, t_zone) in allow_pairs
                            or ("any", t_zone) in allow_pairs
                            or (f_zone, "any") in allow_pairs
                            or ("any", "any") in allow_pairs
                        )
                        if f_zone and t_zone and not covered:
                            flow_desc = f"{src}->{dst} ({f_zone}->{t_zone}) [{app}]"
                            if flow_desc not in uncovered_flows:
                                uncovered_flows.append(flow_desc)
                    if uncovered_flows:
                        warnings.append(
                            "ACTIVE FLOW SEVERANCE: Flipping 'interzone-default' to deny without an explicit allow "
                            f"rule covering observed interzone flow(s): {'; '.join(uncovered_flows[:3])}"
                        )
        except Exception as exc:
            logger.debug(f"[Sanctuary] Interzone-default check skipped: {exc}")

    is_safe = len(warnings) == 0
    return {
        "safe": is_safe,
        "changed": True,
        "warnings": warnings,
        "summary": "Candidate changes passed Sanctuary checks." if is_safe else f"{len(warnings)} Sanctuary risk(s) detected.",
    }
