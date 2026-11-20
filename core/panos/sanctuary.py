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
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Set, Tuple

from core.panos.cartographer import Cartographer
from core.panos.client import PanOSClientPool

logger = logging.getLogger(__name__)

# Standard base-OS App-ID -> default protocol/port bindings for `application-default` candidate evaluation
_APP_DEFAULT_PORTS: Dict[str, Set[Tuple[str, int, int]]] = {
    "ssl": {("6", 443, 443)},
    "web-browsing": {("6", 80, 80)},
    "ssh": {("6", 22, 22)},
    "dns": {("6", 53, 53), ("17", 53, 53)},
    "dns-base": {("6", 53, 53), ("17", 53, 53)},
    "ntp": {("17", 123, 123), ("6", 123, 123)},
    "ntp-base": {("17", 123, 123), ("6", 123, 123)},
    "snmp": {("17", 161, 162), ("6", 161, 162)},
    "rdp": {("6", 3389, 3389), ("17", 3389, 3389)},
    "ms-rdp": {("6", 3389, 3389), ("17", 3389, 3389)},
    "smb": {("6", 445, 445), ("6", 139, 139)},
    "ms-ds-smb": {("6", 445, 445)},
    "ldap": {("6", 389, 389), ("17", 389, 389), ("6", 636, 636)},
    "kerberos": {("6", 88, 88), ("17", 88, 88)},
    "syslog": {("17", 514, 514), ("6", 6514, 6514), ("6", 1468, 1468)},
    "bgp": {("6", 179, 179)},
    "ike": {("17", 500, 500), ("17", 4500, 4500)},
    "ipsec-esp-udp": {("17", 4500, 4500)},
    "ping": {("1", 0, 65535)},
    "icmp": {("1", 0, 65535)},
}


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


def parse_commit_scope(commit_cmd: str) -> Dict[str, Any]:
    """
    Classify the PAN-OS commit variant the operator typed:
      `commit` / `commit description "..."` -> full
      `commit force`                        -> force (full candidate, overrides locks)
      `commit partial admin <a> [...]`      -> partial (only those admins' changes are committed)
    """
    raw = re.sub(r"\s+", " ", (commit_cmd or "").strip())
    low = raw.lower()
    if not low.startswith("commit"):
        return {"kind": "none", "admins": []}
    if re.match(r"^commit\s+partial\b", low):
        admins: List[str] = []
        m_list = re.search(r"\badmin\s+\[\s*([^\]]+?)\s*\]", raw, re.IGNORECASE)
        m_one = re.search(r"\badmin\s+([^\s\[\]]+)", raw, re.IGNORECASE)
        if m_list:
            admins = [a for a in m_list.group(1).split() if a]
        elif m_one:
            admins = [m_one.group(1)]
        return {"kind": "partial", "admins": admins}
    if re.match(r"^commit\s+force\b", low):
        return {"kind": "force", "admins": []}
    return {"kind": "full", "admins": []}


def _change_entry_admin(entry: ET.Element) -> str:
    return (entry.findtext("admin") or entry.get("admin") or "").strip()


def detect_panorama_management(target_device: Optional[str] = None) -> Dict[str, Any]:
    """
    Fail-soft check of `show panorama-status`. Local candidate edits on a Panorama-managed firewall
    can be overwritten by the next template / device-group push, so callers should warn before staging.
    Returns {"managed": True | False | None, "detail": str}; None means the status could not be read.
    """
    try:
        client = PanOSClientPool.get_instance().get_client(target_device)
        st, xml_out = client.execute_op("<show><panorama-status></panorama-status></show>")
    except Exception as exc:
        return {"managed": None, "detail": f"panorama-status unavailable ({exc})"}
    if st != 200 or not xml_out:
        return {"managed": None, "detail": "panorama-status unavailable"}
    try:
        text = " ".join(ET.fromstring(xml_out).itertext())
    except ET.ParseError:
        text = xml_out
    servers = re.findall(r"Panorama Server \d+\s*:\s*([0-9A-Za-z.:-]+)", text)
    connected = re.search(r"Connected\s*:\s*yes", text, re.IGNORECASE) is not None
    if connected:
        return {"managed": True, "detail": f"connected to Panorama {', '.join(servers) or '(server unknown)'}"}
    if servers:
        return {"managed": True, "detail": f"Panorama configured ({', '.join(servers)}) but not currently connected"}
    return {"managed": False, "detail": "no Panorama configured"}


def evaluate_precommit_sanctuary(
    target_device: Optional[str] = None,
    operator_ip_hint: Optional[str] = None,
    commit_cmd: str = "commit",
) -> Dict[str, Any]:
    """
    Run deterministic `$0.00` pre-commit safety checks against candidate XML vs. live state.

    Scope-aware: for `commit partial admin <x>`, only changes attributed to those admins are considered
    when deciding which checks apply. If the firewall's change list carries no admin attribution, the full
    candidate is evaluated and `scope_note` says so.

    Known limitation: another admin (or a Panorama push) can still modify the shared candidate between
    this check and the moment `commit` executes.

    Returns:
        {
            "safe": bool,
            "changed": bool,
            "warnings": List[str],
            "summary": str,
            "scope": {"kind": ..., "admins": [...]},
            "scope_note": str,
        }
    """
    warnings: List[str] = []
    scope = parse_commit_scope(commit_cmd)
    scope_note = ""
    try:
        client = PanOSClientPool.get_instance().get_client(target_device)
    except Exception as exc:
        return {
            "safe": True,
            "changed": True,
            "warnings": [],
            "summary": f"Sanctuary check skipped (client unavailable: {exc})",
            "scope": scope,
            "scope_note": "",
        }

    # 1. Fast check: are there any uncommitted candidate changes (within commit scope) at all?
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
                    "scope": scope,
                    "scope_note": "",
                }
            if scope["kind"] == "partial" and scope["admins"] and entries:
                attributed = [e for e in entries if _change_entry_admin(e)]
                if attributed:
                    wanted = {a.lower() for a in scope["admins"]}
                    in_scope = [e for e in attributed if _change_entry_admin(e).lower() in wanted]
                    scope_note = (
                        f"partial commit: evaluated {len(in_scope)}/{len(entries)} change(s) "
                        f"attributed to {', '.join(scope['admins'])}"
                    )
                    if not in_scope:
                        return {
                            "safe": True,
                            "changed": False,
                            "warnings": [],
                            "summary": f"No candidate changes attributed to {', '.join(scope['admins'])}.",
                            "scope": scope,
                            "scope_note": scope_note,
                        }
                    changed_text = " ".join(ET.tostring(e, encoding="unicode") for e in in_scope).lower()
                else:
                    scope_note = "partial commit: change list has no admin attribution — evaluated full candidate"
                    changed_text = chg_xml.lower()
            else:
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
        "summary": "Candidate changes passed pre-commit checks." if is_safe else f"{len(warnings)} pre-commit risk(s) detected.",
        "scope": scope,
        "scope_note": scope_note,
    }


def get_pending_candidate_changes(target_device: Optional[str] = None) -> List[str]:
    """Return non-empty list of uncommitted candidate change descriptions, or [] if candidate == running."""
    try:
        client = PanOSClientPool.get_instance().get_client(target_device)
        st_chg, chg_xml = client.execute_op("<show><config><list><changes/></list></config></show>")
        if st_chg != 200 or not chg_xml:
            return []
        root_chg = ET.fromstring(chg_xml)
        items: List[str] = []
        for entry in root_chg.findall(".//entry"):
            parts = [
                (entry.findtext(tag) or "").strip()
                for tag in ("xpath", "cmd", "admin", "action")
                if (entry.findtext(tag) or "").strip()
            ]
            label = " | ".join(parts) if parts else ("".join(entry.itertext()).strip())
            if label:
                items.append(label[:160])
        if not items:
            raw_res = (root_chg.findtext(".//result") or "").strip()
            if raw_res:
                items.extend([ln.strip()[:160] for ln in raw_res.splitlines() if ln.strip()])
        return items
    except Exception:
        return []


def summarize_candidate_diff(target_device: Optional[str] = None) -> str:
    """
    Deterministic `$0.00` pre-commit candidate audit (`@diff` / `/diff`):
    1. Lists pending uncommitted candidate changes from `mgmtsrvr`.
    2. Runs Sanctuary lockout / drift / active-flow-severance checks.
    3. Audits candidate security rules for broad `application: any`, `service: any`, or missing security profiles.
    """
    changes = get_pending_candidate_changes(target_device=target_device)
    sanctuary = evaluate_precommit_sanctuary(target_device=target_device)
    if not changes and not sanctuary.get("changed"):
        return "No uncommitted candidate changes in [edit] (candidate == running)."

    lines: List[str] = [f"Pending Candidate Edits: {len(changes) or 1} uncommitted change(s) in [edit]"]
    for idx, ch in enumerate(changes[:15], 1):
        lines.append(f"  {idx:02d}. {ch}")
    if len(changes) > 15:
        lines.append(f"  ... (+{len(changes) - 15} more)")

    # Inspect candidate security rule posture
    posture_notes: List[str] = []
    try:
        client = PanOSClientPool.get_instance().get_client(target_device)
        st_sec, sec_xml = client.execute_get("/config/devices/entry/vsys/entry/rulebase/security")
        if st_sec == 200 and sec_xml:
            root = ET.fromstring(sec_xml)
            for entry in root.findall(".//security/rules/entry"):
                rname = entry.get("name") or "unnamed"
                if (entry.findtext("disabled") or "no").strip().lower() == "yes":
                    continue
                if (entry.findtext("action") or "").strip().lower() != "allow":
                    continue
                apps = [m.text.strip() for m in entry.findall("./application/member") if m.text]
                svcs = [m.text.strip() for m in entry.findall("./service/member") if m.text]
                prof = entry.find("profile-setting")
                has_prof = prof is not None and (
                    bool(prof.findall(".//group/member")) or bool(prof.findall(".//profiles/*"))
                )
                flags = []
                if "any" in apps:
                    flags.append("application:any")
                if "any" in svcs:
                    flags.append("service:any (prefer application-default)")
                if not has_prof:
                    flags.append("no-security-profile")
                if flags:
                    posture_notes.append(f"Rule '{rname}': {', '.join(flags)}")
    except Exception:
        pass

    if sanctuary.get("warnings"):
        lines.append("\nSanctuary Pre-Commit Warnings:")
        for w in sanctuary["warnings"]:
            lines.append(f"  ! {w}")
    else:
        lines.append("\nSanctuary Gate: PASS (no MGT lockout or uncovered interzone severance detected).")

    if posture_notes:
        lines.append("\nCandidate Allow-Rule Posture Notes:")
        for pn in posture_notes[:10]:
            lines.append(f"  - {pn}")

    lines.append("\nTip: Run '@walk <src_ip> <dst_ip> [port]' to compare COMMITTED vs. CANDIDATE [edit] SP3 path before 'commit'.")
    return "\n".join(lines)


def _members_list(parent: Optional[ET.Element], tag: str) -> List[str]:
    if parent is None:
        return []
    vals = [m.text.strip() for m in parent.findall(f"./{tag}/member") if m.text and m.text.strip()]
    return vals


def _parse_port_ranges(port_spec: str) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    for raw_part in (port_spec or "").split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            if lo_s.strip().isdigit() and hi_s.strip().isdigit():
                ranges.append((int(lo_s.strip()), int(hi_s.strip())))
        elif part.isdigit():
            p = int(part)
            ranges.append((p, p))
    return ranges


def _build_candidate_object_tables(vsys_root: Optional[ET.Element]) -> Dict[str, Any]:
    """Extract candidate `<address>`, `<address-group>`, `<service>`, `<service-group>`, and `<zone>` maps."""
    addr_map: Dict[str, Tuple[str, str]] = {}
    addr_groups: Dict[str, List[str]] = {}
    svc_map: Dict[str, List[Tuple[str, int, int]]] = {
        "service-http": [("6", 80, 80), ("6", 8080, 8080)],
        "service-https": [("6", 443, 443)],
    }
    svc_groups: Dict[str, List[str]] = {}
    if_to_zone: Dict[str, str] = {}

    if vsys_root is None:
        return {
            "addr_map": addr_map,
            "addr_groups": addr_groups,
            "svc_map": svc_map,
            "svc_groups": svc_groups,
            "if_to_zone": if_to_zone,
        }

    for z_entry in vsys_root.findall(".//zone/entry"):
        z_name = (z_entry.get("name") or "").strip()
        if not z_name:
            continue
        for mode_tag in ("layer3", "layer2", "virtual-wire", "tunnel", "tap"):
            for m in z_entry.findall(f"./network/{mode_tag}/member"):
                if m.text and m.text.strip():
                    if_to_zone[m.text.strip()] = z_name

    for a_entry in vsys_root.findall(".//address/entry"):
        name = (a_entry.get("name") or "").strip()
        if not name:
            continue
        netmask = (a_entry.findtext("ip-netmask") or "").strip()
        ip_rng = (a_entry.findtext("ip-range") or "").strip()
        fqdn = (a_entry.findtext("fqdn") or "").strip()
        if netmask:
            addr_map[name] = ("net", netmask)
        elif ip_rng:
            addr_map[name] = ("range", ip_rng)
        elif fqdn:
            addr_map[name] = ("fqdn", fqdn)

    for ag_entry in vsys_root.findall(".//address-group/entry"):
        name = (ag_entry.get("name") or "").strip()
        if not name:
            continue
        static_members = [m.text.strip() for m in ag_entry.findall("./static/member") if m.text and m.text.strip()]
        if static_members:
            addr_groups[name] = static_members
        elif ag_entry.find("dynamic") is not None:
            addr_map[name] = ("dynamic", "dag")

    for s_entry in vsys_root.findall(".//service/entry"):
        name = (s_entry.get("name") or "").strip()
        if not name:
            continue
        tuples: List[Tuple[str, int, int]] = []
        for proto_name, proto_num in (("tcp", "6"), ("udp", "17")):
            p_text = (s_entry.findtext(f"./protocol/{proto_name}/port") or "").strip()
            for lo, hi in _parse_port_ranges(p_text):
                tuples.append((proto_num, lo, hi))
        if tuples:
            svc_map[name] = tuples

    for sg_entry in vsys_root.findall(".//service-group/entry"):
        name = (sg_entry.get("name") or "").strip()
        if not name:
            continue
        members = [m.text.strip() for m in sg_entry.findall("./members/member") if m.text and m.text.strip()]
        if members:
            svc_groups[name] = members

    return {
        "addr_map": addr_map,
        "addr_groups": addr_groups,
        "svc_map": svc_map,
        "svc_groups": svc_groups,
        "if_to_zone": if_to_zone,
    }


def _resolve_single_ip_token(token: str, tables: Dict[str, Any], _seen: Optional[Set[str]] = None) -> Optional[str]:
    """Resolve a literal IP or candidate address object into a concrete IPv4/IPv6 host string (for DNAT)."""
    tok = (token or "").strip()
    if not tok:
        return None
    cand = tok.split(":")[0].split("/")[0].strip()
    try:
        ipaddress.ip_address(cand)
        return cand
    except ValueError:
        pass
    seen = _seen or set()
    if tok in seen:
        return None
    seen.add(tok)
    kind_val = tables["addr_map"].get(tok)
    if kind_val and kind_val[0] == "net":
        inner = kind_val[1].split("/")[0].strip()
        try:
            ipaddress.ip_address(inner)
            return inner
        except ValueError:
            return None
    return None


def _merge_object_tables(shared_tables: Dict[str, Any], vsys_tables: Dict[str, Any]) -> Dict[str, Any]:
    """Merge `/config/shared` objects underneath vsys objects (vsys-local names shadow shared names)."""
    merged: Dict[str, Any] = {}
    for key in ("addr_map", "addr_groups", "svc_map", "svc_groups", "if_to_zone"):
        combined = dict(shared_tables.get(key) or {})
        combined.update(vsys_tables.get(key) or {})
        merged[key] = combined
    return merged


def _ip_matches_member_token(
    ip_obj: ipaddress._BaseAddress,
    token: str,
    tables: Dict[str, Any],
    unresolved_notes: List[str],
    _depth: int = 0,
) -> Optional[bool]:
    """Tri-state address match: True / False / None (indeterminate — runtime DNS, DAG, EDL, region, or unknown object)."""
    tok = (token or "").strip()
    if not tok or _depth > 8:
        return False
    if tok.lower() == "any":
        return True
    if tok in tables["addr_groups"]:
        sub_results = [
            _ip_matches_member_token(ip_obj, sub, tables, unresolved_notes, _depth + 1)
            for sub in tables["addr_groups"][tok]
        ]
        if any(r is True for r in sub_results):
            return True
        return None if any(r is None for r in sub_results) else False
    if tok in tables["addr_map"]:
        kind, val = tables["addr_map"][tok]
        if kind == "net":
            try:
                return ip_obj in ipaddress.ip_network(val, strict=False)
            except ValueError:
                return False
        if kind == "range" and "-" in val:
            lo_s, hi_s = val.split("-", 1)
            try:
                lo_ip = ipaddress.ip_address(lo_s.strip())
                hi_ip = ipaddress.ip_address(hi_s.strip())
                return type(lo_ip) is type(ip_obj) and int(lo_ip) <= int(ip_obj) <= int(hi_ip)
            except ValueError:
                return False
        note = f"object '{tok}' ({kind}:{val}) requires runtime DNS/DAG state"
        if note not in unresolved_notes:
            unresolved_notes.append(note)
        return None
    # Raw CIDR, host IP, or IP range inline
    if "-" in tok:
        lo_s, hi_s = tok.split("-", 1)
        try:
            lo_ip = ipaddress.ip_address(lo_s.strip())
            hi_ip = ipaddress.ip_address(hi_s.strip())
            return type(lo_ip) is type(ip_obj) and int(lo_ip) <= int(ip_obj) <= int(hi_ip)
        except ValueError:
            pass
    try:
        return ip_obj in ipaddress.ip_network(tok, strict=False)
    except ValueError:
        note = f"unresolved address token '{tok}' (EDL, region, predefined, or object outside candidate vsys/shared)"
        if note not in unresolved_notes:
            unresolved_notes.append(note)
        return None


def _ip_matches_rule_field(
    ip_obj: ipaddress._BaseAddress,
    members: List[str],
    negate: bool,
    tables: Dict[str, Any],
    unresolved_notes: List[str],
) -> Optional[bool]:
    eff = members or ["any"]
    if "any" in [m.lower() for m in eff]:
        return not negate
    results = [_ip_matches_member_token(ip_obj, m, tables, unresolved_notes) for m in eff]
    if any(r is True for r in results):
        raw_hit: Optional[bool] = True
    elif any(r is None for r in results):
        raw_hit = None
    else:
        raw_hit = False
    if raw_hit is None:
        return None
    return (not raw_hit) if negate else raw_hit


def _service_token_matches(
    proto_num: str,
    port_int: int,
    svc_token: str,
    rule_apps: List[str],
    query_app: Optional[str],
    tables: Dict[str, Any],
    _depth: int = 0,
    unresolved_notes: Optional[List[str]] = None,
) -> Optional[bool]:
    """Tri-state service match: True / False / None (indeterminate — unknown App-ID default ports or unknown service object)."""

    def _note(msg: str) -> None:
        if unresolved_notes is not None and msg not in unresolved_notes:
            unresolved_notes.append(msg)

    tok = (svc_token or "").strip()
    if not tok or _depth > 8:
        return False
    low = tok.lower()
    if low == "any":
        return True
    if low == "application-default":
        apps_to_check = [a.lower() for a in (rule_apps or ["any"])]
        if query_app and query_app.lower() != "any":
            q_low = query_app.lower()
            if "any" not in apps_to_check and q_low not in apps_to_check:
                return False
            bound = _APP_DEFAULT_PORTS.get(q_low)
            if bound is not None:
                return any(p == proto_num and lo <= port_int <= hi for p, lo, hi in bound)
            _note(f"application-default ports for App-ID '{q_low}' not in local table")
            return None
        if "any" in apps_to_check:
            return True
        known_union: Set[Tuple[str, int, int]] = set()
        unknown_apps: List[str] = []
        for a in apps_to_check:
            if a in _APP_DEFAULT_PORTS:
                known_union.update(_APP_DEFAULT_PORTS[a])
            else:
                unknown_apps.append(a)
        if known_union and any(p == proto_num and lo <= port_int <= hi for p, lo, hi in known_union):
            return True
        if unknown_apps:
            _note(f"application-default ports for App-ID(s) {unknown_apps[:3]} not in local table")
            return None
        return False

    if tok in tables["svc_groups"]:
        sub_results = [
            _service_token_matches(proto_num, port_int, sub, rule_apps, query_app, tables, _depth + 1, unresolved_notes)
            for sub in tables["svc_groups"][tok]
        ]
        if any(r is True for r in sub_results):
            return True
        return None if any(r is None for r in sub_results) else False
    if tok in tables["svc_map"]:
        return any(p == proto_num and lo <= port_int <= hi for p, lo, hi in tables["svc_map"][tok])

    # Inline tcp/443 or udp-53 fallback
    m_inline = re.match(r"^(tcp|udp)[/-](\d+(?:-\d+)?)$", low)
    if m_inline:
        want_p = "6" if m_inline.group(1) == "tcp" else "17"
        return proto_num == want_p and any(lo <= port_int <= hi for lo, hi in _parse_port_ranges(m_inline.group(2)))
    _note(f"unresolved service object '{tok}'")
    return None


def _any_service_match(
    proto_num: str,
    port_int: int,
    svc_tokens: List[str],
    rule_apps: List[str],
    query_app: Optional[str],
    tables: Dict[str, Any],
    unresolved_notes: List[str],
) -> Optional[bool]:
    results = [
        _service_token_matches(proto_num, port_int, sv, rule_apps, query_app, tables, 0, unresolved_notes)
        for sv in svc_tokens
    ]
    if any(r is True for r in results):
        return True
    return None if any(r is None for r in results) else False


def _candidate_static_route_lpm(
    net_root: Optional[ET.Element],
    ip_str: str,
    virtual_router: str = "default",
) -> Optional[Dict[str, str]]:
    """Evaluate Longest-Prefix-Match across candidate `<virtual-router>` static routes."""
    if net_root is None:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return None

    vr_entries = net_root.findall(".//virtual-router/entry")
    target_vr = None
    for vr in vr_entries:
        if (vr.get("name") or "").strip() == virtual_router:
            target_vr = vr
            break
    if target_vr is None and vr_entries:
        target_vr = vr_entries[0]
    if target_vr is None:
        return None

    best_plen = -1
    best_metric = 999999
    best_hit: Optional[Dict[str, str]] = None
    for sr in target_vr.findall("./routing-table/ip/static-route/entry"):
        dest_txt = (sr.findtext("destination") or "").strip()
        if not dest_txt:
            continue
        try:
            net = ipaddress.ip_network(dest_txt, strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network) or ip_obj not in net:
            continue
        metric_txt = (sr.findtext("metric") or "10").strip()
        metric = int(metric_txt) if metric_txt.isdigit() else 10
        if net.prefixlen > best_plen or (net.prefixlen == best_plen and metric < best_metric):
            best_plen = net.prefixlen
            best_metric = metric
            intf = (sr.findtext("interface") or "").strip()
            nh_ip = (sr.findtext("./nexthop/ip-address") or "").strip()
            is_discard = sr.find("./nexthop/discard") is not None
            next_vr = (sr.findtext("./nexthop/next-vr") or "").strip()
            best_hit = {
                "route_name": (sr.get("name") or "static"),
                "prefix": str(net),
                "prefixlen": str(net.prefixlen),
                "interface": "discard" if is_discard else intf,
                "next_hop": "discard" if is_discard else (nh_ip or next_vr or "0.0.0.0"),
            }
    return best_hit


def evaluate_candidate_packet_walk(
    source: str,
    destination: str,
    port: str = "443",
    protocol: str = "6",
    from_zone: Optional[str] = None,
    to_zone: Optional[str] = None,
    application: Optional[str] = None,
    virtual_router: str = "default",
    target_device: Optional[str] = None,
    live_if_to_zone: Optional[Dict[str, str]] = None,
    live_routing_fallback: Optional[Dict[str, Dict[str, str]]] = None,
    fib_lookup_fn: Optional[Any] = None,
    vsys: str = "vsys1",
) -> Dict[str, Any]:
    """
    Deterministic `$0.00` Pre-Commit Candidate `[edit]` SP3 Packet Walk (APPROXIMATION of PAN-OS):
    Evaluates uncommitted `<config>` XML (`PBF -> Static Route/FIB -> Candidate NAT ->
    Post-DNAT Zone Re-Lookup -> Candidate Security Rules + Default Rules + Shadow Check`)
    so operators can test staged `[edit]` rules BEFORE running `commit`.

    Counter-Logic: this is a Python model of the policy engine, not the dataplane. Any rule whose match
    depends on state the model cannot resolve (FQDN/DAG/EDL/region objects, unknown App-ID default ports,
    unknown service objects, unresolvable DNAT targets) makes the verdict `INDETERMINATE` instead of
    silently treating that rule as a non-match.
    """
    proto_map = {"tcp": "6", "udp": "17", "icmp": "1"}
    proto_clean = proto_map.get(str(protocol or "6").strip().lower(), str(protocol or "6").strip())
    port_int = int(str(port or "443").strip())
    src_ip = ipaddress.ip_address(str(source).strip())
    dst_ip = ipaddress.ip_address(str(destination).strip())
    vsys_name = re.sub(r"[^A-Za-z0-9_.-]", "", str(vsys or "vsys1")) or "vsys1"

    client = PanOSClientPool.get_instance().get_client(target_device)
    st_vsys, vsys_xml = client.execute_get(f"/config/devices/entry/vsys/entry[@name='{vsys_name}']")
    st_net, net_xml = client.execute_get("/config/devices/entry/network")
    try:
        st_shared, shared_xml = client.execute_get("/config/shared")
    except Exception:
        st_shared, shared_xml = 0, ""

    vsys_root = ET.fromstring(vsys_xml) if (st_vsys == 200 and vsys_xml) else None
    net_root = ET.fromstring(net_xml) if (st_net == 200 and net_xml) else None
    shared_root = None
    if st_shared == 200 and shared_xml:
        try:
            shared_root = ET.fromstring(shared_xml)
        except ET.ParseError:
            shared_root = None

    shared_tables = _build_candidate_object_tables(shared_root)
    shared_tables["if_to_zone"] = {}
    tables = _merge_object_tables(shared_tables, _build_candidate_object_tables(vsys_root))
    merged_if_zone: Dict[str, str] = dict(live_if_to_zone or {})
    if not merged_if_zone:
        try:
            st_if, if_xml = client.execute_op("<show><interface>all</interface></show>")
            if st_if == 200 and if_xml:
                if_root = ET.fromstring(if_xml)
                for if_ent in if_root.findall(".//ifnet/entry"):
                    iname = (if_ent.findtext("name") or "").strip()
                    izone = (if_ent.findtext("zone") or "").strip()
                    if iname and izone:
                        merged_if_zone[iname] = izone
        except Exception:
            pass
    merged_if_zone.update(tables["if_to_zone"])
    fb_routes: Dict[str, Dict[str, str]] = dict(live_routing_fallback or {})
    unresolved_notes: List[str] = []
    indeterminate_reasons: List[str] = []

    def _rule_addr_svc_match(entry: ET.Element, apps: List[str], svc_tokens: List[str]) -> Optional[bool]:
        """Sequential tri-state match on source -> destination -> service (stops at first definite False)."""
        neg_s = (entry.findtext("negate-source") or "no").strip().lower() == "yes"
        neg_d = (entry.findtext("negate-destination") or "no").strip().lower() == "yes"
        s_res = _ip_matches_rule_field(src_ip, _members_list(entry, "source"), neg_s, tables, unresolved_notes)
        if s_res is False:
            return False
        # SP3 invariant: NAT, PBF, and Security all match on PRE-NAT destination IP
        d_res = _ip_matches_rule_field(dst_ip, _members_list(entry, "destination"), neg_d, tables, unresolved_notes)
        if d_res is False:
            return False
        v_res = _any_service_match(proto_clean, port_int, svc_tokens, apps, application, tables, unresolved_notes)
        if v_res is False:
            return False
        if s_res is None or d_res is None or v_res is None:
            return None
        return True

    def _lookup_route(ip_text: str) -> Dict[str, str]:
        cand_sr = _candidate_static_route_lpm(net_root, ip_text, virtual_router=virtual_router)
        live_rt = fb_routes.get(ip_text)
        if live_rt is None and callable(fib_lookup_fn):
            try:
                live_rt = fib_lookup_fn(ip_text) or {}
                fb_routes[ip_text] = live_rt
            except Exception:
                live_rt = {}
        live_rt = live_rt or {}
        if cand_sr is not None:
            # Candidate static route overrides unless live FIB has a strictly more specific connected subnet
            live_plen = int(live_rt.get("prefixlen", -1)) if str(live_rt.get("prefixlen", "")).lstrip("-").isdigit() else -1
            if int(cand_sr["prefixlen"]) >= live_plen:
                return cand_sr
        return {
            "interface": str(live_rt.get("interface") or ""),
            "next_hop": str(live_rt.get("next_hop") or "0.0.0.0"),
        }

    # 1. Ingress Zone Resolution
    src_rt = _lookup_route(str(src_ip))
    ingress_intf = src_rt.get("interface") or ""
    cand_from_zone = (
        (from_zone.strip() if from_zone and str(from_zone).strip() else None)
        or merged_if_zone.get(ingress_intf)
        or "any"
    )

    # 2. Candidate PBF Stage
    pbf_matched_rule = "none"
    pbf_override_intf = ""
    pbf_discard = False
    if vsys_root is not None:
        for p_entry in vsys_root.findall(".//rulebase/pbf/rules/entry"):
            if (p_entry.findtext("disabled") or "no").strip().lower() == "yes":
                continue
            p_zones = _members_list(p_entry, "from/zone") or _members_list(p_entry.find("from"), "zone")
            p_intfs = _members_list(p_entry.find("from"), "interface")
            if p_zones and "any" not in [z.lower() for z in p_zones] and cand_from_zone not in p_zones:
                continue
            if p_intfs and ingress_intf and ingress_intf not in p_intfs:
                continue
            p_apps = _members_list(p_entry, "application") or ["any"]
            p_svcs = _members_list(p_entry, "service") or ["any"]
            p_match = _rule_addr_svc_match(p_entry, p_apps, p_svcs)
            if p_match is False:
                continue
            if p_match is None:
                indeterminate_reasons.append(
                    f"PBF rule '{p_entry.get('name') or 'pbf-rule'}' may match (unresolved objects) — forwarding path unknown"
                )
                break
            pbf_matched_rule = p_entry.get("name") or "pbf-rule"
            if p_entry.find("./action/discard") is not None:
                pbf_discard = True
            elif p_entry.find("./action/no-pbf") is None:
                pbf_override_intf = (p_entry.findtext("./action/forward/egress-interface") or "").strip()
            break

    # 3. Pre-NAT FIB + Candidate Static Route Lookup
    pre_rt = _lookup_route(str(dst_ip))
    pre_intf = "discard" if pbf_discard else (pbf_override_intf or pre_rt.get("interface") or "")
    pre_to_zone = merged_if_zone.get(pre_intf) or (to_zone.strip() if to_zone else None) or "any"

    # 4. Candidate NAT Evaluation
    cand_nat_rule: Optional[str] = None
    cand_dnat_ip: Optional[str] = None
    cand_dnat_port: Optional[int] = None
    cand_snat: bool = False
    if vsys_root is not None and not pbf_discard:
        for n_entry in vsys_root.findall(".//rulebase/nat/rules/entry"):
            if (n_entry.findtext("disabled") or "no").strip().lower() == "yes":
                continue
            n_from = _members_list(n_entry, "from") or ["any"]
            n_to = _members_list(n_entry, "to") or ["any"]
            n_to_if = (n_entry.findtext("to-interface") or "any").strip()
            if "any" not in [z.lower() for z in n_from] and cand_from_zone not in n_from:
                continue
            if "any" not in [z.lower() for z in n_to] and pre_to_zone not in n_to:
                continue
            if n_to_if.lower() != "any" and pre_intf and n_to_if != pre_intf:
                continue
            n_svc = (n_entry.findtext("service") or "any").strip()
            n_match = _rule_addr_svc_match(n_entry, ["any"], [n_svc])
            if n_match is False:
                continue
            if n_match is None:
                indeterminate_reasons.append(
                    f"NAT rule '{n_entry.get('name') or 'nat-rule'}' may match (unresolved objects) — translation unknown"
                )
                break

            cand_nat_rule = n_entry.get("name") or "nat-rule"
            cand_snat = n_entry.find("source-translation") is not None
            raw_dnat = (
                n_entry.findtext("./destination-translation/translated-address")
                or n_entry.findtext("./dynamic-destination-translation/translated-address")
                or ""
            ).strip()
            if raw_dnat:
                cand_dnat_ip = _resolve_single_ip_token(raw_dnat, tables)
                if cand_dnat_ip is None:
                    indeterminate_reasons.append(
                        f"DNAT target '{raw_dnat}' in NAT rule '{cand_nat_rule}' is not a static IP/netmask "
                        "(FQDN/range/dynamic) — post-NAT zone unknown"
                    )
            raw_dport = (
                n_entry.findtext("./destination-translation/translated-port")
                or n_entry.findtext("./dynamic-destination-translation/translated-port")
                or ""
            ).strip()
            if raw_dport.isdigit():
                cand_dnat_port = int(raw_dport)
            break

    # 5. Post-DNAT Re-Routing (SP3 Rule: DNAT destination IP triggers second FIB lookup for Post-NAT Zone)
    post_intf = pre_intf
    post_nh = pre_rt.get("next_hop") or "0.0.0.0"
    if cand_dnat_ip:
        post_rt = _lookup_route(cand_dnat_ip)
        if post_rt.get("interface"):
            post_intf = post_rt["interface"]
            post_nh = post_rt.get("next_hop") or post_nh
    cand_final_to_zone = (
        (to_zone.strip() if to_zone and str(to_zone).strip() else None)
        or merged_if_zone.get(post_intf)
        or pre_to_zone
    )

    # 6. Candidate Security Policy Evaluation (Pre-NAT Destination IP + Post-NAT Destination Zone) + Shadow Scan
    matched_sec_rule: Optional[str] = None
    matched_sec_action: Optional[str] = None
    matched_sec_index: Optional[int] = None
    shadowed_rules: List[str] = []
    first_indeterminate_sec: Optional[Tuple[int, str]] = None

    if pbf_discard or post_intf == "discard":
        matched_sec_rule = f"PBF/Route Discard ({pbf_matched_rule if pbf_discard else 'static-discard'})"
        matched_sec_action = "discard"
        matched_sec_index = 0
    elif vsys_root is not None:
        sec_entries = vsys_root.findall(".//rulebase/security/rules/entry")
        for idx, s_entry in enumerate(sec_entries, 1):
            if (s_entry.findtext("disabled") or "no").strip().lower() == "yes":
                continue
            r_type = (s_entry.findtext("rule-type") or "universal").strip().lower()
            if r_type == "intrazone" and cand_from_zone != cand_final_to_zone:
                continue
            if r_type == "interzone" and cand_from_zone == cand_final_to_zone:
                continue
            s_from = _members_list(s_entry, "from") or ["any"]
            s_to = _members_list(s_entry, "to") or ["any"]
            if "any" not in [z.lower() for z in s_from] and cand_from_zone not in s_from:
                continue
            if "any" not in [z.lower() for z in s_to] and cand_final_to_zone not in s_to:
                continue

            s_apps = _members_list(s_entry, "application") or ["any"]
            if application and application.lower() != "any":
                if "any" not in [a.lower() for a in s_apps] and application.lower() not in [a.lower() for a in s_apps]:
                    continue

            s_svcs = _members_list(s_entry, "service") or ["any"]
            s_match = _rule_addr_svc_match(s_entry, s_apps, s_svcs)
            if s_match is False:
                continue

            r_name = s_entry.get("name") or f"rule-{idx}"
            r_action = (s_entry.findtext("action") or "deny").strip().lower()
            if s_match is None:
                if matched_sec_rule is None and first_indeterminate_sec is None:
                    first_indeterminate_sec = (idx, r_name)
                continue
            if matched_sec_rule is None:
                matched_sec_rule = r_name
                matched_sec_action = r_action
                matched_sec_index = idx
            else:
                shadowed_rules.append(f"#{idx} '{r_name}' ({r_action})")

        if matched_sec_rule is None:
            is_intra = cand_from_zone != "any" and cand_from_zone == cand_final_to_zone
            def_rule = "intrazone-default" if is_intra else "interzone-default"
            def_action = "allow" if is_intra else "deny"
            def_node = vsys_root.find(f".//rulebase/default-security-rules/rules/entry[@name='{def_rule}']")
            if def_node is None:
                def_node = vsys_root.find(f".//rulebase/default-security-rules/{def_rule}")
            if def_node is not None and (def_node.findtext("action") or "").strip():
                def_action = (def_node.findtext("action") or def_action).strip().lower()
            matched_sec_rule = def_rule
            matched_sec_action = def_action

        if first_indeterminate_sec is not None:
            indeterminate_reasons.append(
                f"Security rule #{first_indeterminate_sec[0]} '{first_indeterminate_sec[1]}' sits above the computed "
                f"match '{matched_sec_rule}' and may match (unresolved objects)"
            )
    else:
        indeterminate_reasons.append(f"Candidate vsys '{vsys_name}' XML unavailable from XML API")

    verdict_status = "INDETERMINATE" if indeterminate_reasons else "DETERMINED"
    result: Dict[str, Any] = {
        "verdict_status": verdict_status,
        "ingress_zone": cand_from_zone,
        "pbf_rule": pbf_matched_rule,
        "pre_nat_egress_interface": pre_intf or "unknown",
        "pre_nat_to_zone": pre_to_zone,
        "nat_rule": cand_nat_rule,
        "snat_applied": cand_snat,
        "translated_destination": cand_dnat_ip,
        "translated_port": cand_dnat_port,
        "post_nat_egress_interface": post_intf or "unknown",
        "post_nat_next_hop": post_nh,
        "final_to_zone": cand_final_to_zone,
        "evaluated_destination_ip": str(dst_ip),
        "security_rule": (matched_sec_rule or "interzone-default") if not indeterminate_reasons else "UNKNOWN",
        "action": (matched_sec_action or "deny") if not indeterminate_reasons else "unknown",
        "rule_index": matched_sec_index if not indeterminate_reasons else None,
        "model_note": "Python approximation of PAN-OS policy evaluation; commit + live 'test' remains authoritative.",
    }
    if indeterminate_reasons:
        result["indeterminate_reasons"] = indeterminate_reasons[:5]
        result["best_effort_rule_if_unresolved_objects_do_not_match"] = matched_sec_rule
    if shadowed_rules and not indeterminate_reasons:
        result["shadowed_later_rules"] = shadowed_rules[:5]
    if unresolved_notes:
        result["unresolved_dynamic_objects"] = unresolved_notes[:5]
    return result

