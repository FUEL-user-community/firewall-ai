"""
Evidence Engine - code owns the facts, the model owns judgment.

Two deterministic layers applied to every investigation report:

1. build_facts(receipts, query="")
   Extracts device facts (versions, content age, licenses, management exposure,
   admin sessions, policy verdicts, adversary presence triage, failed/blocked steps)
   straight from SUCCESS receipts. The model can neither invent these nor skip them.

2. annotate_claims(text, receipts, query="")
   Checks every claim line in the model's report against the receipts:
     - cites a step that FAILED / was BLOCKED / does not exist -> UNVERIFIED
     - cites a document page that was never successfully read  -> UNVERIFIED
     - quotes text that appears in no successful receipt         -> UNVERIFIED
     - names an IP address found in no receipt and not the query -> UNVERIFIED
     - asserts presence for an unobserved query IP citing a step lacking it -> UNVERIFIED
     - states a fact without any [Step N] citation              -> UNCITED

Counter-logic: a citation to a SUCCESS step proves the step exists, not that
it supports the sentence. Quote and IP checks narrow that gap; they do not
close it. Marked lines are the ones an engineer must not trust as-is.

Dependency-free (stdlib + PyYAML) so brain and exporters can both import it.
"""

import datetime
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a core dependency
    yaml = None

from core.pipeline.outcomes import effective_status


FACTS_HEADING = "### Device Facts (computed by code from receipts, not written by the model)"

# Markers this module appends. Stripped before re-annotation so the pass is idempotent.
_MARKER_RE = re.compile(r" ?`\[(?:UNVERIFIED|UNCITED)[^`]*\]`")
_CITATION_RE = re.compile(r"\[Steps?\s+(\d+(?:\s*(?:,|-|–|and|&)\s*\d+)*)([^\]]*)\]", re.IGNORECASE)
_PAGE_RE = re.compile(
    r"\b(?:pp?\.|pages?)\s*(\d{1,4}(?:\s*(?:-|–|,|and|&|to)\s*\d{1,4})*)", re.IGNORECASE
)
_IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?:/\d{1,2})?(?!(?:\.\d|[\d]))")
def _extract_all_ips(text: str) -> List[str]:
    v4 = _IP_RE.findall(text or "")
    v6_candidates = re.findall(r"(?<![a-fA-F0-9:])([a-fA-F0-9:]{2,39})(?:/\d{1,3})?(?![:a-fA-F0-9])", text or "")
    v6 = []
    for cand in v6_candidates:
        if ":" in cand:
            try:
                ip_obj = ipaddress.ip_address(cand)
                if isinstance(ip_obj, ipaddress.IPv6Address):
                    v6.append(cand)
            except ValueError:
                pass
    return list(dict.fromkeys(v4 + v6))


def _extract_query_candidate_ips(query: str) -> List[str]:
    """Extract IPv4/IPv6 host addresses from user query, excluding netmasks, broadcast, and loopback."""
    candidates = _extract_all_ips(query or "")
    valid_hosts: List[str] = []
    for ip_str in candidates:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                continue
            if isinstance(ip_obj, ipaddress.IPv4Address):
                if ip_str in {"255.255.255.0", "255.255.0.0", "255.0.0.0", "255.255.255.255"}:
                    continue
            valid_hosts.append(ip_str)
        except ValueError:
            continue
    return list(dict.fromkeys(valid_hosts))


_ABSENCE_TERMS_RE = re.compile(
    r"\b(?:absent|not found|no entry|no entries|not present|unresolved|untracked|zero sessions|0 sessions|no sessions|none found|never seen|not observed)\b",
    re.IGNORECASE,
)

_QUOTE_RE = re.compile(r'"([^"\n]+)"|“([^”\n]+)”|\'([a-zA-Z0-9_\-\.]{2,50})\'|‘([a-zA-Z0-9_\-\.]{2,50})’')
# Recommendations are judgment, not facts: a line that starts with an action verb
# needs no receipt. Everything else that reads as a statement must cite one.
_RECOMMENDATION_RE = re.compile(
    r"^(?:[-*+]\s+|\d+[.)]\s+)?(?:\*\*|\*|_)?(?:(?:strictly|immediately|then|next|first|also|optionally)\s+)?"
    r"(?:add|apply|attach|avoid|bind|check|commit|configure|consider|create|decrypt|delete|disable|enable|"
    r"enforce|ensure|follow|install|isolate|limit|log|migrate|monitor|move|pin|re-?activate|re-?run|"
    r"reinstate|remove|renew|replace|request|restrict|review|rotate|route|run|schedule|set|stage|strip|"
    r"test|trigger|upgrade|use|validate|verify)\b",
    re.IGNORECASE,
)
_CAUSAL_CONJUNCTIONS = re.compile(
    r"\b(?:because|due to|caused by|resulting from|in order to stop|mitigating the|after the|which caused|which triggered)\b",
    re.IGNORECASE,
)
_STATUS_KEYWORD_RE = re.compile(
    r"\b(?:up|down|dropped|blocked|allowed|applied|failing|failed|degraded|offline|online)\b",
    re.IGNORECASE,
)
_INFERENCE_RE = re.compile(
    r"\b(?:inference|general knowledge)\s*:|^(?:[-*+]\s+)?(?:\*\*|\*|_)?logic\s*\(",
    re.IGNORECASE,
)
_ASSERTIVE_VERBS_RE = re.compile(
    r"\b(?:is|was|are|were|dropped|blocked|failed|caused by|identified as)\b",
    re.IGNORECASE,
)
DISJOINT_TOOL_AFFINITY = {
    "routing": {
        "pattern": re.compile(
            r"\b(?:bgp peer|ospf neighbor|fib lookup|next-hop|egress route|route flapping)\b",
            re.IGNORECASE,
        ),
        "forbidden_tools": {"system_info", "license_info", "admin_sessions", "clock_status", "ntp_status"},
        "domain_name": "routing/BGP",
    },
    "vpn": {
        "pattern": re.compile(
            r"\b(?:ipsec tunnel|ike phase|ike sa|globalprotect active users)\b",
            re.IGNORECASE,
        ),
        "forbidden_tools": {"system_info", "license_info", "admin_sessions", "disk_space"},
        "domain_name": "VPN",
    },
}


# =============================================================================
# Receipt helpers
# =============================================================================

def _raw(receipt: Dict[str, Any]) -> str:
    return str(receipt.get("raw_output") or receipt.get("output_snippet") or "")


def _load(raw: str) -> Any:
    """Parse a YAML-rendered tool output. Returns None when it isn't structured."""
    if not yaml or not raw.strip():
        return None
    try:
        return yaml.safe_load(raw)
    except Exception:
        return None


def _find(obj: Any, key: str) -> Any:
    """Depth-first search for the first value stored under `key`."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = _find(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find(v, key)
            if found is not None:
                return found
    return None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _walk_dicts(obj: Any):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk_dicts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_dicts(v)


def _parse_device_time(value: str) -> Optional[datetime.datetime]:
    if not value:
        return None
    val_str = str(value).strip()
    for fmt in (
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S %Z %Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            return datetime.datetime.strptime(val_str, fmt)
        except (ValueError, TypeError):
            continue
    # Strip potential timezone token e.g. "Mon Oct 12 07:04:10 PDT 2026"
    parts = val_str.split()
    if len(parts) == 6:
        no_tz = f"{parts[0]} {parts[1]} {parts[2]} {parts[3]} {parts[5]}"
        try:
            return datetime.datetime.strptime(no_tz, "%a %b %d %H:%M:%S %Y")
        except (ValueError, TypeError):
            pass
    return None


def _parse_release(value: str) -> Optional[datetime.datetime]:
    text = str(value or "").replace(" UTC", "").strip()
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
        try:
            return datetime.datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _cite(*steps: int) -> str:
    uniq = sorted(set(steps))
    label = "Step" if len(uniq) == 1 else "Steps"
    return f"[{label} {', '.join(str(s) for s in uniq)}]"


def step_header(step: int, status: str) -> str:
    """Prefix shown to the model on every tool result so it can cite receipts."""
    return f"[Step {step} | {status.upper()}]"


def _short_args(args: Any) -> str:
    if not isinstance(args, dict):
        return ""
    for key in ("xpath", "target", "cmd", "command", "source", "destination", "ip", "log_type", "filter_query"):
        if args.get(key):
            return f"{key}={args[key]}"
    return ""


# =============================================================================
# Layer 1: computed facts
# =============================================================================

def build_facts(receipts: List[Dict[str, Any]], query: str = "") -> List[str]:
    """Return fact lines (markdown bullets without the dash) derived from receipts."""
    facts: List[str] = []
    local_ips: set = set()
    statuses = [effective_status(r) for r in receipts]
    ok = [(i, r) for i, (r, st) in enumerate(zip(receipts, statuses), 1) if st == "success"]

    systems: List[Tuple[int, Dict[str, Any], Any]] = []
    for i, r in ok:
        data = _load(_raw(r))
        if data is not None and _find(data, "sw-version") is not None:
            systems.append((i, data, r))

    device_time = None
    mgmt_net, mgmt_ip = None, None
    system_step = None

    if len(systems) == 1:
        s, system, r = systems[0]
        system_step = s
        model = _find(system, "model") or "UNKNOWN"
        host = _find(system, "hostname") or _find(system, "devicename") or "UNKNOWN"
        facts.append(f"PAN-OS {_find(system, 'sw-version')} on {model} (hostname {host}) {_cite(s)}")
        device_time = _parse_device_time(_find(system, "time"))
        if _find(system, "time"):
            facts.append(f"Device clock: {_find(system, 'time')} {_cite(s)}")
        threat_rel_date = None

        for label, ver_key, date_key in (
            ("App/threat content", "threat-version", "threat-release-date"),
            ("Antivirus content", "av-version", "av-release-date"),
            ("WildFire content", "wildfire-version", "wildfire-release-date"),
        ):
            ver = _find(system, ver_key)
            if ver is None:
                continue
            rel = _parse_release(_find(system, date_key))
            if label == "App/threat content" and rel:
                threat_rel_date = rel
            if rel:
                age = f", {(device_time - rel).days} days old at device time" if device_time else ""
                stale = " (STALE: over 7 days)" if device_time and (device_time - rel).days > 7 else ""
                facts.append(f"{label} {ver}, released {rel.date().isoformat()}{age}{stale} {_cite(s)}")
            else:
                facts.append(f"{label} {ver}, release date unknown {_cite(s)}")

        if query and threat_rel_date:
            cve_matches = re.findall(r"\bCVE-((\d{4})-\d+)\b", query, re.IGNORECASE)
            for full_suffix, cve_year_str in sorted(set(cve_matches)):
                cve_year = int(cve_year_str)
                if cve_year > threat_rel_date.year:
                    facts.append(
                        f"Content Blindspot: Queried CVE-{full_suffix.upper()} post-dates active App/threat content "
                        f"(released {threat_rel_date.date().isoformat()}); threat engine has NO signatures for this vulnerability {_cite(s)}"
                    )

        wf_rt = _find(system, "wildfire-rt")
        if wf_rt is not None:
            facts.append(f"WildFire real-time updates: {wf_rt} {_cite(s)}")
        url_ver = _find(system, "url-filtering-version")
        if url_ver is not None:
            note = " (no URL database loaded)" if str(url_ver).startswith("0000") else ""
            facts.append(f"URL filtering database version {url_ver}{note} {_cite(s)}")
        gp_pkg = _find(system, "global-protect-client-package-version")
        if gp_pkg is not None:
            note = " (no GlobalProtect app hosted on this firewall)" if str(gp_pkg) == "0.0.0" else ""
            facts.append(f"GlobalProtect client package {gp_pkg}{note} {_cite(s)}")

        ip, mask = _find(system, "ip-address"), _find(system, "netmask")
        if ip and mask:
            try:
                mgmt_net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                mgmt_ip = str(ip)
                local_ips.add(mgmt_ip)
                gw = _find(system, "default-gateway")
                if gw:
                    local_ips.add(str(gw))
                facts.append(
                    f"Management interface {ip}/{mgmt_net.prefixlen}, gateway {_find(system, 'default-gateway')} {_cite(s)}"
                )
            except ValueError:
                pass
    elif len(systems) > 1:
        for s, system, r in systems:
            ip = _find(system, "ip-address")
            if ip:
                local_ips.add(str(ip))
            gw = _find(system, "default-gateway")
            if gw:
                local_ips.add(str(gw))
            model = _find(system, "model") or "UNKNOWN"
            host = _find(system, "hostname") or _find(system, "devicename") or (r.get("args") or {}).get("target_device") or f"device-{s}"
            facts.append(f"Device [{host}]: PAN-OS {_find(system, 'sw-version')} on {model} {_cite(s)}")
            d_time = _parse_device_time(_find(system, "time"))
            if _find(system, "time"):
                facts.append(f"  [{host}] Device clock: {_find(system, 'time')} {_cite(s)}")
            for label, ver_key, date_key in (
                ("App/threat content", "threat-version", "threat-release-date"),
                ("Antivirus content", "av-version", "av-release-date"),
                ("WildFire content", "wildfire-version", "wildfire-release-date"),
            ):
                ver = _find(system, ver_key)
                if ver is None:
                    continue
                rel = _parse_release(_find(system, date_key))
                if rel:
                    age = f", {(d_time - rel).days} days old" if d_time else ""
                    stale = " (STALE: over 7 days)" if d_time and (d_time - rel).days > 7 else ""
                    facts.append(f"  [{host}] {label} {ver}, released {rel.date().isoformat()}{age}{stale} {_cite(s)}")
                else:
                    facts.append(f"  [{host}] {label} {ver}, release date unknown {_cite(s)}")

    # Licenses
    for i, r in ok:
        data = _load(_raw(r))
        if data is None:
            continue
        lic = _find(data, "licenses")
        entries = _as_list(_find(lic, "entry")) if lic is not None else []
        entries = [e for e in entries if isinstance(e, dict) and "feature" in e]
        if not entries:
            continue
        expired = [f"{e['feature']} ({e.get('expires', '?')})" for e in entries if str(e.get("expired")).lower() == "yes"]
        active = [f"{e['feature']} (expires {e.get('expires', '?')})" for e in entries if str(e.get("expired")).lower() != "yes"]
        if expired:
            facts.append(f"Licenses EXPIRED ({len(expired)}): {', '.join(expired)} {_cite(i)}")
        if active:
            facts.append(f"Licenses active ({len(active)}): {', '.join(active)} {_cite(i)}")
        notes = {str(e["vm-license-status"]) for e in entries if e.get("vm-license-status")}
        for n in sorted(notes):
            facts.append(f"License status note: {n} {_cite(i)}")
        break

    # Dataplane interfaces vs management subnet
    dp_interface_ips: Dict[str, str] = {}
    for i, r in ok:
        data = _load(_raw(r))
        ifnet = _find(data, "ifnet") if data is not None else None
        if ifnet is None:
            continue
        for e in _as_list(_find(ifnet, "entry")):
            if not isinstance(e, dict):
                continue
            addr = str(e.get("ip") or "")
            name = str(e.get("name") or "")
            if "/" in addr:
                clean_ip = addr.split("/")[0]
                local_ips.add(clean_ip)
                if name:
                    dp_interface_ips[clean_ip] = name
            elif addr and addr != "N/A":
                local_ips.add(addr)
                if name:
                    dp_interface_ips[addr] = name
            if mgmt_net is None or "/" not in addr:
                continue
            try:
                iface = ipaddress.ip_interface(addr)
            except ValueError:
                continue
            if iface.ip in mgmt_net:
                facts.append(
                    f"Management IP {mgmt_ip} is in the same subnet as dataplane interface "
                    f"{e.get('name')} (zone {e.get('zone')}, {addr}) {_cite(system_step, i)}"
                )
        break

    # Management profiles bound to dataplane interfaces
    for i, r in ok:
        data = _load(_raw(r))
        if data is None:
            continue
        bound = []
        for d in _walk_dicts(data):
            name = d.get("@name")
            if not name:
                continue
            l3 = d.get("layer3") if isinstance(d.get("layer3"), dict) else d
            prof = l3.get("interface-management-profile") if isinstance(l3, dict) else None
            if prof:
                bound.append(f"{name} = {prof}")
        if bound:
            facts.append(
                f"Management profiles bound to interfaces: {'; '.join(bound)} "
                f"(profile contents not read unless a later step shows them) {_cite(i)}"
            )

    # Explicit interzone/intrazone default overrides
    for i, r in ok:
        data = _load(_raw(r))
        if data is None:
            continue
        for d in _walk_dicts(data):
            if d.get("@name") in ("interzone-default", "intrazone-default") and d.get("action"):
                facts.append(f"Default rule override: {d['@name']} action = {d['action']} {_cite(i)}")

    # Admin sessions
    for i, r in ok:
        data = _load(_raw(r))
        admins = _find(data, "admins") if data is not None else None
        if admins is None:
            continue
        sessions = [e for e in _as_list(_find(admins, "entry")) if isinstance(e, dict)]
        for e in sessions:
            facts.append(
                f"Admin session: user '{e.get('admin')}' from {e.get('from')} via {e.get('type')}, "
                f"idle {e.get('idle-for')}, expires {e.get('session-expiry')} {_cite(i)}"
            )
        break

    # Core Diagnostic Verdicts: Security Policy Matches
    for i, r in ok:
        tool = r.get("tool")
        if tool in ("test_security_policy", "test_policy_match"):
            data = _load(_raw(r))
            if data:
                rule = _find(data, "rule") or _find(data, "rules")
                action = _find(data, "action")
                idx = _find(data, "index") or _find(data, "rule-idx")
                args = r.get("args") or {}
                flow = ""
                listener_note = ""
                if args.get("source") and args.get("destination"):
                    flow = f" ({args['source']} -> {args['destination']}:{args.get('port', '*')})"
                    dst_ip = str(args.get("destination"))
                    port = str(args.get("port", "443"))
                    if dst_ip in dp_interface_ips and port in ("443", "80", "22", "23"):
                        iface_name = dp_interface_ips[dst_ip]
                        listener_note = (
                            f" (NOTE: destination is local dataplane interface {iface_name}; "
                            "requires Interface Management Profile with service enabled to accept management traffic)"
                        )
                if rule and action:
                    idx_str = f" (index {idx})" if idx else ""
                    facts.append(
                        f"Security policy verdict{flow}: rule '{rule}'{idx_str} -> action {str(action).upper()}{listener_note} {_cite(i)}"
                    )

    # Core Diagnostic Verdicts: Routing FIB Lookups
    for i, r in ok:
        tool = r.get("tool")
        if tool in ("test_routing_fib", "test_routing_lookup"):
            data = _load(_raw(r))
            if data:
                iface = _find(data, "interface") or _find(data, "egress-interface")
                nh = _find(data, "next-hop") or _find(data, "nexthop")
                ip_arg = (r.get("args") or {}).get("ip", "")
                target_str = f" for {ip_arg}" if ip_arg else ""
                if iface:
                    nh_str = f", next-hop {nh}" if nh else ""
                    mgt_caveat = (
                        " (CAUTION: target is dedicated MGT interface; dataplane FIB does not forward to out-of-band management port)"
                        if mgmt_ip and ip_arg == mgmt_ip
                        else ""
                    )
                    facts.append(
                        f"Routing FIB verdict{target_str}: egress interface {iface}{nh_str}{mgt_caveat} {_cite(i)}"
                    )

    # Core Diagnostic Verdicts: NAT Policy Matches
    for i, r in ok:
        tool = r.get("tool")
        if tool in ("test_nat_policy", "test_nat_match"):
            data = _load(_raw(r))
            if data:
                rule = _find(data, "rule")
                action = _find(data, "action") or _find(data, "type")
                if rule:
                    act_str = f" ({action})" if action else ""
                    facts.append(f"NAT policy match: rule '{rule}'{act_str} {_cite(i)}")

    # Adversary Presence Triage (Queried external host vs wire telemetry)
    if query:
        cand_query_ips = _extract_query_candidate_ips(query)
        external_query_ips = [ip for ip in cand_query_ips if ip not in local_ips]
        for cand_ip in external_query_ips:
            cand_observed_steps: List[int] = []
            wire_check_steps: List[int] = []
            for i, r in ok:
                tool = str(r.get("tool") or "").lower()
                raw = _raw(r)
                args_str = str(r.get("args") or "").lower()
                is_sim = tool in ("test_security_policy", "test_nat_policy", "test_routing_fib", "test_pbf_policy")
                is_doc = tool == "query_knowledge_base"
                is_wire = any(k in tool or k in args_str for k in ("arp", "session", "log", "neighbor", "client"))

                if is_wire and not is_sim:
                    wire_check_steps.append(i)
                if not is_sim and not is_doc and cand_ip in raw:
                    cand_observed_steps.append(i)

            if cand_observed_steps:
                facts.append(
                    f"Adversary Presence: Query IP {cand_ip} is OBSERVED on wire telemetry {_cite(*cand_observed_steps)}"
                )
            elif wire_check_steps:
                facts.append(
                    f"Adversary Presence: Query IP {cand_ip} has NO wire telemetry "
                    f"(0 active sessions, absent from ARP/neighbor tables; evaluate as SIMULATED / GHOST ATTACKER scenario) "
                    f"{_cite(*wire_check_steps)}"
                )
            else:
                facts.append(
                    f"Adversary Presence: Query IP {cand_ip} has NO wire telemetry in receipts "
                    "(evaluate as SIMULATED / HYPOTHETICAL adversary)"
                )

    # Gaps
    for i, (r, st) in enumerate(zip(receipts, statuses), 1):
        if st == "success":
            continue
        out_lines = [ln for ln in _raw(r).strip().splitlines() if ln.strip()]
        if len(out_lines) > 1 and out_lines[0].startswith("--- READING"):
            out_lines = out_lines[1:]
        first = out_lines[0] if out_lines else "no output"
        detail = _short_args(r.get("args"))
        detail = f" ({detail})" if detail else ""
        first_clean = first.strip().rstrip(".")
        if len(first_clean) > 240:
            truncated = first_clean[:237]
            if " " in truncated:
                truncated = truncated.rsplit(" ", 1)[0]
            err_msg = truncated + "..."
        else:
            err_msg = first_clean + "."
        facts.append(
            f"GAP: Step {i} `{r.get('tool', 'unknown')}`{detail} {st.upper()}: {err_msg} "
            "Anything that depends on it is UNKNOWN, not absent."
        )

    return facts


def render_facts(receipts: List[Dict[str, Any]], query: str = "") -> str:
    facts = build_facts(receipts, query=query)
    if not facts:
        return ""
    return FACTS_HEADING + "\n" + "\n".join(f"- {f}" for f in facts)


def split_facts_block(text: str) -> Tuple[str, str]:
    """Separate an existing facts block from the rest of the report."""
    lines = (text or "").split("\n")
    for idx, line in enumerate(lines):
        if line.strip() == FACTS_HEADING:
            end = idx + 1
            while end < len(lines) and lines[end].startswith("- "):
                end += 1
            block = "\n".join(lines[idx:end])
            rest = "\n".join(lines[:idx] + lines[end:]).lstrip("\n")
            return block, rest
    return "", text or ""


# =============================================================================
# Layer 2: claim annotation
# =============================================================================

def _expand_steps(spec: str) -> List[int]:
    steps: List[int] = []
    for part in re.split(r"\s*(?:,|and|&)\s*", spec):
        part = part.strip()
        if not part:
            continue
        rng = re.match(r"^(\d+)\s*[-–]\s*(\d+)$", part)
        if rng:
            a, b = int(rng.group(1)), int(rng.group(2))
            if 0 < b - a < 50:
                steps.extend(range(a, b + 1))
            continue
        if part.isdigit():
            steps.append(int(part))
    return steps


def _expand_pages(spec: str) -> List[int]:
    pages: List[int] = []
    for part in re.split(r"\s*(?:,|and|&)\s*", spec):
        rng = re.match(r"^(\d+)\s*(?:-|–|to)\s*(\d+)$", part.strip())
        if rng:
            a, b = int(rng.group(1)), int(rng.group(2))
            if 0 <= b - a <= 200:
                pages.extend(range(a, b + 1))
        elif part.strip().isdigit():
            pages.append(int(part.strip()))
    return pages


def _norm(text: str) -> str:
    """Normalize for quote matching: quote style and line wrapping are not content."""
    text = re.sub(r"[\"'“”‘’`]", "", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def _slice_range(receipt: Dict[str, Any]) -> Optional[Tuple[int, int]]:
    args = receipt.get("args") or {}
    if receipt.get("tool") != "query_knowledge_base" or args.get("action") != "read_slice":
        return None
    try:
        start = int(float(args.get("start_page")))
        end = int(float(args.get("end_page")))
        return start, end
    except (TypeError, ValueError):
        return None


def _read_pages_from_receipt(receipt: Dict[str, Any]) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    if rng := _slice_range(receipt):
        ranges.append(rng)
    if receipt.get("tool") == "query_knowledge_base":
        raw = _raw(receipt)
        found_pages = sorted({int(p) for p in re.findall(r"\[---\s*PAGE\s+(\d+)\s*---\]", raw)})
        if found_pages:
            # Group strictly contiguous runs: e.g. [1, 2, 3, 80] -> [(1, 3), (80, 80)]
            start = found_pages[0]
            prev = start
            for p in found_pages[1:]:
                if p == prev + 1:
                    prev = p
                else:
                    ranges.append((start, prev))
                    start = p
                    prev = p
            ranges.append((start, prev))
    return ranges


def _is_claim_line(stripped: str) -> bool:
    stripped = (stripped or "").strip()
    if not stripped:
        return False
    if stripped.rstrip("*_` \t").endswith(":"):
        if not _ASSERTIVE_VERBS_RE.search(stripped):
            return False
    min_len = 12 if _STATUS_KEYWORD_RE.search(stripped) else 25
    if len(stripped) < min_len:
        return False
    if stripped.startswith(("#", ">", "<", "---", "===", "|:", "| :", "```")):
        return False
    if re.match(r"^\[(?:CRITICAL|CAUTION|NORMAL|ENFORCING)\]\s+", stripped):
        return False
    if re.fullmatch(r"[\s|:\-]+", stripped):
        return False
    return True


def _append_marker(line: str, marker: str) -> str:
    stripped = line.rstrip()
    if stripped.endswith("|") and stripped.count("|") >= 2:
        return stripped[:-1].rstrip() + f" {marker} |"
    return stripped + f" {marker}"


def annotate_claims(text: str, receipts: List[Dict[str, Any]], query: str = "") -> Tuple[str, Dict[str, int]]:
    """
    Mark claim lines that are not backed by a SUCCESS receipt.
    Returns (annotated_text, stats). Idempotent: existing markers are replaced.
    """
    receipts = receipts or []
    statuses = [effective_status(r) for r in receipts]
    ok_raw = {i: _raw(r) for i, (r, st) in enumerate(zip(receipts, statuses), 1) if st == "success"}
    ok_args = [
        str(r.get("args") or "")
        for r, st in zip(receipts, statuses)
        if st == "success" and r.get("args")
    ]
    all_receipt_text = "\n".join(
        [_raw(r) for r in receipts]
        + [str(r.get("args") or "") for r in receipts if r.get("args")]
    )
    corpus = _norm(all_receipt_text + "\n" + (query or ""))
    ip_corpus = "\n".join(list(ok_raw.values()) + ok_args) + "\n" + (query or "")
    known_ips = set(_extract_all_ips(ip_corpus))
    for cidr in re.findall(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})(?![\d.])", ip_corpus):
        try:
            known_ips.add(str(ipaddress.ip_interface(cidr).network.network_address))
        except ValueError:
            pass
    for ip_str in list(known_ips):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj.is_private:
                net24 = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                known_ips.add(str(net24.network_address))
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                net64 = ipaddress.ip_network(f"{ip_str}/64", strict=False)
                known_ips.add(str(net64.network_address))
        except ValueError:
            pass
    read_ranges: Dict[int, List[Tuple[int, int]]] = {
        i: rngs for i, r in enumerate(receipts, 1)
        if statuses[i - 1] == "success" and (rngs := _read_pages_from_receipt(r))
    }
    device_raw_ips = set(_extract_all_ips("\n".join(ok_raw.values())))
    query_cand_ips = set(_extract_query_candidate_ips(query or ""))
    unobserved_query_ips = query_cand_ips - device_raw_ips
    stats = {"claims": 0, "cited_ok": 0, "inference": 0, "unverified": 0, "uncited": 0}

    cleaned = _MARKER_RE.sub("", text or "")
    lines = cleaned.split("\n")
    out: List[str] = []
    in_fence = False
    in_reasoning = False
    in_facts = False
    fence_ips: List[str] = []
    prev_table_header = False

    for idx, line in enumerate(lines):
        stripped = line.strip()

        # Region tracking -------------------------------------------------
        if stripped == FACTS_HEADING:
            in_facts = True
            out.append(line)
            continue
        if in_facts:
            if stripped.startswith("- "):
                out.append(line)
                continue
            in_facts = False
        if re.search(r"<REASONING>", stripped, re.IGNORECASE):
            in_reasoning = True
        if in_reasoning:
            out.append(line)
            if re.search(r"</REASONING>", stripped, re.IGNORECASE):
                in_reasoning = False
            continue
        if stripped.startswith("```"):
            if in_fence:
                unknown = sorted({ip for ip in fence_ips if ip not in known_ips})
                out.append(line)
                if unknown:
                    stats["unverified"] += 1
                    out.append(
                        f"`[UNVERIFIED: code block above uses {', '.join(unknown)}, not found in any receipt or the query]`"
                    )
                fence_ips = []
                in_fence = False
            else:
                in_fence = True
                out.append(line)
            continue
        if in_fence:
            fence_ips.extend(_extract_all_ips(line))
            out.append(line)
            continue

        # Table header rows (row directly followed by a separator row) are labels, not claims.
        nxt = lines[idx + 1].strip() if idx + 1 < len(lines) else ""
        is_table_header = stripped.startswith("|") and re.fullmatch(r"\|?[\s|:\-]+\|?", nxt or "x") is not None
        if is_table_header or not _is_claim_line(stripped):
            out.append(line)
            continue

        # Claim checks ------------------------------------------------------
        problems: List[str] = []
        cited: List[int] = []
        for m in _CITATION_RE.finditer(stripped):
            cited.extend(_expand_steps(m.group(1)))
        for step in sorted(set(cited)):
            if step < 1 or step > len(receipts):
                problems.append(f"Step {step} does not exist")
            elif statuses[step - 1] != "success":
                if not re.search(r"\b(?:unknown|failed|blocked|error)\b", stripped, re.IGNORECASE):
                    problems.append(f"Step {step} was {statuses[step - 1].upper()}")

        for domain, config in DISJOINT_TOOL_AFFINITY.items():
            if config["pattern"].search(stripped):
                cited_tools = [receipts[s - 1].get("tool", "") for s in cited if 1 <= s <= len(receipts)]
                if cited_tools and all(t in config["forbidden_tools"] for t in cited_tools):
                    problems.append(
                        f"cites {', '.join(dict.fromkeys(cited_tools))} which cannot provide {config['domain_name']} telemetry"
                    )

        scope_ranges: List[Tuple[int, int]] = []
        step_scoped = [read_ranges[s] for s in cited if s in read_ranges]
        if step_scoped:
            for r_list in step_scoped:
                scope_ranges.extend(r_list)
        else:
            for r_list in read_ranges.values():
                scope_ranges.extend(r_list)

        unread: List[int] = []
        for pm in _PAGE_RE.finditer(stripped):
            for p in _expand_pages(pm.group(1)):
                if p not in unread and not any(a <= p <= b for a, b in scope_ranges):
                    unread.append(p)
        if unread:
            label = "page" if len(unread) == 1 else "pages"
            problems.append(f"{label} {', '.join(str(p) for p in unread)} never read")

        for qm in _QUOTE_RE.finditer(stripped):
            raw_quote = next((g for g in qm.groups() if g), "")
            q_clean = raw_quote.strip()
            if len(q_clean) >= 20:
                fragments = [f for f in re.split(r"\.\.\.|…", q_clean) if len(f.strip()) >= 15]
                missing = [f for f in fragments if _norm(f).strip(" .,;") not in corpus]
                if missing:
                    problems.append("quoted text not found in any receipt")
            elif len(q_clean) >= 4:
                norm_quote = _norm(q_clean)
                entity_context = re.search(
                    rf"\b(?:rule|zone|profile|policy|application)\s+['\"“‘]{re.escape(q_clean)}['\"”’]",
                    stripped,
                    re.IGNORECASE,
                )
                if entity_context and norm_quote not in corpus:
                    if norm_quote not in {"any", "none", "drop", "allow", "reset", "alert"}:
                        problems.append(f"quoted entity '{q_clean}' not found in any receipt")

        unknown_ips = sorted({ip for ip in _extract_all_ips(stripped) if ip not in known_ips})
        if unknown_ips:
            problems.append(f"{', '.join(unknown_ips)} not found in any receipt or the query")

        # Check citations for unobserved query IPs (Ghost attacker / hallucinated wire presence)
        if cited and unobserved_query_ips:
            line_ips = _extract_all_ips(stripped)
            for cand_ip in line_ips:
                if cand_ip in unobserved_query_ips:
                    # If this is an absence assertion (e.g. "absent from ARP [Step 14]"), citation to an empty receipt is valid
                    if _ABSENCE_TERMS_RE.search(stripped):
                        continue
                    # Check if any cited step actually contains this IP in raw output or args
                    step_contains_ip = False
                    for s in cited:
                        if 1 <= s <= len(receipts):
                            r_step = receipts[s - 1]
                            r_text = _raw(r_step) + " " + str(r_step.get("args") or "")
                            if cand_ip in r_text:
                                step_contains_ip = True
                                break
                    if not step_contains_ip:
                        label = f"Step {cited[0]}" if len(cited) == 1 else f"Steps {', '.join(str(s) for s in cited)}"
                        problems.append(f"{label} contains no records for {cand_ip}")

        is_rec = bool(_RECOMMENDATION_RE.match(stripped))
        has_causal_claim = is_rec and bool(_CAUSAL_CONJUNCTIONS.search(stripped))
        has_signal = (not is_rec) or has_causal_claim
        if problems or cited or has_signal:
            stats["claims"] += 1

        if problems:
            stats["unverified"] += 1
            out.append(_append_marker(line, f"`[UNVERIFIED: {'; '.join(dict.fromkeys(problems))}]`"))
        elif cited:
            stats["cited_ok"] += 1
            out.append(line)
        elif _INFERENCE_RE.search(stripped):
            stats["inference"] += 1
            out.append(line)
        elif has_signal:
            stats["uncited"] += 1
            out.append(_append_marker(line, "`[UNCITED]`"))
        else:
            out.append(line)

    return "\n".join(out), stats


def claim_summary(stats: Dict[str, int]) -> str:
    """One-line banner for report headers."""
    if not stats.get("claims"):
        return "Enforced by code - no checkable claims found in the narrative."
    return (
        f"Enforced by code - {stats['cited_ok']} claim lines cite a successful step; "
        f"{stats.get('inference', 0)} labeled as inference; "
        f"{stats['unverified']} marked UNVERIFIED; {stats['uncited']} marked UNCITED. "
        "A citation proves the step exists, not that it supports the sentence."
    )


def apply_evidence(text: str, receipts: List[Dict[str, Any]], query: str = "") -> Tuple[str, Dict[str, int]]:
    """Facts block on top + annotated narrative. Safe to run repeatedly on its own output."""
    _, rest = split_facts_block(text or "")
    annotated, stats = annotate_claims(rest, receipts, query)
    facts = render_facts(receipts, query=query)
    combined = f"{facts}\n\n{annotated}" if facts else annotated
    return combined, stats
