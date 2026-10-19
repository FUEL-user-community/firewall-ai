"""
Evidence engine tests, built from the real receipts of trace a02a6ea8
(Gemini 3.8 Flash, threat-intel + hardening audit on fw-hq).

Each annotation test reproduces a defect found in the manual review of that
report, and asserts the code now catches it.
"""

from core.pipeline.evidence import (
    FACTS_HEADING,
    annotate_claims,
    apply_evidence,
    build_facts,
    claim_summary,
    step_header,
)
from core.pipeline.outcomes import classify_outcome


SYSTEM_INFO = """response:
  result:
    system:
      hostname: firewall-a
      ip-address: 192.168.1.254
      netmask: 255.255.255.0
      default-gateway: 192.168.1.1
      time: Mon Oct 12 07:04:10 2026
      devicename: firewall-a
      model: PA-VM
      sw-version: 10.0.12-h3
      global-protect-client-package-version: 0.0.0
      app-version: 8792-8469
      app-release-date: 2023/12/19 22:38:55 UTC
      av-version: 5488-6015
      av-release-date: 2026/03/11 11:02:36 UTC
      threat-version: 8792-8469
      threat-release-date: 2023/12/19 22:38:55 UTC
      wildfire-version: 1065692-1070004
      wildfire-release-date: 2026/03/15 22:27:00 UTC
      wildfire-rt: Disabled
      url-filtering-version: 0000.00.00.000
"""

LICENSE_INFO = """response:
  result:
    licenses:
      entry:
      - feature: Threat Prevention
        expires: May 21, 2026
        expired: 'yes'
      - feature: WildFire License
        expires: May 21, 2026
        expired: 'yes'
      - feature: GlobalProtect Portal
        expires: Never
        expired: 'no'
        vm-license-status: Updates disabled due to expired PA-VM license
      - feature: PA-VM
        expires: May 21, 2026
        expired: 'yes'
"""

ADMIN_GUIDE_8_18 = """--- READING SLICE: administrative-access-best-practices 10.1.pdf (Pages 8.0-18.0) ---

[--- PAGE 9 ---]
When you use a DP port to inspect traffic destined for the MGT port, do not enable management
protocols on the DP port. Enable management protocols only on the MGT port. To ensure the highest
level of security, limit
administrative access traffic such as web UI, API, and CLI to the dedicated management
interface unless site requirements prevent it.
[--- PAGE 12 ---]
The most secure action is to replace the default account with a new
local account because the username \u201cadmin\u201d is well known.
[--- PAGE 18 ---]
Specify the Permitted IP Addresses. Ideally, the only allowed IP addresses are
the bastion host\u2019s IP addresses and required IP addresses within the management network.
"""

ADMIN_GUIDE_1_5 = """--- READING SLICE: administrative-access-best-practices 10.1.pdf (Pages 1.0-5.0) ---

Keep Content and Software Updates Current ....................................................... 21
"""

INTERFACE_ALL = """response:
  result:
    ifnet:
      entry:
      - name: ethernet1/1
        zone: outside
        ip: 203.0.113.20/24
      - name: ethernet1/2
        zone: inside
        ip: 192.168.1.1/24
      - name: ethernet1/3
        zone: dmz
        ip: 192.168.50.1/24
      - name: ethernet1/4
        zone: danger
        ip: N/A
"""

ADMIN_SESSIONS = """response:
  result:
    admins:
      entry:
        admin: admin
        from: 192.168.1.20
        type: Web
        idle-for: 07:49:59s
        session-expiry: 11/10 23:15:56
"""

IFACE_CONFIG = """interface:
  ethernet:
    entry:
    - '@name': ethernet1/2
      layer3:
        ip:
          entry: 192.168.1.1/24
        interface-management-profile: ping-response-pages
    - '@name': ethernet1/3
      layer3:
        ip:
          entry: 192.168.50.1/24
        interface-management-profile: ping
    - '@name': ethernet1/1
      layer3:
        ip:
          entry: 203.0.113.20/24
"""

AQUARIUM_403 = (
    "--- READING SLICE: Aquarium_Intel_Feed (Pages 1.0-5.0) ---\n\n"
    "PDF Extraction Failed: <HttpError 403 ... fileNotDownloadable>"
)


def _r(tool, raw, args=None, status="success"):
    return {"tool": tool, "args": args or {}, "status": status, "raw_output": raw}


def _kb_slice(target, start, end, raw):
    return _r("query_knowledge_base", raw, {"target": target, "action": "read_slice",
                                            "start_page": start, "end_page": end})


RECEIPTS = [
    _r("query_knowledge_base", "--- KNOWLEDGE BASE DOCUMENTS ---\nDocument: panw_cves.csv", {"action": "list_contents"}),  # 1
    _r("system_info", SYSTEM_INFO, {"target_device": "fw-hq"}),                                   # 2
    _r("license_info", LICENSE_INFO, {"target_device": "fw-hq"}),                                 # 3
    _kb_slice("Threat Brief: Operation MidnightEclipse", 1.0, 3.0, "--- READING SLICE: brief ---\n\ntext"),  # 4
    _r("query_knowledge_base", "--- READING CSV DATA: panw_cves.csv ---\n\n| ID |", {"target": "panw_cves.csv"}),  # 5
    _kb_slice("Aquarium_Intel_Feed", 1.0, 5.0, AQUARIUM_403),                                     # 6 (labelled success, actually failed)
    _kb_slice("administrative-access-best-practices 10.1.pdf", 1.0, 5.0, ADMIN_GUIDE_1_5),       # 7
    _kb_slice("administrative-access-best-practices 10.1.pdf", 8.0, 18.0, ADMIN_GUIDE_8_18),     # 8
    _r("get_live_config",
       "ERROR: Security Policy Block - XPath '/config/devices/entry/deviceconfig/system' is not permitted.",
       {"target_device": "fw-hq", "xpath": "/config/devices/entry/deviceconfig/system"}, status="blocked"),  # 9
    _r("interface_all", INTERFACE_ALL, {"target_device": "fw-hq"}),                               # 10
    _r("admin_sessions", ADMIN_SESSIONS, {"target_device": "fw-hq"}),                             # 11
    _r("mgmt_clients", "response:\n  result:\n    clients: {}", {"target_device": "fw-hq"}),       # 12
    _r("get_live_config", IFACE_CONFIG, {"target_device": "fw-hq", "xpath": "/config/devices/entry/network/interface"}),  # 13
]

QUERY = "Pull whatever threat intelligence we have in the Drive knowledge base and tell me which of it applies to fw-hq."


def _facts_text():
    return "\n".join(build_facts(RECEIPTS))


def _marker_for(line, receipts=RECEIPTS):
    annotated, _ = annotate_claims(line, receipts, QUERY)
    return annotated


# =============================================================================
# Outcome classification: Drive failures hidden behind a success header
# =============================================================================

def test_wrapped_drive_failure_is_failed():
    assert classify_outcome(AQUARIUM_403) == "failed"


def test_wrapped_drive_success_is_success():
    assert classify_outcome(ADMIN_GUIDE_8_18) == "success"


def test_empty_wrapper_is_failed():
    assert classify_outcome("--- READING SLICE: x (Pages 1-2) ---") == "failed"


def test_step_header_format():
    assert step_header(9, "blocked") == "[Step 9 | BLOCKED]"


# =============================================================================
# Layer 1: computed facts (things the model missed or overstated)
# =============================================================================

def test_facts_version_and_content_age():
    facts = _facts_text()
    assert "PAN-OS 10.0.12-h3 on PA-VM" in facts
    assert "App/threat content 8792-8469, released 2023-12-19" in facts
    assert "STALE" in facts


def test_facts_av_and_wildfire_newer_than_threat_content():
    # The model claimed zero protection after Dec 2023; AV and WildFire are from 2026.
    facts = _facts_text()
    assert "Antivirus content 5488-6015, released 2026-03-11" in facts
    assert "WildFire content 1065692-1070004, released 2026-03-15" in facts
    assert "WildFire real-time updates: Disabled" in facts


def test_facts_url_db_and_gp_package():
    facts = _facts_text()
    assert "no URL database loaded" in facts
    assert "no GlobalProtect app hosted" in facts


def test_facts_licenses():
    facts = _facts_text()
    assert "Licenses EXPIRED (3)" in facts
    assert "GlobalProtect Portal (expires Never)" in facts
    assert "Updates disabled due to expired PA-VM license" in facts


def test_facts_mgmt_ip_on_user_lan():
    # Missed by the model: management IP shares the inside user subnet.
    facts = _facts_text()
    assert "Management IP 192.168.1.254 is in the same subnet as dataplane interface ethernet1/2" in facts
    assert "[Steps 2, 10]" in facts


def test_facts_mgmt_profiles_and_admin_session():
    facts = _facts_text()
    assert "ethernet1/2 = ping-response-pages" in facts
    assert "ethernet1/3 = ping" in facts
    assert "user 'admin' from 192.168.1.20 via Web, idle 07:49:59s" in facts


def test_facts_gaps_include_blocked_xpath_and_hidden_drive_failure():
    facts = _facts_text()
    assert "GAP: Step 9 `get_live_config` (xpath=/config/devices/entry/deviceconfig/system) BLOCKED" in facts
    assert "GAP: Step 6 `query_knowledge_base`" in facts
    assert "UNKNOWN, not absent" in facts


def test_facts_empty_receipts():
    assert build_facts([]) == []


# =============================================================================
# Layer 2: claim annotation (defects from the manual review)
# =============================================================================

def test_claim_on_blocked_step_is_unverified():
    line = "- The management interface has no permitted-ip list bound [Step 9]."
    assert "`[UNVERIFIED: Step 9 was BLOCKED]`" in _marker_for(line)


def test_claim_on_hidden_drive_failure_is_unverified():
    line = "- The Aquarium feed shows no active campaigns against PAN-OS [Step 6]."
    assert "Step 6 was FAILED" in _marker_for(line)


def test_fabricated_quote_and_unread_page_are_unverified():
    # Real defect: quoted text never appeared in any receipt; page 21 never read.
    line = ('5. **Expired Licenses (Violation of pp. 8, 21)** "Keep Content and Software Updates Current... '
            'ensure device maintains active security subscriptions."')
    out = _marker_for(line)
    assert "UNVERIFIED" in out
    assert "page 21 never read" in out
    assert "quoted text not found in any receipt" in out


def test_verbatim_quote_with_curly_quotes_passes():
    line = ('- Guide: "The most secure action is to replace the default account with a new local account '
            'because the username \'admin\' is well known." [Step 8, p. 12]')
    assert "UNVERIFIED" not in _marker_for(line)


def test_elided_quote_is_unverified():
    # Real defect: the model dropped "such as web UI, API, and CLI" from the quote.
    line = ('- Guide: "limit administrative access traffic to the dedicated management interface." '
            '[Step 8, p. 9]')
    assert "quoted text not found" in _marker_for(line)


def test_cited_page_outside_cited_slice_is_unverified():
    line = "- The guide requires an idle timeout on p. 16 [Step 7]."
    assert "page 16 never read" in _marker_for(line)


def test_guide_step_reference_is_not_a_receipt_citation():
    line = "1. **Default admin account in use (Violation of guide STEP 1, pp. 12-13)** confirmed [Step 11]."
    assert "UNVERIFIED" not in _marker_for(line)


def test_unknown_ip_in_text_is_unverified():
    line = "- Publish the server on 203.0.113.21 using a new NAT rule [Step 10]."
    assert "203.0.113.21 not found" in _marker_for(line)


def test_derived_subnet_address_is_known():
    line = "- Any host in 192.168.1.0/24 can reach the management IP [Steps 2, 10]."
    assert "UNVERIFIED" not in _marker_for(line)


def test_unknown_ip_in_code_block_is_flagged_after_fence():
    text = "Remediation:\n```panos\nset deviceconfig system permitted-ip 192.168.1.50/32\n```"
    out = _marker_for(text)
    assert "code block above uses 192.168.1.50" in out
    assert "set deviceconfig system permitted-ip 192.168.1.50/32\n```\n`[UNVERIFIED" in out


def test_uncited_fact_is_marked():
    line = "- Administrative access relies entirely on local database authentication for admin."
    assert line + " `[UNCITED]`" == _marker_for(line)


def test_labeled_inference_is_not_marked():
    line = "- Inference: CVE-2026-0308 likely does not affect 10.0 because 10.2 is not listed."
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert annotated == line
    assert stats["inference"] == 1


def test_recommendations_are_not_marked_uncited():
    text = ("- Re-activate base PA-VM licensing and Threat Prevention subscriptions.\n"
            "2. **Upgrade** the firewall to a supported PAN-OS release before renewing content.\n"
            "- Strictly restrict all inbound access to the management IP to the bastion host.")
    out, stats = annotate_claims(text, RECEIPTS, QUERY)
    assert "UNCITED" not in out
    assert stats["uncited"] == 0


def test_nonexistent_step_marker_goes_inside_table_row():
    row = "| CVE-2026-0310 | 9.2 | Applies to unsupported 10.0 [Step 20] |"
    out = _marker_for(row)
    assert out.endswith("`[UNVERIFIED: Step 20 does not exist]` |")


def test_table_header_and_headings_are_not_claims():
    text = "## 3. Compliance Audit\n| Requirement | Live State |\n| :--- | :--- |"
    out, stats = annotate_claims(text, RECEIPTS, QUERY)
    assert out == text
    assert stats["claims"] == 0


def test_well_cited_claim_passes():
    line = "- fw-hq runs PAN-OS 10.0.12-h3 with threat content from 2023-12-19 [Step 2]."
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert annotated == line
    assert stats["cited_ok"] == 1


def test_reasoning_block_is_skipped():
    text = "<REASONING>\nmaybe 10.9.9.9 is the bastion\n</REASONING>\nDone."
    out, _ = annotate_claims(text, RECEIPTS, QUERY)
    assert "UNVERIFIED" not in out


# =============================================================================
# End-to-end: facts on top, idempotent, banner
# =============================================================================

REPORT = """### Incident Investigation Summary
- fw-hq runs PAN-OS 10.0.12-h3 [Step 2].
- The management interface has no permitted-ip list [Step 9].
- Administrative access relies on local authentication only.
"""


def test_apply_evidence_puts_facts_first_and_marks_claims():
    out, stats = apply_evidence(REPORT, RECEIPTS, QUERY)
    assert out.startswith(FACTS_HEADING)
    assert "`[UNVERIFIED: Step 9 was BLOCKED]`" in out
    assert "`[UNCITED]`" in out
    assert stats["cited_ok"] == 1 and stats["unverified"] == 1 and stats["uncited"] == 1


def test_apply_evidence_is_idempotent():
    once, s1 = apply_evidence(REPORT, RECEIPTS, QUERY)
    twice, s2 = apply_evidence(once, RECEIPTS, QUERY)
    assert once == twice
    assert s1 == s2


def test_claim_summary_wording():
    _, stats = apply_evidence(REPORT, RECEIPTS, QUERY)
    line = claim_summary(stats)
    assert "1 marked UNVERIFIED" in line and "1 marked UNCITED" in line
    assert "not that it supports the sentence" in line


def test_export_banner_uses_computed_claims():
    from core.integrations.google_export import generate_incident_markdown
    md = generate_incident_markdown("a02a6ea8", QUERY, REPORT, RECEIPTS)
    assert "**Claim Verification:** Enforced by code" in md
    assert FACTS_HEADING in md
    assert "xpath=/config/devices/entry/deviceconfig/system" in md
    # Step 6 hidden failure now counted honestly in the receipt banner
    assert "Steps 6, 9" in md


def test_remediation_subnet_derived_from_known_ip_is_verified():
    """Verify that valid /24 network address derived from known host IP (e.g. 192.168.1.0 from 192.168.1.254) passes without unverified warning."""
    query = "Check firewall 192.168.1.254"
    receipts = [{"raw_output": "ip-address: 192.168.1.254", "tool": "test_routing_fib", "args": {}}]
    text = "```panos\nset deviceconfig system permitted-ip [ 192.168.1.0/24 ]\n```"
    out, stats = annotate_claims(text, receipts, query)
    assert "UNVERIFIED" not in out
    assert stats["unverified"] == 0


def test_hallucinated_ip_in_code_block_is_unverified():
    """Verify that genuinely hallucinated foreign IP in a code block is caught and flagged."""
    query = "Check firewall 192.168.1.254"
    receipts = [{"raw_output": "ip-address: 192.168.1.254", "tool": "test_routing_fib", "args": {}}]
    text = "```panos\nset rulebase security rules bad to 10.99.99.1\n```"
    out, stats = annotate_claims(text, receipts, query)
    assert "[UNVERIFIED: code block above uses 10.99.99.1" in out
    assert stats["unverified"] == 1


def test_read_pages_from_list_contents_receipt():
    """Verify that auto-extracted pages from query_knowledge_base(action='list_contents') are credited."""
    receipts = [{
        "tool": "query_knowledge_base",
        "args": {"action": "list_contents", "target": "CVE"},
        "raw_output": (
            "--- KNOWLEDGE BASE DOCUMENTS ---\nDocument: cve-matrix.pdf\n"
            "--- EXTRACTING TABLE OF CONTENTS (Pages 1-5) ---\n"
            "[--- PAGE 1 ---]\nOverview of CVE-2024-3400\n"
            "[--- PAGE 2 ---]\nAffected versions\n"
            "[--- PAGE 3 ---]\nWorkarounds and mitigation\n"
            "[--- PAGE 4 ---]\nIOCs\n"
            "[--- PAGE 5 ---]\nReferences\n"
        )
    }]
    line = "- Emergency advisory details SAML vulnerability mitigations [Step 1, pp. 1, 3]."
    out, stats = annotate_claims(line, receipts, "")
    assert "UNVERIFIED" not in out
    assert stats["cited_ok"] == 1
    assert stats["unverified"] == 0


def test_markdown_bold_header_ending_colon_is_not_claim():
    """Verify that bold section headers ending with colons (:**) are not flagged as uncited claims."""
    headers = [
        "- **Counter-Logic (Empirical Telemetry & Physical Reality):**",
        "2. **Long-Term Architectural Remediation:**",
        "- **Immediate Tactical Hardening:**",
    ]
    for header in headers:
        out, stats = annotate_claims(header, [], "")
        assert "UNCITED" not in out
        assert stats["claims"] == 0
        assert stats["uncited"] == 0


def test_format3_severity_banner_is_not_claim():
    """Verify that Format 3 severity title banners like [CRITICAL] are not flagged as uncited claims."""
    banner = "[CRITICAL] Management Plane Layer 2 Bypass & Authentication Vulnerability Assessment"
    out, stats = annotate_claims(banner, [], "")
    assert "UNCITED" not in out
    assert stats["claims"] == 0
    assert stats["uncited"] == 0


def test_operator_premise_logic_is_counted_as_inference():
    """Verify that operator premise lines starting with Logic (...) are counted as inference rather than uncited."""
    query = "Investigate if attacker 192.168.1.100 can reach firewall 192.168.1.254"
    premise = (
        "- **Logic (Attack Vector & Operator Premise):** Attacker at 192.168.1.100 reaches XML API/Web GUI "
        "at 192.168.1.254:443 via dataplane transit through ethernet1/2."
    )
    out, stats = annotate_claims(premise, [], query)
    assert "UNCITED" not in out
    assert stats["inference"] == 1
    assert stats["uncited"] == 0


def test_cartographer_context_ips_are_known():
    """Verify that IPs introduced by Cartographer topology context are recognized and not flagged as unknown."""
    cartographer_context = '{"active_admin_sessions": [{"admin": "admin", "from": "192.168.1.20", "type": "Web"}]}'
    evidence_context = f"Check firewall 192.168.1.254\n{cartographer_context}"
    text = (
        "- Preserved active administrator session from 192.168.1.20 in remediation.\n"
        "```panos\nset deviceconfig system permitted-ip 192.168.1.20/32\n```"
    )
    out, stats = annotate_claims(text, [], evidence_context)
    assert "UNVERIFIED" not in out
    assert stats["unverified"] == 0


def test_facts_gap_clean_word_truncation():
    """Verify that GAP facts lines preserve full messages under 240 chars and cleanly truncate longer errors."""
    long_error = (
        "ERROR: Security Policy Block - XPath '/config/devices/entry/deviceconfig/system' is not permitted. "
        "Reason: XPath '/config/devices/entry/deviceconfig/system' is not in the safe configuration allowlist."
    )
    receipts = [{
        "tool": "get_live_config",
        "args": {"xpath": "/config/devices/entry/deviceconfig/system"},
        "raw_output": long_error,
        "blocked_by": "policy"
    }]
    facts = build_facts(receipts)
    assert len(facts) == 1
    # Full message preserved under 240 chars without awkward mid-sentence cut
    assert "safe configuration allowlist." in facts[0]
    assert "is ." not in facts[0]

    # Verify message over 240 chars truncates cleanly with ellipsis
    massive_error = long_error + " Extra diagnostic trace details that push total length well past 240 characters."
    receipts_massive = [{
        "tool": "get_live_config",
        "args": {"xpath": "/config/devices/entry/deviceconfig/system"},
        "raw_output": massive_error,
        "blocked_by": "policy"
    }]
    facts_massive = build_facts(receipts_massive)
    assert "..." in facts_massive[0]
    assert facts_massive[0].endswith("Anything that depends on it is UNKNOWN, not absent.")


def test_two_short_quotes_on_same_line_do_not_bridge():
    """Verify that two short quoted words (<20 chars) on the same line do not bridge unquoted prose into false quote."""
    line = 'At line 73 of core/panos/config.py, "certificate" is in DISALLOWED_XPATH_KEYWORDS [Step 2] and blocked by the substring "certificate".'
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert "quoted text not found in any receipt" not in annotated
    assert stats["unverified"] == 0
    assert stats["cited_ok"] == 1


def test_explicit_failure_or_block_report_is_exempt_from_unverified():
    """Verify that reporting a step failed or was blocked is not marked [UNVERIFIED: Step N was FAILED/BLOCKED]."""
    line_blocked = "- Permitted IPs: UNKNOWN (Step 9 was blocked by policy) [Step 9]."
    annotated_b, stats_b = annotate_claims(line_blocked, RECEIPTS, QUERY)
    assert "UNVERIFIED" not in annotated_b
    assert stats_b["cited_ok"] == 1
    assert stats_b["unverified"] == 0

    line_failed = "- Threat feed retrieval failed in Step 6 [Step 6]."
    annotated_f, stats_f = annotate_claims(line_failed, RECEIPTS, QUERY)
    assert "UNVERIFIED" not in annotated_f
    assert stats_f["cited_ok"] == 1
    assert stats_f["unverified"] == 0


def test_long_header_ending_with_colon_is_not_claim():
    """Verify that long numbered/bulleted section headers ending with a colon (>120 chars) are exempt from claim checks."""
    header = (
        "2. **Blindspot 2 — core/panos/cartographer.py (Missing GlobalProtect and Telemetry Extraction "
        "Required for CVE-2024-3400 / CVE-2020-2021 Security Posture Auditing):**"
    )
    assert len(header) > 120
    annotated, stats = annotate_claims(header, [], "")
    assert "UNCITED" not in annotated
    assert stats["claims"] == 0
    assert stats["uncited"] == 0


def test_tested_args_ips_are_credited_in_ip_corpus():
    """Verify external test IP supplied in tool args is recognized in ip_corpus and not flagged as unverified."""
    receipts = [{
        "tool": "test_security_policy",
        "args": {"source": "192.168.1.50", "destination": "203.0.113.50", "port": 443},
        "raw_output": "response:\n  result: ''",
        "status": "success"
    }]
    line = "- Probed security policy match to external destination 203.0.113.50 [Step 1]."
    annotated, stats = annotate_claims(line, receipts, "")
    assert "203.0.113.50 not found" not in annotated
    assert "UNVERIFIED" not in annotated
    assert stats["cited_ok"] == 1
    assert stats["unverified"] == 0


def test_causal_recommendation_requires_citation_or_marked_uncited():
    """Verify that a recommendation smuggling a causal assertion gets caught as a claim."""
    line = "- Configure rate-limiting immediately to mitigate the active attack which caused the outage."
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert "[UNCITED]" in annotated
    assert stats["uncited"] == 1


def test_ipv6_hallucination_is_unverified():
    """Verify that an unverified IPv6 address is caught and flagged."""
    line = "- Traffic is routed to gateway 2001:db8:85a3::8a2e:370:7334 [Step 2]."
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert "2001:db8:85a3::8a2e:370:7334 not found" in annotated
    assert stats["unverified"] == 1


def test_short_quoted_firewall_entity_is_unverified():
    """Verify that a quoted firewall entity (<20 chars) not in receipts is flagged."""
    line = "- Packet was dropped by rule 'fake-deny-p2p' in the security policy [Step 2]."
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert "quoted entity 'fake-deny-p2p' not found in any receipt" in annotated
    assert stats["unverified"] == 1


def test_multi_device_facts_fleet():
    """Verify that multi-device receipts produce fact entries for all queried firewalls."""
    dev2_sys = SYSTEM_INFO.replace("firewall-a", "firewall-b").replace("10.0.12-h3", "11.1.2")
    fleet_receipts = [
        {"tool": "system_info", "status": "success", "raw_output": SYSTEM_INFO, "args": {"target_device": "fw-a"}},
        {"tool": "system_info", "status": "success", "raw_output": dev2_sys, "args": {"target_device": "fw-b"}},
    ]
    facts = build_facts(fleet_receipts)
    joined = "\n".join(facts)
    assert "Device [firewall-a]: PAN-OS 10.0.12-h3" in joined
    assert "Device [firewall-b]: PAN-OS 11.1.2" in joined


def test_short_status_claim_is_marked_uncited():
    """Verify that short lines (<25 chars) asserting status are treated as claims."""
    line = "- Tunnel 1 is down."
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert "[UNCITED]" in annotated
    assert stats["uncited"] == 1


def test_contiguous_page_intervals_rejects_gap_pages():
    """Verify that non-contiguous page outputs do not bridge gap pages into verified ranges."""
    gap_receipts = [{
        "tool": "query_knowledge_base",
        "status": "success",
        "args": {"action": "search"},
        "raw_output": "[--- PAGE 1 ---]\nIntroduction\n[--- PAGE 50 ---]\nIndex and References",
    }]
    line = "- The hardening guide recommends disabling telnet on p. 25 [Step 1]."
    annotated, stats = annotate_claims(line, gap_receipts, "")
    assert "page 25 never read" in annotated
    assert stats["unverified"] == 1


def test_colon_ending_assertion_is_marked_uncited():
    """Verify that a factual claim ending with a colon is audited as a claim and marked uncited."""
    line = "- Root cause was determined to be an unassigned security zone on ethernet1/1:"
    annotated, stats = annotate_claims(line, [], "")
    assert "[UNCITED]" in annotated
    assert stats["uncited"] == 1


def test_semantic_citation_hijacking_is_unverified():
    """Verify that citing an unrelated system_info tool for a BGP/routing claim is flagged."""
    line = "- BGP peer 192.168.1.20 is down due to route flapping [Step 2]."
    annotated, stats = annotate_claims(line, RECEIPTS, QUERY)
    assert "cannot provide routing/BGP telemetry" in annotated
    assert stats["unverified"] == 1


def test_deterministic_policy_and_fib_verdicts_in_facts():
    """Verify that test_security_policy and test_routing_fib produce deterministic facts."""
    verdict_receipts = [
        {
            "tool": "test_security_policy",
            "status": "success",
            "args": {"source": "10.0.1.5", "destination": "192.168.1.1", "port": 443},
            "raw_output": "response:\n  result:\n    rules:\n      entry:\n        rule: Block-Web-Inbound\n        action: deny\n        index: 14\n"
        },
        {
            "tool": "test_routing_fib",
            "status": "success",
            "args": {"ip": "8.8.8.8"},
            "raw_output": "response:\n  result:\n    fib:\n      entry:\n        interface: ethernet1/1\n        next-hop: 203.0.113.1\n"
        }
    ]
    facts = build_facts(verdict_receipts)
    facts_str = "\n".join(facts)
    assert "Security policy verdict (10.0.1.5 -> 192.168.1.1:443): rule 'Block-Web-Inbound' (index 14) -> action DENY [Step 1]" in facts_str
    assert "Routing FIB verdict for 8.8.8.8: egress interface ethernet1/1, next-hop 203.0.113.1 [Step 2]" in facts_str


def test_adversary_presence_ghost_attacker_detected_in_facts():
    """Verify that an unobserved IP in the query with empty ARP telemetry is classified as SIMULATED / GHOST ATTACKER."""
    receipts = [
        {"tool": "system_info", "status": "success", "raw_output": SYSTEM_INFO, "args": {}},
        {"tool": "interface_all", "status": "success", "raw_output": INTERFACE_ALL, "args": {}},
        {"tool": "execute_operational_command", "status": "success", "args": {"cmd": "show arp dynamic"}, "raw_output": "response:\n  result:\n    entries: {}\n"}
    ]
    query = "Host 192.168.1.100 is probing 192.168.1.254 and 192.168.1.1 on port 443"
    facts = build_facts(receipts, query=query)
    facts_str = "\n".join(facts)
    assert "Adversary Presence: Query IP 192.168.1.100 has NO wire telemetry (0 active sessions, absent from ARP/neighbor tables; evaluate as SIMULATED / GHOST ATTACKER scenario) [Step 3]" in facts_str
    # Verify local firewall IPs (192.168.1.254, 192.168.1.1) are NOT misclassified as adversaries
    assert "Adversary Presence: Query IP 192.168.1.254" not in facts_str
    assert "Adversary Presence: Query IP 192.168.1.1 " not in facts_str


def test_adversary_presence_observed_live_on_wire():
    """Verify that an IP in the query with corroborating device telemetry is classified as OBSERVED."""
    receipts = [
        {"tool": "admin_sessions", "status": "success", "raw_output": ADMIN_SESSIONS, "args": {}}
    ]
    query = "Investigate active host 192.168.1.20"
    facts = build_facts(receipts, query=query)
    facts_str = "\n".join(facts)
    assert "Adversary Presence: Query IP 192.168.1.20 is OBSERVED on wire telemetry [Step 1]" in facts_str


def test_claim_citing_empty_arp_step_for_ghost_ip_is_unverified():
    """Verify that citing an empty ARP tool step to assert active wire resolution for a ghost IP is marked UNVERIFIED."""
    receipts = [
        {"tool": "system_info", "status": "success", "raw_output": SYSTEM_INFO, "args": {}},
        {"tool": "execute_operational_command", "status": "success", "args": {"cmd": "show arp dynamic"}, "raw_output": "response:\n  result:\n    entries: {}\n"}
    ]
    query = "Host 192.168.1.100 is probing 192.168.1.254"
    line = "- Host 192.168.1.100 resolves 192.168.1.254 via Layer 2 ARP [Step 2]."
    annotated, stats = annotate_claims(line, receipts, query)
    assert "`[UNVERIFIED: Step 2 contains no records for 192.168.1.100]`" in annotated
    assert stats["unverified"] == 1
    assert stats["cited_ok"] == 0


def test_claim_asserting_absence_citing_empty_arp_passes():
    """Verify that citing an empty ARP tool step to assert absence/unresolved state passes as cited_ok."""
    receipts = [
        {"tool": "execute_operational_command", "status": "success", "args": {"cmd": "show arp dynamic"}, "raw_output": "response:\n  result:\n    entries: {}\n"}
    ]
    query = "Host 192.168.1.100 is probing 192.168.1.254"
    line = "- Host 192.168.1.100 is absent from active ARP telemetry [Step 1]."
    annotated, stats = annotate_claims(line, receipts, query)
    assert "UNVERIFIED" not in annotated
    assert stats["cited_ok"] == 1
    assert stats["unverified"] == 0


def test_claim_citing_policy_test_with_tested_ip_passes():
    """Verify that citing a policy simulation step whose args tested the IP passes without unverified warning."""
    receipts = [
        {
            "tool": "test_security_policy",
            "status": "success",
            "args": {"source": "192.168.1.100", "destination": "192.168.1.1", "port": 443},
            "raw_output": "response:\n  result:\n    rules:\n      entry:\n        rule: Allow-Inside-Out\n        action: allow\n"
        }
    ]
    query = "Host 192.168.1.100 is probing 192.168.1.1"
    line = "- Security policy verdict for 192.168.1.100 -> 192.168.1.1:443 allows traffic [Step 1]."
    annotated, stats = annotate_claims(line, receipts, query)
    assert "UNVERIFIED" not in annotated
    assert stats["cited_ok"] == 1
    assert stats["unverified"] == 0


def test_cve_post_dating_content_produces_blindspot_fact():
    """Verify that a queried CVE post-dating active threat content produces a Content Blindspot fact."""
    receipts = [
        {"tool": "system_info", "status": "success", "raw_output": SYSTEM_INFO, "args": {}}
    ]
    query = "Investigate whether device is vulnerable to CVE-2024-3400 and CVE-2020-2021"
    facts = build_facts(receipts, query=query)
    facts_str = "\n".join(facts)
    # CVE-2024-3400 post-dates 2023 threat content and must be flagged
    assert "Content Blindspot: Queried CVE-2024-3400 post-dates active App/threat content (released 2023-12-19); threat engine has NO signatures for this vulnerability [Step 1]" in facts_str
    # CVE-2020-2021 pre-dates 2023 and must NOT be flagged
    assert "Content Blindspot: Queried CVE-2020" not in facts_str


def test_routing_fib_for_mgmt_ip_has_caution_note():
    """Verify that Routing FIB lookup for the dedicated MGT IP includes a CAUTION note that FIB does not forward to MGT NIC."""
    receipts = [
        {"tool": "system_info", "status": "success", "raw_output": SYSTEM_INFO, "args": {}},
        {
            "tool": "test_routing_fib",
            "status": "success",
            "args": {"ip": "192.168.1.254"},
            "raw_output": "response:\n  result:\n    fib:\n      entry:\n        interface: ethernet1/2\n        next-hop: 0.0.0.0\n"
        }
    ]
    facts = build_facts(receipts)
    facts_str = "\n".join(facts)
    assert "Routing FIB verdict for 192.168.1.254: egress interface ethernet1/2, next-hop 0.0.0.0 (CAUTION: target is dedicated MGT interface; dataplane FIB does not forward to out-of-band management port) [Step 2]" in facts_str


def test_security_policy_to_local_dataplane_interface_has_listener_note():
    """Verify that a security policy verdict allowing management port to a local dataplane interface notes listener requirement."""
    receipts = [
        {"tool": "interface_all", "status": "success", "raw_output": INTERFACE_ALL, "args": {}},
        {
            "tool": "test_security_policy",
            "status": "success",
            "args": {"source": "192.168.1.100", "destination": "192.168.1.1", "port": "443"},
            "raw_output": "response:\n  result:\n    rules:\n      entry:\n        rule: Allow-Inside-Out\n        action: allow\n"
        }
    ]
    facts = build_facts(receipts)
    facts_str = "\n".join(facts)
    assert "Security policy verdict (192.168.1.100 -> 192.168.1.1:443): rule 'Allow-Inside-Out' -> action ALLOW (NOTE: destination is local dataplane interface ethernet1/2; requires Interface Management Profile with service enabled to accept management traffic) [Step 2]" in facts_str




