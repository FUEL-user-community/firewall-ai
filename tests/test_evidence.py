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
