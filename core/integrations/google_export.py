import os
import io
import re
import datetime
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

from core.pipeline.outcomes import effective_status
from core.pipeline.evidence import annotate_claims, claim_summary, render_facts, split_facts_block


def summarize_receipt_integrity(receipts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute the report integrity banner from receipt evidence.

    Counter-logic: every receipt succeeding proves the device answered; it does
    NOT prove the narrative claims are backed by those answers. Until claim-level
    verification exists, the banner never asserts the findings are verified.
    """
    statuses = [effective_status(r) for r in receipts]
    gaps = [
        (i, r.get("tool", "unknown"), st)
        for i, (r, st) in enumerate(zip(receipts, statuses), 1)
        if st != "success"
    ]
    ok = statuses.count("success")
    total = len(statuses)

    if total == 0:
        receipt_line = "NONE - no live device executions recorded. All findings are unverified."
    elif not gaps:
        receipt_line = f"{ok}/{total} executions returned device data."
    else:
        counts = ", ".join(
            f"{statuses.count(s)} {s}" for s in ("failed", "blocked", "skipped") if statuses.count(s)
        )
        steps = ", ".join(str(i) for i, _, _ in gaps)
        step_label = "Step" if len(gaps) == 1 else "Steps"
        receipt_line = (
            f"PARTIAL - {ok}/{total} executions returned device data ({counts}; {step_label} {steps}). "
            "Findings that depend on those steps are unverified."
        )

    return {
        "statuses": statuses,
        "gaps": gaps,
        "receipt_line": receipt_line,
        "claim_line": "Not enforced - narrative findings are model-generated; confirm each against the receipts in Section 3.",
    }


def sanitize_mermaid_labels(text: str) -> str:
    """Sanitize Mermaid code blocks to prevent syntax crashes caused by parentheses in edge labels."""
    if not text or "```mermaid" not in text:
        return text or ""

    def _clean_block(match: re.Match) -> str:
        block = match.group(1)
        cleaned = re.sub(
            r"\|([^|\n]+)\|",
            lambda m: f"|{re.sub(r'\s+', ' ', m.group(1).replace('(', ' - ').replace(')', '')).strip()}|",
            block,
        )
        return f"```mermaid\n{cleaned}\n```"

    return re.sub(r"```mermaid\s*\n([\s\S]*?)\n```", _clean_block, text)


def generate_incident_markdown(
    trace_id: str,
    query: str,
    verdict: str,
    receipts: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Format an investigation verdict and execution receipts into an executive incident report."""
    receipts = receipts or []
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    total_ms = sum(r.get("duration_ms", 0.0) for r in receipts)

    # Detect and format Range Simulation payload if present
    clean_verdict = verdict.strip()
    mermaid_section = ""
    is_simulation = False
    try:
        import json as _json
        parsed_payload = _json.loads(clean_verdict)
        if isinstance(parsed_payload, dict) and ("mermaid" in parsed_payload or "message" in parsed_payload):
            is_simulation = True
            clean_verdict = parsed_payload.get("message", clean_verdict).strip()
            raw_mermaid = parsed_payload.get("mermaid", "").strip()
            if raw_mermaid:
                mermaid_section = f"\n\n### Attack Vector Topology (Mermaid)\n```mermaid\n{raw_mermaid}\n```\n"
    except Exception:
        pass

    # Dynamic Report Title Detection
    lower_verdict = clean_verdict.lower()
    is_compiler = "compensating policy compilation" in lower_verdict or "policy compilation manifest" in lower_verdict
    if is_simulation:
        report_title = "Breach & Attack Simulation Report"
        query_title = "Adversary Attack Scenario"
        verdict_title = "Emulation Findings & Containment Posture"
    elif is_compiler:
        report_title = "Pre-Flight Threat-to-Policy Compilation Manifest"
        query_title = "Operator Policy Directives"
        verdict_title = "Autonomous Policy Compilation & Triage"
    else:
        report_title = "Incident Investigation Report"
        query_title = "Operator Query"
        verdict_title = "Executive Diagnosis & Root Cause"

    # Cognitive Scratchpad Interception & Formatting
    reasoning_match = re.search(r'<REASONING>([\s\S]*?)</REASONING>', clean_verdict, re.IGNORECASE)
    raw_reasoning = ""
    if reasoning_match:
        raw_reasoning = reasoning_match.group(1).strip()
        # Remove raw XML reasoning tag from verdict
        clean_verdict = clean_verdict[:reasoning_match.start()] + clean_verdict[reasoning_match.end():]

    # Evidence pass: code-computed facts + claim markers (idempotent on brain output)
    facts_md = ""
    ev_stats = None
    if not is_simulation:
        _, clean_verdict = split_facts_block(clean_verdict)
        clean_verdict, ev_stats = annotate_claims(clean_verdict, receipts, query)
        facts_md = render_facts(receipts, query=query)

    # Check for main structural heading to neatly tuck any preamble thoughts into Scratchpad
    split_pattern = r'(### (?:Compensating Policy Compilation Manifest|Incident Investigation Summary|Executive Health Summary)[\s\S]*)'
    split_match = re.search(split_pattern, clean_verdict, re.IGNORECASE)
    if split_match:
        preamble = clean_verdict[:split_match.start()].strip()
        manifest_body = split_match.group(1).strip()
        scratchpad_parts = []
        if preamble:
            scratchpad_parts.append(f"**Pre-Flight Analytical Notes:**\n{preamble}")
        if raw_reasoning:
            scratchpad_parts.append(f"**Hypothesis Matrix & Contradiction Trace:**\n```text\n{raw_reasoning}\n```")

        if scratchpad_parts:
            scratchpad_html = (
                "<details>\n"
                "<summary><b>Cognitive Scratchpad: Autonomous Hypothesis & Contradiction Trace</b> (Click to expand)</summary>\n\n"
                + "\n\n".join(scratchpad_parts)
                + "\n\n</details>\n\n"
            )
            clean_verdict = scratchpad_html + manifest_body
        else:
            clean_verdict = manifest_body
    elif raw_reasoning:
        scratchpad_html = (
            "<details>\n"
            "<summary><b>Cognitive Scratchpad: Autonomous Hypothesis & Contradiction Trace</b> (Click to expand)</summary>\n\n"
            f"```text\n{raw_reasoning}\n```\n\n"
            "</details>\n\n"
        )
        clean_verdict = scratchpad_html + clean_verdict.strip()

    if facts_md:
        clean_verdict = f"{facts_md}\n\n{clean_verdict}"
    
    clean_verdict = sanitize_mermaid_labels(clean_verdict)
    if mermaid_section:
        mermaid_section = sanitize_mermaid_labels(mermaid_section)

    integrity = summarize_receipt_integrity(receipts)
    if ev_stats is not None:
        integrity["claim_line"] = claim_summary(ev_stats)

    lines = [
        f"# Core Defense - {report_title}",
        f"**Trace ID:** `{trace_id}`  ",
        f"**Generated:** {timestamp}  ",
        f"**Receipt Integrity:** {integrity['receipt_line']}  ",
        f"**Claim Verification:** {integrity['claim_line']}  ",
        f"**Diagnostic Latency:** {total_ms:.1f}ms across {len(receipts)} execution steps  ",
        "",
        "---",
        "",
        f"## 1. {query_title}",
        f"> {query}",
        "",
        f"## 2. {verdict_title}",
        clean_verdict + mermaid_section,
        "",
        "---",
        "",
        "## 3. Execution Receipts & Audit Trail",
        "Deterministic CLI and API commands executed directly against Palo Alto Networks NGFWs:",
        ""
    ]

    if not receipts:
        lines.append("*No direct CLI/API executions recorded for this trace (diagnostic derived from local cache or offline baseline).*")
    else:
        lines.append("| Step | Tool / Command | Duration | Status | Arguments |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for i, r in enumerate(receipts, 1):
            tool = r.get("tool", "unknown")
            dur = f"{r.get('duration_ms', 0.0):.1f}ms"
            st = integrity["statuses"][i - 1].upper()
            args = r.get("args", {})
            key_arg = next(
                (f"{k}={args[k]}" for k in ("xpath", "target", "cmd", "command") if isinstance(args, dict) and args.get(k)),
                "",
            )
            args_str = key_arg or str(args)
            if len(args_str) > 90:
                args_str = args_str[:87] + "..."
            lines.append(f"| {i} | `{tool}` | {dur} | {st} | `{args_str}` |")
        
        lines.append("")
        lines.append("### Detailed Tool Outputs")
        for i, r in enumerate(receipts, 1):
            tool = r.get("tool", "unknown")
            dur = f"{r.get('duration_ms', 0.0):.1f}ms"
            st = integrity["statuses"][i - 1].upper()
            raw = r.get("raw_output") or r.get("output_snippet") or "No output captured"
            lines.append("<details>")
            lines.append(f"<summary><b>Step {i}: <code>{tool}</code> Execution Output</b> ({dur}, {st})</summary>\n")
            lines.append("```")
            lines.append(str(raw).strip())
            lines.append("```\n")
            lines.append("</details>\n")

    lines.extend([
        "---",
        "",
        "## 4. Verification & Recommendations",
    ])
    for step, tool, st in integrity["gaps"]:
        lines.append(
            f"- [ ] Step {step} `{tool}` {st.upper()}: conclusions that depend on it are unverified. "
            "Re-run the check or verify manually before acting."
        )
    lines.append("- [ ] Cross-check each finding in Section 2 against a SUCCESS receipt in Section 3.")
    lines.append("- [ ] Stage any recommended configuration in a candidate config and validate with `test` commands before commit.")

    return "\n".join(lines)



def _init_drive_write_service():
    """Initializes Google Drive API with write permissions using Service Account or ADC."""
    creds_file = os.getenv("GCP_SERVICE_ACCOUNT_FILE")
    scopes = [
        'https://www.googleapis.com/auth/drive.file',
        'https://www.googleapis.com/auth/drive'
    ]

    try:
        from googleapiclient.discovery import build
        from google.oauth2 import service_account

        if creds_file and os.path.exists(creds_file):
            logger.info(f"[EXPORT-GDOC] Authenticating with service account file: {creds_file}")
            creds = service_account.Credentials.from_service_account_file(creds_file, scopes=scopes)
        else:
            import google.auth
            logger.info("[EXPORT-GDOC] Authenticating using Application Default Credentials (ADC)...")
            creds, _ = google.auth.default(scopes=scopes)

        service = build('drive', 'v3', credentials=creds, cache_discovery=False)
        return service, None
    except Exception as e:
        logger.warning(f"[EXPORT-GDOC] Google Drive write service not available: {e}")
        return None, str(e)


def export_to_markdown_report(
    trace_id: str,
    query: str,
    verdict: str,
    receipts: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Generates direct structured Markdown report for local download without Google Drive dependency."""
    markdown_content = generate_incident_markdown(trace_id, query, verdict, receipts)
    prefix = "Simulation" if "mermaid" in verdict.lower() else "Incident"
    title = f"CoreDefense_{prefix}_{trace_id[:8]}"
    return {
        "success": True,
        "mode": "markdown_download",
        "doc_url": None,
        "title": title,
        "markdown": markdown_content,
        "message": f"Exported structured {prefix} report."
    }


def export_to_google_doc(
    trace_id: str,
    query: str,
    verdict: str,
    receipts: Optional[List[Dict[str, Any]]] = None,
    folder_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Exports investigation findings and execution receipts to a Google Doc if Google Drive API
    is configured, or returns the structured Markdown report for local download.
    """
    markdown_content = generate_incident_markdown(trace_id, query, verdict, receipts)
    title = f"CoreDefense_Incident_{trace_id[:8]}"

    # Check if local markdown export is explicitly forced
    if os.getenv("EXPORT_LOCAL_MD_ONLY", "false").lower() == "true":
        return {
            "success": True,
            "mode": "markdown_download",
            "doc_url": None,
            "title": title,
            "markdown": markdown_content,
            "message": "Exporting local Markdown report."
        }

    service, err_msg = _init_drive_write_service()
    if not service:
        return {
            "success": True,
            "mode": "markdown_download",
            "doc_url": None,
            "title": title,
            "markdown": markdown_content,
            "message": "Google Drive credentials not configured. Exporting local incident report."
        }

    target_folder = (
        folder_id
        or os.getenv("INCIDENT_REPORTS_FOLDER_ID")
        or os.getenv("GOOGLE_DRIVE_FOLDER_ID")
    )

    try:
        from googleapiclient.http import MediaIoBaseUpload

        file_metadata = {
            'name': f"Core Defense Incident - {trace_id[:8]}",
            'mimeType': 'application/vnd.google-apps.document'
        }
        if target_folder:
            file_metadata['parents'] = [target_folder]

        media = MediaIoBaseUpload(
            io.BytesIO(markdown_content.encode('utf-8')),
            mimetype='text/plain',
            resumable=True
        )

        try:
            created_file = service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id, webViewLink'
            ).execute()
        except Exception as create_err:
            if target_folder and "insufficientParentPermissions" in str(create_err):
                logger.warning(f"[EXPORT-GDOC] Service account lacks edit permissions for folder '{target_folder}'. Falling back to service account root Drive...")
                file_metadata.pop('parents', None)
                media = MediaIoBaseUpload(
                    io.BytesIO(markdown_content.encode('utf-8')),
                    mimetype='text/plain',
                    resumable=True
                )
                created_file = service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id, webViewLink'
                ).execute()
            else:
                raise create_err

        file_id = created_file.get('id')
        doc_url = created_file.get('webViewLink') or f"https://docs.google.com/document/d/{file_id}/edit"

        return {
            "success": True,
            "mode": "google_doc",
            "doc_url": doc_url,
            "doc_id": file_id,
            "title": title,
            "markdown": markdown_content,
            "message": "Successfully created Google Doc."
        }
    except Exception as e:
        logger.error(f"[EXPORT-GDOC] Error creating Google Doc: {e}")
        return {
            "success": True,
            "mode": "markdown_download",
            "doc_url": None,
            "title": title,
            "markdown": markdown_content,
            "message": f"Google Doc creation failed ({e}). Falling back to local report."
        }
