"""
Outcome Classification — single source of truth for tool execution status.

Used by the executor/brain (to label receipts) and by report exporters (to
compute integrity banners). Dependency-free so any layer can import it.
"""

# Tool failure conventions used across core/panos, core/integrations, and the
# executor itself. Matched against the START of the output only, so telemetry
# that merely contains the word "error" (logs, counters) is not misclassified.
FAILURE_PREFIXES = (
    "Tool Error:",
    "ERROR:",
    "Error:",
    "Error ",
    "Argument validation error",
    "Input Validation Error:",
    "PDF Extraction Failed",
    "Log Query Failed:",
    "Log Query Logic Failed:",
    "Report Query Failed:",
    "Report Query Logic Failed:",
    "Discovery Failed:",
    "Live Analytics Failed:",
    "Live Research Failed:",
    "Live Research Execution Failed",
    "HEALTH CHECK FAILED:",
)
IN_TOOL_BLOCK_PREFIX = "ERROR: Security Policy Block"

# Drive reads wrap their payload in a header line. A failure inside the wrapper
# (e.g. a 403 on a native Google Doc) is still a failure.
WRAPPER_PREFIXES = (
    "--- READING SLICE:",
    "--- READING CSV DATA:",
    "--- READING MARKDOWN:",
    "--- READING TEXT:",
)

STATUSES = ("success", "failed", "blocked", "skipped")


import re


def _is_single_body_failed(body: str) -> bool:
    """Return True if an unwrapped tool/sub-command output represents a failure."""
    b = (body or "").lstrip()
    if not b:
        return True
    if b.startswith(IN_TOOL_BLOCK_PREFIX) or b.startswith(FAILURE_PREFIXES):
        return True
    if b.startswith("<?xml") or b.startswith("<response"):
        if re.search(r'status=[\'"]error[\'"]', b[:200], re.IGNORECASE):
            return True
    if b.startswith("{"):
        if re.search(r'["\']status["\']\s*:\s*["\']error["\']', b[:100], re.IGNORECASE):
            return True
    return False


def classify_outcome(raw_output: str, blocked_by: str = "") -> str:
    """
    Classify a tool execution for the audit trail.

    Returns one of: "success", "failed", "blocked", "skipped".
    A receipt must never report success for an execution that produced no
    device data; downstream reports and Slot A/B probation derive truth from this.
    """
    if blocked_by == "duplicate":
        return "skipped"
    if blocked_by:
        return "blocked"
    text = (raw_output or "").lstrip()
    if text.startswith(IN_TOOL_BLOCK_PREFIX):
        return "blocked"
    if text.startswith(FAILURE_PREFIXES):
        return "failed"
    # Catch PAN-OS XML and JSON API error responses
    if text.startswith("<?xml") or text.startswith("<response"):
        if re.search(r'status=[\'"]error[\'"]', text[:200], re.IGNORECASE):
            return "failed"
    if text.startswith("{"):
        if re.search(r'["\']status["\']\s*:\s*["\']error["\']', text[:100], re.IGNORECASE):
            return "failed"
    if text.startswith(WRAPPER_PREFIXES):
        body = text.split("\n", 1)[1].lstrip() if "\n" in text else ""
        if _is_single_body_failed(body):
            return "failed"
    # Macro wrapper check: "--- CMD: <cmd> ---\n<body>"
    # If every sub-command in the macro failed, the macro produced zero device data.
    if text.startswith("--- CMD:"):
        blocks = [blk for blk in re.split(r'(?m)^--- CMD: ', text) if blk.strip()]
        if blocks:
            sub_statuses = []
            for blk in blocks:
                header, _, sub_body = blk.partition("\n")
                if "(FAILED) ---" in header or _is_single_body_failed(sub_body):
                    sub_statuses.append("failed")
                else:
                    sub_statuses.append("success")
            if all(s == "failed" for s in sub_statuses):
                return "failed"
    return "success"


def effective_status(receipt: dict) -> str:
    """
    Derive a receipt's status from its evidence rather than trusting the stored
    label. Receipts recorded before honest classification existed may say
    "success" over a "Tool Error" payload; this re-derives the truth.
    """
    stored = str(receipt.get("status", "")).lower()
    if stored in ("blocked", "skipped"):
        return stored
    raw = receipt.get("raw_output") or receipt.get("output_snippet") or ""
    return classify_outcome(raw, receipt.get("blocked_by", "") or "")
