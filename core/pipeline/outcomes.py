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
    "PDF Extraction Failed",
)
IN_TOOL_BLOCK_PREFIX = "ERROR: Security Policy Block"

# Drive reads wrap their payload in a header line. A failure inside the wrapper
# (e.g. a 403 on a native Google Doc) is still a failure.
WRAPPER_PREFIXES = ("--- READING SLICE:", "--- READING CSV DATA:")

STATUSES = ("success", "failed", "blocked", "skipped")


def classify_outcome(raw_output: str, blocked_by: str = "") -> str:
    """
    Classify a tool execution for the audit trail.

    Returns one of: "success", "failed", "blocked", "skipped".
    A receipt must never report success for an execution that produced no
    device data; downstream reports derive their integrity banner from this.
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
    if text.startswith(WRAPPER_PREFIXES):
        body = text.split("\n", 1)[1].lstrip() if "\n" in text else ""
        if not body or body.startswith(FAILURE_PREFIXES):
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
