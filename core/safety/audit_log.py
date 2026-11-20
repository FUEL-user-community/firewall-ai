"""
Append-only, hash-chained change-provenance log (`core/safety/audit_log.py`).

Every action where NEO proposes, repairs, injects, or gates a change on the live SSH session is
recorded as one JSON line. Each entry carries the SHA-256 of the previous entry, so silent edits,
deletions, or reordering are detectable with `verify_audit_chain()`.

Why this exists: lines injected by `@stage` are attributed by PAN-OS to the operator's admin account.
This log keeps the missing half of the story — what the model proposed, what the human saw, what the
human approved, and the exact bytes that reached the firewall.

Location: `NEO_AUDIT_LOG` env var, defaulting to `~/.neo/audit/neo_audit.jsonl` (outside the repo).
Set `NEO_AUDIT_LOG=off` to disable (not recommended outside tests).
"""

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_GENESIS_HASH = "0" * 64
_LOCK = threading.Lock()


def _resolve_audit_path() -> Optional[Path]:
    raw = os.getenv("NEO_AUDIT_LOG", "").strip()
    if raw.lower() in ("off", "0", "false", "none"):
        return None
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".neo" / "audit" / "neo_audit.jsonl"


def _entry_hash(entry_without_hash: Dict[str, Any]) -> str:
    canonical = json.dumps(entry_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.is_file():
        return _GENESIS_HASH
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, 65536)
            fh.seek(size - block)
            tail_lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        if not tail_lines:
            return _GENESIS_HASH
        return str(json.loads(tail_lines[-1].decode("utf-8")).get("hash") or _GENESIS_HASH)
    except Exception:
        return _GENESIS_HASH


def _scrub_field(val: Any) -> Any:
    """Recursively scrub strings before persisting provenance entries to disk."""
    from core.safety.scrubber import scrub

    if isinstance(val, str):
        return scrub(val)
    if isinstance(val, list):
        return [_scrub_field(item) for item in val]
    if isinstance(val, dict):
        return {str(k): _scrub_field(v) for k, v in val.items()}
    if isinstance(val, (int, float, bool)) or val is None:
        return val
    return scrub(str(val))


def record_audit_event(event: str, **fields: Any) -> Optional[Dict[str, Any]]:
    """
    Append one hash-chained event. Never raises: provenance logging must not break the operator's session.
    Returns the written entry (or None when disabled / on I/O failure).
    """
    path = _resolve_audit_path()
    if path is None:
        return None
    with _LOCK:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            entry: Dict[str, Any] = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "event": str(event),
                "operator": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
            }
            for key, val in fields.items():
                entry[key] = _scrub_field(val)
            entry["prev_hash"] = _last_hash(path)
            entry["hash"] = _entry_hash(entry)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return entry
        except Exception:
            return None


def verify_audit_chain(path: Optional[Path] = None) -> Tuple[bool, int, Optional[int]]:
    """Verify every entry's hash and prev_hash link. Returns (ok, entry_count, first_bad_line_number)."""
    target = Path(path) if path else _resolve_audit_path()
    if target is None or not target.is_file():
        return True, 0, None
    prev = _GENESIS_HASH
    count = 0
    with target.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, 1):
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                return False, count, line_no
            claimed = entry.pop("hash", None)
            if entry.get("prev_hash") != prev or claimed != _entry_hash(entry):
                return False, count, line_no
            prev = claimed
            count += 1
    return True, count, None


def read_recent_audit_events(limit: int = 10) -> List[Dict[str, Any]]:
    path = _resolve_audit_path()
    if path is None or not path.is_file():
        return []
    with path.open("r", encoding="utf-8") as fh:
        rows = [ln for ln in fh.read().splitlines() if ln.strip()]
    out: List[Dict[str, Any]] = []
    for raw in rows[-max(1, limit):]:
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out
