"""
Human-in-the-Loop (HITL) Approval Gate
Manages write operation authorization signatures with persistent HMAC secrets (L1).
Supports autopilot auto-approval, simulated interactive review, and true interactive approval queue.
"""
import os
import hmac
import time
import hashlib
import json
import logging
import threading
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = [
    "ApprovalRequest",
    "ApprovalResult",
    "AutoApproveProvider",
    "SimulatedInteractiveProvider",
    "InteractiveHITLProvider",
    "get_hitl_provider",
    "get_pending_approvals",
    "submit_approval_decision",
    "clear_pending_approvals",
]

_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"

_HITL_SECRET_RAW = os.getenv("HITL_SECRET")
if not _HITL_SECRET_RAW:
    import secrets as _secrets
    _HITL_SECRET_RAW = _secrets.token_hex(32)
    os.environ["HITL_SECRET"] = _HITL_SECRET_RAW
    try:
        from dotenv import set_key
        if _ENV_FILE.exists():
            set_key(str(_ENV_FILE), "HITL_SECRET", _HITL_SECRET_RAW)
            logger.info(f"[HITL] Persisted new HITL_SECRET to {_ENV_FILE}")
    except Exception as e:
        logger.warning(f"[HITL] Could not persist HITL_SECRET to .env: {e}")

_HITL_SECRET = _HITL_SECRET_RAW.encode()


@dataclass
class ApprovalRequest:
    tool_name: str
    tool_args: dict
    user_id: str
    trace_id: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    channel_id: str = ""

    @property
    def summary(self) -> str:
        args_str = ", ".join(f"{k}={v}" for k, v in self.tool_args.items())
        return f"{self.tool_name}({args_str})"

    @property
    def request_id(self) -> str:
        payload = f"{self.tool_name}:{json.dumps(self.tool_args, sort_keys=True)}:{self.trace_id}"
        return hmac.new(_HITL_SECRET, payload.encode(), hashlib.sha256).hexdigest()[:12]


@dataclass
class ApprovalResult:
    approved: bool
    approver_id: str = ""
    reason: str = ""
    signature: str = ""
    latency_ms: int = 0


@dataclass
class PendingApproval:
    request: ApprovalRequest
    created_at: float
    event: threading.Event
    decision: Optional[ApprovalResult] = None


_PENDING_APPROVALS: dict[str, PendingApproval] = {}
_APPROVAL_LOCK = threading.Lock()


def get_pending_approvals() -> list[dict]:
    """Return all pending approval requests currently waiting in the interactive queue."""
    with _APPROVAL_LOCK:
        now = time.time()
        results = []
        for req_id, pending in _PENDING_APPROVALS.items():
            req = pending.request
            results.append({
                "request_id": req.request_id,
                "tool_name": req.tool_name,
                "tool_args": req.tool_args,
                "user_id": req.user_id,
                "trace_id": req.trace_id,
                "timestamp": req.timestamp,
                "channel_id": req.channel_id,
                "summary": req.summary,
                "created_at": pending.created_at,
                "age_seconds": round(now - pending.created_at, 1),
            })
        return results


def submit_approval_decision(
    request_id: str,
    approved: bool,
    approver_id: str = "operator",
    reason: str = ""
) -> tuple[bool, str]:
    """
    Submit an operator decision (approve or deny) for a pending approval request.
    Wakes up the waiting investigation worker thread.
    Returns (success: bool, message: str).
    """
    with _APPROVAL_LOCK:
        pending = _PENDING_APPROVALS.get(request_id)
        if not pending:
            return False, f"Approval request '{request_id}' not found or already resolved"

        if approved:
            sig_payload = f"approved:{request_id}:{approver_id}"
            signature = hmac.new(_HITL_SECRET, sig_payload.encode(), hashlib.sha256).hexdigest()[:16]
            dec_reason = reason or "Operator approved"
        else:
            signature = ""
            dec_reason = reason or "Operator rejected"

        pending.decision = ApprovalResult(
            approved=approved,
            approver_id=approver_id,
            reason=dec_reason,
            signature=signature,
            latency_ms=0
        )
        pending.event.set()
        return True, f"Decision recorded for request '{request_id}'"


def clear_pending_approvals():
    """Clear all pending approvals (used primarily for test isolation and cleanup)."""
    with _APPROVAL_LOCK:
        for pending in _PENDING_APPROVALS.values():
            pending.event.set()
        _PENDING_APPROVALS.clear()


class AutoApproveProvider:
    def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        logger.warning(f"[HITL] AUTO-APPROVED: {request.summary} (user={request.user_id})")
        sig_payload = f"approved:{request.request_id}:{request.user_id}"
        signature = hmac.new(_HITL_SECRET, sig_payload.encode(), hashlib.sha256).hexdigest()[:16]
        return ApprovalResult(
            approved=True,
            approver_id=request.user_id,
            reason="auto-approved",
            signature=signature,
            latency_ms=0
        )

    def get_mode(self) -> str:
        return "autopilot"


class SimulatedInteractiveProvider:
    def __init__(self, delay: Optional[float] = None, **kwargs):
        self.delay = delay if delay is not None else float(os.getenv("HITL_SIMULATE_DELAY", "3.0"))

    def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        if self.delay > 0:
            logger.info(f"[HITL] Simulating human review delay ({self.delay}s)...")
            time.sleep(self.delay)

        sig_payload = f"approved:{request.request_id}:{request.user_id}"
        signature = hmac.new(_HITL_SECRET, sig_payload.encode(), hashlib.sha256).hexdigest()[:16]
        return ApprovalResult(
            approved=True,
            approver_id=request.user_id,
            reason="simulated-interactive-approval",
            signature=signature,
            latency_ms=int(self.delay * 1000)
        )

    def get_mode(self) -> str:
        return "simulated"


class InteractiveHITLProvider:
    """
    True interactive Human-in-the-Loop provider.
    Enqueues write operations in _PENDING_APPROVALS and pauses the calling thread
    until an operator submits a decision via /api/hitl/decide or timeout expires.
    Fail-closed security: if timeout expires without approval, operation is denied.
    """
    def __init__(self, timeout_seconds: Optional[float] = None, **kwargs):
        self.timeout_seconds = timeout_seconds or float(os.getenv("HITL_TIMEOUT_SECONDS", "60.0"))

    def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        req_id = request.request_id
        event = threading.Event()
        pending = PendingApproval(
            request=request,
            created_at=time.time(),
            event=event,
            decision=None
        )

        with _APPROVAL_LOCK:
            _PENDING_APPROVALS[req_id] = pending

        logger.info(
            f"[HITL] Queued approval request {req_id} for {request.summary} "
            f"(user={request.user_id}, timeout={self.timeout_seconds}s)"
        )

        start_time = time.time()
        try:
            signaled = event.wait(timeout=self.timeout_seconds)
            latency_ms = int((time.time() - start_time) * 1000)

            with _APPROVAL_LOCK:
                if signaled and pending.decision is not None:
                    pending.decision.latency_ms = latency_ms
                    logger.info(
                        f"[HITL] Resolved {req_id}: approved={pending.decision.approved} "
                        f"by {pending.decision.approver_id} ({latency_ms}ms)"
                    )
                    return pending.decision

                # Otherwise timed out or event signaled without decision: FAIL-CLOSED
                logger.warning(
                    f"[HITL] Approval request {req_id} timed out after "
                    f"{self.timeout_seconds}s without operator decision — FAIL-CLOSED"
                )
                return ApprovalResult(
                    approved=False,
                    approver_id="system-timeout",
                    reason=f"Operator authorization timed out after {self.timeout_seconds}s (fail-closed)",
                    signature="",
                    latency_ms=latency_ms
                )
        finally:
            with _APPROVAL_LOCK:
                _PENDING_APPROVALS.pop(req_id, None)

    def get_mode(self) -> str:
        return "interactive"


def get_hitl_provider(mode: Optional[str] = None, **kwargs):
    target = mode or os.getenv("HITL_MODE", "simulated")
    target = str(target).strip().lower()
    if target == "autopilot":
        return AutoApproveProvider()
    if target in ("interactive", "queue", "operator"):
        return InteractiveHITLProvider(**kwargs)
    return SimulatedInteractiveProvider(**kwargs)
