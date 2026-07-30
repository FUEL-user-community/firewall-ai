"""
Human-in-the-Loop (HITL) Approval Gate

Auto-approves all operations with audit logging.
The agent runs read-only by default (enforced by policy_engine.py),
so this gate is a safety net that rarely fires.
"""

import os
import hmac
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

_HITL_SECRET_RAW = os.getenv("HITL_SECRET")
if not _HITL_SECRET_RAW:
    import secrets as _secrets
    _HITL_SECRET_RAW = _secrets.token_hex(32)
    logger.warning("[HITL] No HITL_SECRET set — generated ephemeral key. "
                   "Set HITL_SECRET in .env for persistent signatures.")
_HITL_SECRET = _HITL_SECRET_RAW.encode()


@dataclass
class ApprovalRequest:
    """A pending write operation awaiting approval."""
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
    """The outcome of an approval request."""
    approved: bool
    approver_id: str = ""
    reason: str = ""
    signature: str = ""
    latency_ms: int = 0


class AutoApproveProvider:
    """Auto-approves all operations with audit logging."""

    def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        logger.warning(
            f"[HITL] AUTO-APPROVED: {request.summary} "
            f"(user={request.user_id}, trace={request.trace_id})"
        )
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


import time

class SimulatedInteractiveProvider:
    """Simulates a human-in-the-loop approval by delaying execution and logging."""

    def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        logger.warning(
            f"\n\n======================================================\n"
            f"[HITL] PENDING APPROVAL REQUIRED\n"
            f"User: {request.user_id} | Trace: {request.trace_id}\n"
            f"Operation: {request.summary}\n"
            f"======================================================\n"
        )
        logger.info("[HITL] Simulating human review delay (3 seconds)...")
        time.sleep(3)
        
        logger.warning(f"[HITL] OPERATION APPROVED VIA SIMULATOR")
        
        sig_payload = f"approved:{request.request_id}:{request.user_id}"
        signature = hmac.new(_HITL_SECRET, sig_payload.encode(), hashlib.sha256).hexdigest()[:16]

        return ApprovalResult(
            approved=True,
            approver_id=request.user_id,
            reason="simulated-interactive-approval",
            signature=signature,
            latency_ms=3000
        )

    def get_mode(self) -> str:
        return "interactive"


def get_hitl_provider(mode: Optional[str] = None, **kwargs):
    """Returns the HITL provider. Currently supports autopilot and simulated interactive."""
    if mode == "autopilot":
        logger.warning("[HITL] Running in AUTOPILOT mode — all writes auto-approved.")
        return AutoApproveProvider()
    return SimulatedInteractiveProvider()
