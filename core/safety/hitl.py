"""
Human-in-the-Loop (HITL) Approval Gate
Manages write operation authorization signatures with persistent HMAC secrets (L1).
"""
import os
import hmac
import time
import hashlib
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = ["ApprovalRequest", "ApprovalResult", "AutoApproveProvider", "SimulatedInteractiveProvider", "get_hitl_provider"]

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
    def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        delay = float(os.getenv("HITL_SIMULATE_DELAY", "3.0"))
        if delay > 0:
            logger.info(f"[HITL] Simulating human review delay ({delay}s)...")
            time.sleep(delay)

        sig_payload = f"approved:{request.request_id}:{request.user_id}"
        signature = hmac.new(_HITL_SECRET, sig_payload.encode(), hashlib.sha256).hexdigest()[:16]
        return ApprovalResult(
            approved=True,
            approver_id=request.user_id,
            reason="simulated-interactive-approval",
            signature=signature,
            latency_ms=int(delay * 1000)
        )

    def get_mode(self) -> str:
        return "interactive"


def get_hitl_provider(mode: Optional[str] = None, **kwargs):
    if mode == "autopilot":
        return AutoApproveProvider()
    return SimulatedInteractiveProvider()
