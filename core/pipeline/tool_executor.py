"""
ToolExecutor — Safety-Gated Tool Execution with Caching and Response Building.

Single responsibility: receive a function_call part, run it through safety gates
(ghost guard → policy gate → HITL gate), execute the tool, build the response part.

Absorbs: ghost tool guard, policy gate, HITL gate, Drive dedup check,
tool execution with caching, kwarg sanitization, PII scrubbing,
thought signature capture/attachment, and ops counting.
"""

import inspect
import time
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Dict

import google.generativeai as genai

# Fail-soft imports — mirrors brain.py pattern
try:
    from core.safety.scrubber import scrub
except ImportError:
    scrub = lambda text: text

try:
    from core.pipeline.tool_schemas import TOOL_SCHEMAS
except ImportError:
    TOOL_SCHEMAS = {}

try:
    from core.safety.hitl import ApprovalRequest
except ImportError:
    ApprovalRequest = None

logger = logging.getLogger(__name__)


# =============================================================================
# Result Container
# =============================================================================

@dataclass
class ToolResult:
    """Structured result from a single tool execution with raw audit receipt."""
    tool_name: str
    response_part: Optional[Any] = None   # genai.protos.Part with function_response
    ops_count: int = 0
    drive_slice_info: Optional[tuple] = None
    blocked_by: str = ""                   # "ghost", "policy", "hitl", "duplicate", ""
    tool_args: dict = field(default_factory=dict)
    raw_output: str = ""
    duration_ms: float = 0.0


# =============================================================================
# Outcome Classification (shared definition lives in core.pipeline.outcomes)
# =============================================================================

from core.pipeline.outcomes import classify_outcome  # noqa: E402,F401  (re-export)
from core.pipeline.evidence import step_header  # noqa: E402


# =============================================================================
# ToolExecutor
# =============================================================================

class ToolExecutor:
    """
    Encapsulates the full lifecycle of a single tool call:
    safety gates → execution → caching → PII scrub → response building.
    """

    def __init__(self, policy, hitl, circuit_breaker, tools):
        self.policy = policy
        self.hitl = hitl
        self.circuit_breaker = circuit_breaker
        self.tools = tools
        self._tool_cache: Dict[str, list] = {}

    def clear_cache(self):
        """Reset tool cache for a fresh investigation."""
        self._tool_cache = {}

    # -----------------------------------------------------------------
    # Core Entry Point
    # -----------------------------------------------------------------
    def execute_function_call(
        self,
        part,
        manifest_str: str,
        trace_id: str,
        user_id: str,
        drive_call_history: dict,
        turn: int,
        thought_signatures: list,
        step_number: Optional[int] = None,
    ) -> ToolResult:
        """
        Process a single function_call part through the full pipeline:
        1. Ghost tool guard
        2. Policy gate
        3. HITL gate
        4. Drive dedup check
        5. Cache check / execution
        6. PII scrub
        7. Response part building (with thought signature attachment)
        """
        fc = part.function_call
        fname = fc.name
        fargs = dict(fc.args)

        # Capture thought signature if present
        if hasattr(part, 'thought_signature') and part.thought_signature:
            thought_signatures.append(part.thought_signature)

        # Safety tick + loop detection
        self.circuit_breaker.tick()
        self.circuit_breaker.track_tool(fname, fargs)

        result = None  # Guards set result on block, execution sets it on success

        # --- 1. GHOST TOOL GUARD (Exact token set matching - H3) ---
        manifest_tools = {t.strip() for t in manifest_str.split(",") if t.strip()}
        if fname not in manifest_tools and fname != "summon_toolkit":
            logger.warning(f"[{trace_id}] [-] Hallucination Blocked: {fname}")
            result = f"ERROR: Tool '{fname}' unknown. Available: [{manifest_str}]"
            blocked_by = "ghost"

        # --- 2. POLICY GATE ---
        elif self.policy:
            try:
                from core.safety.policy_engine import PolicyViolationError
                self.policy.check(fname)
            except PolicyViolationError as pve:
                logger.warning(f"[{trace_id}] [POLICY] {pve}")
                result = f"POLICY BLOCKED: {pve}"
                blocked_by = "policy"

        # --- 2.5 DEVICE ACCESS GATE ---
        if result is None and self.policy:
            target_device = fargs.get("target_device") or fargs.get("device") or fargs.get("target")
            if target_device:
                try:
                    from core.safety.policy_engine import DeviceAccessDeniedError
                    self.policy.check_device_access(user_id, str(target_device))
                except DeviceAccessDeniedError as dade:
                    logger.warning(f"[{trace_id}] [RBAC] {dade}")
                    result = f"DEVICE ACCESS DENIED: {dade}"
                    blocked_by = "rbac"

        # --- 3. HITL GATE ---
        if result is None and self.hitl and self.policy:
            is_write_op = (
                fname in self.policy.WRITE_TOOLS
                or any(fname.startswith(p) for p in getattr(self.policy, "WRITE_PREFIXES", ()))
            )
            is_unbounded_session = False

            if fname == "execute_operational_command":
                cmd_val = str(fargs.get("cmd") or fargs.get("command") or "").lower()
                if re.search(r'\bshow\s+session\s+all\b', cmd_val) and not re.search(r'\bfilter\s+\S+', cmd_val):
                    is_unbounded_session = True
                    # Counter-logic defense: Strip any self-declared approval argument fabricated by LLM
                    fargs.pop("hitl_approved", None)

            if (is_write_op or is_unbounded_session) and ApprovalRequest:
                approval_request = ApprovalRequest(
                    tool_name=fname,
                    tool_args=fargs,
                    user_id=user_id,
                    trace_id=trace_id
                )
                approval = self.hitl.request_approval(approval_request)
                if not approval.approved:
                    logger.warning(f"[{trace_id}] [HITL] DENIED: {fname} ({approval.reason})")
                    result = f"HITL DENIED: {fname} was rejected by the approval gate. Reason: {approval.reason}"
                    blocked_by = "hitl"
                else:
                    logger.info(f"[{trace_id}] [HITL] APPROVED: {fname} (sig={approval.signature})")
                    if is_unbounded_session:
                        fargs["hitl_approved"] = True


        # --- 4. DRIVE DEDUP CHECK ---
        if result is None and fname == 'query_knowledge_base':
            result, blocked_by = self._check_drive_dedup(fargs, drive_call_history, turn, trace_id)

        # --- 5. EXECUTION ---
        ops_count = 0
        drive_slice_info = None
        duration_ms = 0.0
        if result is None:
            t0 = time.perf_counter()
            result, ops_count, drive_slice_info = self._execute_with_cache(fname, fargs, trace_id)
            duration_ms = round((time.perf_counter() - t0) * 1000, 1)
            blocked_by = ""

        # --- 6. PII SCRUB + RESPONSE BUILDING ---
        scrubbed = scrub(str(result)) if result is not None else ""
        if step_number is not None:
            # Same numbering as the report's receipt table, so the model can cite [Step N].
            status = classify_outcome(str(result) if result is not None else "", blocked_by if result else "")
            scrubbed = f"{step_header(step_number, status)}\n{scrubbed}"
        response_part = genai.protos.Part(
            function_response=genai.protos.FunctionResponse(
                name=fname,
                response={'result': scrubbed}
            )
        )

        # --- 7. THOUGHT SIGNATURE ATTACHMENT ---
        if thought_signatures:
            try:
                response_part.thought_signature = thought_signatures[0]
            except (AttributeError, Exception) as sig_err:
                logger.debug(f"[{trace_id}] [G3] Thought signature attachment skipped: {sig_err}")

        return ToolResult(
            tool_name=fname,
            response_part=response_part,
            ops_count=ops_count,
            drive_slice_info=drive_slice_info,
            blocked_by=blocked_by if result else "",
            tool_args=fargs,
            raw_output=str(result) if result is not None else "",
            duration_ms=duration_ms,
        )

    # -----------------------------------------------------------------
    # Drive Deduplication
    # -----------------------------------------------------------------
    def _check_drive_dedup(self, fargs, drive_call_history, turn, trace_id):
        """Returns (result, blocked_by) or (None, '') if not a duplicate."""
        action = fargs.get('action', 'list_contents')
        target = fargs.get('target', '')

        if action == 'read_slice':
            pages = (fargs.get('start_page'), fargs.get('end_page'))
            cache_key = (action, target, pages)
        else:
            cache_key = (action, target, None)

        if cache_key in drive_call_history:
            prev_turn = drive_call_history[cache_key]
            logger.warning(f"[{trace_id}] [SKIP] Duplicate Drive call on Turn {turn+1} (first called on Turn {prev_turn})")
            return (
                f"This content was already loaded on Turn {prev_turn}. "
                "The information is already in your context. Synthesize from existing data instead.",
                "duplicate"
            )
        else:
            drive_call_history[cache_key] = turn + 1
            return None, ""

    # -----------------------------------------------------------------
    # Execute with Timeline Cache
    # -----------------------------------------------------------------
    def _execute_with_cache(self, fname, fargs, trace_id):
        """Execute a tool with caching. Returns (result, ops_count, drive_slice_info)."""
        import json
        clean_args = json.dumps(fargs, sort_keys=True, default=str)
        cache_key = f"{fname}:{clean_args}"
        now = datetime.now()
        ops_count = 0
        drive_slice_info = None

        if cache_key in self._tool_cache:
            executions = self._tool_cache[cache_key]
            last_exec = executions[-1]
            time_since_last = (now - last_exec['timestamp']).total_seconds()

            if time_since_last < 5.0:
                # Cache hit — prevent loops
                logger.info(f"[{trace_id}]    [CACHE HIT] {fname} (last exec {time_since_last:.1f}s ago)")
                result = last_exec['result']
                ops_count = result.count("--- CMD:") if isinstance(result, str) else 0
                return result, max(ops_count, 1), None

            # Intentional re-check after >5s
            result, ops_count, drive_slice_info = self._raw_execute(fname, fargs, trace_id)
            if result is not None:
                exec_num = len(executions) + 1
                self._tool_cache[cache_key].append({
                    'execution_num': exec_num,
                    'timestamp': now,
                    'result': result,
                    'preview': str(result)[:200]
                })
            return result, ops_count, drive_slice_info
        else:
            # First execution
            result, ops_count, drive_slice_info = self._raw_execute(fname, fargs, trace_id)
            if result is not None:
                self._tool_cache[cache_key] = [{
                    'execution_num': 1,
                    'timestamp': now,
                    'result': result,
                    'preview': str(result)[:200]
                }]
            return result, ops_count, drive_slice_info

    # -----------------------------------------------------------------
    # Raw Tool Execution
    # -----------------------------------------------------------------
    def _raw_execute(self, fname, fargs, trace_id):
        """Execute a tool function directly. Returns (result, ops_count, drive_slice_info)."""
        matching_tool = next((t for t in self.tools if t.__name__ == fname), None)
        if not matching_tool:
            return f"Error: Tool '{fname}' not available in the current toolkit.", 0, None

        try:
            logger.info(f"[{trace_id}]    [EXEC] {fname}")
            dropped = self.unsupported_args(matching_tool, fargs)
            result = self.safe_call(matching_tool, fargs)

            # Counter-logic: a silently dropped argument means the device answered a
            # different question than the model asked. Say so in the result.
            if dropped and isinstance(result, str):
                result += (
                    f"\n\n[EXECUTOR NOTE] Unsupported arguments were ignored: {sorted(dropped)}. "
                    "The output above does NOT reflect them."
                )

            ops_count = 0
            if isinstance(result, str):
                ops_in_tool = result.count("--- CMD:")
                ops_count = ops_in_tool if ops_in_tool > 0 else 1

            # Track Drive slices
            drive_slice_info = None
            if fname == 'query_knowledge_base' and fargs.get('action') == 'read_slice':
                drive_slice_info = (
                    fargs.get('start_page', 'unknown'),
                    fargs.get('end_page', 'unknown')
                )

            return result, ops_count, drive_slice_info
        except Exception as te:
            return f"Tool Error: {te}", 0, None

    # -----------------------------------------------------------------
    # Kwarg Sanitization (Static)
    # -----------------------------------------------------------------
    @staticmethod
    def unsupported_args(tool_func, fargs: dict) -> set:
        """Return the argument names the tool's signature cannot accept."""
        sig = inspect.signature(tool_func)
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
            return set()
        return set(fargs.keys()) - set(sig.parameters.keys())

    @staticmethod
    def safe_call(tool_func, fargs: dict):
        """
        P0 Fix: Sanitizes kwargs before calling a tool function.
        Drops any hallucinated kwargs not in the tool's signature.
        If the function accepts **kwargs, all keys pass through.
        """
        dropped = ToolExecutor.unsupported_args(tool_func, fargs)
        sanitized = {k: v for k, v in fargs.items() if k not in dropped}

        if dropped:
            logger.warning(f"[SANITIZE] Dropped hallucinated kwargs for '{tool_func.__name__}': {dropped}")

        # Validate arg values against Pydantic schema if one exists
        schema = TOOL_SCHEMAS.get(tool_func.__name__)
        if schema:
            try:
                validated = schema(**sanitized)
                sanitized = validated.model_dump()
            except Exception as e:
                logger.warning(f"[SCHEMA] Validation failed for '{tool_func.__name__}': {e}")
                return f"Argument validation error for {tool_func.__name__}: {e}. Fix your arguments and retry."

        return tool_func(**sanitized)
