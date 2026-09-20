import os
import re
import json
import yaml
import time
import uuid
import random
import logging
import inspect
import warnings
import datetime
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Generator
from pydantic import BaseModel, Field

# Specifically filter google.generativeai deprecation / future warnings during import
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning, module="google.generativeai")
    warnings.filterwarnings("ignore", category=FutureWarning, module="google.generativeai")
    import google.generativeai as genai

logger = logging.getLogger(__name__)

# Constants
MAX_AMBIENT_ALERTS = 5
DEFAULT_TRACE_ID_LEN = 8
DEFAULT_REQUEST_TIMEOUT = float(os.getenv("GEMINI_REQUEST_TIMEOUT", "60.0"))

# Devices inventory path & mtime-cached loader
_DEVICES_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "devices.yaml"
_devices_cache: Dict[str, Any] = {}
_devices_last_mtime: float = 0.0


def _load_devices_config() -> dict:
    """Loads devices.yaml with mtime caching to eliminate disk I/O on hot query paths."""
    global _devices_cache, _devices_last_mtime
    if not _DEVICES_CONFIG_PATH.exists():
        return {}
    try:
        current_mtime = _DEVICES_CONFIG_PATH.stat().st_mtime
        if current_mtime != _devices_last_mtime:
            with open(_DEVICES_CONFIG_PATH, "r", encoding="utf-8") as f:
                _devices_cache = yaml.safe_load(f) or {}
            _devices_last_mtime = current_mtime
        return _devices_cache
    except Exception as e:
        logger.warning(f"[FLEET] Error reading devices config: {e}")
        return _devices_cache


# Standard Absolute Imports
from core.pipeline.tool_keeper import ToolKeeper
from core.safety.circuit_breaker import CircuitBreaker, CircuitBreakerError
from core.safety.semantic_drift_gate import SemanticDriftGate

# Secrets management -- fail-soft
try:
    from core.integrations.secrets import get_secret
except ImportError:
    get_secret = lambda k: os.getenv(k.upper())

# Autonomous Defense Deck store -- fail-soft
try:
    from core.engine.card_store import CardStore
except ImportError:
    CardStore = None

# Policy-gated execution
try:
    from core.safety.policy_engine import PolicyEngine
except ImportError:
    PolicyEngine = None
    logger.warning("[BRAIN] policy_engine not available -- policy checks disabled.")

# Deterministic health check workflow
try:
    from core.workflows.health_check import run_health_check
except ImportError:
    run_health_check = None
    logger.warning("[BRAIN] health_check workflow not available.")

# Human-in-the-loop approval gate
try:
    from core.safety.hitl import get_hitl_provider
except ImportError:
    get_hitl_provider = None
    logger.warning("[HITL] hitl module not available -- write operations ungated.")

# =============================================================================
# Core Pipeline Modules
# =============================================================================
from core.pipeline.prompt_assembler import SYSTEM_PROMPT
from core.pipeline.model_config import (
    GEMINI_MODEL, PRICE_PER_M_INPUT, PRICE_PER_M_OUTPUT,
    MAX_TURNS,
    classify_mode, get_thinking_level, get_generation_config,
)
from core.pipeline.tool_executor import ToolExecutor
from core.pipeline.context_manager import ContextManager
from core.pipeline.synthesizer import ResponseSynthesizer
from core.integrations.telemetry import UsageTracker

# Budget guard -- fail-soft if not available
try:
    from core.safety.budget_guard import BudgetGuard, BudgetExceededError
except ImportError:
    BudgetGuard = None
    BudgetExceededError = None
    logger.warning("[BUDGET] budget_guard not available -- cost limits disabled.")


# =============================================================================
# System Prompt Constants
# =============================================================================
CIRCUIT_BREAKER_REFLECTION_PROMPT = (
    "[SYSTEM: LOOP DETECTED. Your investigation is being terminated for safety. "
    "Before shutdown, produce a PARTIAL REPORT: "
    "1) WHAT_TRIED: List every tool you called and key findings. "
    "2) WHY_STALLED: One sentence on why you were repeating actions. "
    "3) RECOMMENDATION: What the human should investigate manually.]"
)

BUDGET_EXCEEDED_PROMPT = (
    "[SYSTEM: Budget limit reached. Produce a PARTIAL REPORT from the data "
    "you have gathered so far. Include all findings and recommendations.]"
)


# =============================================================================
# Structured Output Schemas
# =============================================================================
class RangeSimulationPayload(BaseModel):
    """Schema contract for Breach & Attack Simulation (BAS) topological outputs."""
    mermaid: str = Field(description="Valid Mermaid AST starting with graph TD or flowchart TD")
    message: str = Field(description="Comprehensive breach verdict and operational analysis")
    threats: int = Field(default=0, description="Count of active threat vectors")
    drops: int = Field(default=0, description="Count of enforced boundary drops")


# =============================================================================
# Investigation Request-Scoped State
# =============================================================================
@dataclass
class InvestigationState:
    """Thread-safe, request-scoped state for a single multi-turn investigation."""
    trace_id: str
    user_id: str
    manifest_str: str
    base_config: Any
    circuit_breaker: CircuitBreaker
    drift_gate: SemanticDriftGate
    tool_executor: ToolExecutor
    status_callback: Optional[Callable[[str], None]] = None
    target_mode: str = "default"
    history: List[Any] = field(default_factory=list)
    prev_turn_tools: List[str] = field(default_factory=list)
    drive_call_history: Dict[str, Any] = field(default_factory=dict)
    drive_slices: List[Any] = field(default_factory=list)
    investigation_trace: List[Dict[str, Any]] = field(default_factory=list)
    abort_event: Optional[threading.Event] = None
    chunk_callback: Optional[Callable[[str], None]] = None

    def emit(self, msg: str) -> None:
        """Emits user status update if a callback is registered."""
        if self.status_callback:
            try:
                self.status_callback(msg)
            except Exception as cb_err:
                logger.debug(f"[{self.trace_id}] Status callback error: {cb_err}")

    def emit_chunk(self, chunk: str) -> None:
        """Emits streaming text chunk if a chunk callback is registered."""
        if self.chunk_callback and chunk:
            try:
                self.chunk_callback(chunk)
            except Exception as chk_err:
                logger.debug(f"[{self.trace_id}] Chunk callback error: {chk_err}")

    def is_aborted(self) -> bool:
        """Returns True if cancellation was requested via abort_event."""
        return self.abort_event is not None and self.abort_event.is_set()


@dataclass
class TurnPartsResult:
    """Aggregated outputs and extracted reasoning from a single turn's response parts."""
    tool_parts: List[Any] = field(default_factory=list)
    turn_reasoning_parts: List[str] = field(default_factory=list)
    turn_ops_count: int = 0


class CoreBrain:
    """
    Central Cognitive Core for PAN-OS investigation.
    Handles Gemini model connection, tool binding, and multi-turn investigation loops.
    """

    def __init__(self, model=None, tools=None, keeper=None):
        # Load Gemini API key from secrets backend
        try:
            self.api_key = get_secret('gemini_api_key')
        except Exception as e:
            logger.error(f"[BRAIN] Failed to load Gemini API key: {e}")
            self.api_key = None

        # Dependency injection -- accept injected keeper/tools/model for testing
        self.keeper = keeper or ToolKeeper()
        self.tools = tools if tools is not None else self.keeper.get_tools("#core")
        logger.info(f"[BRAIN] ToolKeeper initialized: {len(self.tools)} tools in #core tray.")

        if model is not None:
            # Injected model -- skip SDK configuration
            self.model = model
            logger.info("[BRAIN] Initialized with injected model (test/mock mode)")
        elif not self.api_key:
            logger.error("[BRAIN] GEMINI_API_KEY not found -- model unavailable.")
            self.model = None
        else:
            genai.configure(api_key=self.api_key)

            # Configurable content safety filters
            safety_level = os.getenv("GEMINI_SAFETY_LEVEL", "security_audit").lower().strip()
            if safety_level in ("security_audit", "off", "block_none"):
                # Security audit context: CVE analysis, exploit signatures, and firewall rules
                # frequently trigger false positives under standard safety filters.
                safety_settings = [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
            elif safety_level == "relaxed":
                safety_settings = [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_ONLY_HIGH"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_ONLY_HIGH"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"},
                ]
            else:
                safety_settings = None

            model_kwargs = {
                "model_name": GEMINI_MODEL,
                "tools": self.tools,
                "system_instruction": str(SYSTEM_PROMPT),
            }
            if safety_settings:
                model_kwargs["safety_settings"] = safety_settings

            self.model = genai.GenerativeModel(**model_kwargs)
            logger.info(f"[BRAIN] Model initialized: {GEMINI_MODEL} ({len(self.tools)} tools, safety={safety_level})")

        # License Awareness Context
        self.license_context = "License Status: UNKNOWN (Assume Capability). Check with 'request license info'."

        # Usage tracking
        self.usage_tracker = UsageTracker(
            model_name=GEMINI_MODEL,
            price_input=PRICE_PER_M_INPUT,
            price_output=PRICE_PER_M_OUTPUT
        )

        # Default safety governor & policy engine
        self.circuit_breaker = CircuitBreaker(max_steps=30, max_loops=4)
        self.policy = PolicyEngine() if PolicyEngine else None

        # Human-in-the-loop approval provider
        if get_hitl_provider:
            hitl_mode = os.getenv("HITL_MODE", "autopilot").lower()
            self.hitl = get_hitl_provider(mode=hitl_mode)
            logger.info(f"[HITL] Provider: {self.hitl.get_mode()}")
        else:
            self.hitl = None
            logger.warning("[HITL] No provider available -- write operations ungated.")

        # Default pipeline modules
        self.tool_executor = ToolExecutor(
            policy=self.policy,
            hitl=self.hitl,
            circuit_breaker=self.circuit_breaker,
            tools=self.tools
        )
        self.context_mgr = ContextManager()
        self.synthesizer = ResponseSynthesizer()

        # Budget guard -- per-investigation + daily cost caps
        if BudgetGuard:
            self.budget_guard = BudgetGuard(
                price_input=PRICE_PER_M_INPUT,
                price_output=PRICE_PER_M_OUTPUT,
            )
            logger.info(f"[BUDGET] Guard active: ${self.budget_guard.max_per_investigation:.2f}/investigation, ${self.budget_guard.max_per_day:.2f}/day")
        else:
            self.budget_guard = None

    def set_usage_callback(self, callback):
        """Sets the function to call with token usage stats."""
        self.usage_tracker.set_callback(callback)

    def _execute_tool(self, name, args):
        """Standardized Tool Execution helper. Routes through full ToolExecutor pipeline."""
        matching_tool = next((t for t in self.tools if t.__name__ == name), None)
        if not matching_tool:
            return "Error: Tool Not Found"
        return self.tool_executor.safe_call(matching_tool, args)

    def _track_usage(self, response, latency_ms=0, success=True, tray="#core", ops_count=0, trace_id="", tool_summary=""):
        """Delegates to UsageTracker with fail-soft protection."""
        try:
            self.usage_tracker.track(
                response, latency_ms=latency_ms, success=success, tray=tray,
                ops_count=ops_count, trace_id=trace_id, tool_summary=tool_summary
            )
        except Exception as te:
            logger.debug(f"[BRAIN] Usage tracking error (non-fatal): {te}")

    def set_license_context(self, status):
        """Updates the License State for prompt injection."""
        self.license_context = f"LICENSE STATE:\n{status}"

    def _build_fleet_context(self) -> str:
        """
        Produces a structured fleet inventory string for injection into the LLM context.
        Uses mtime caching so changes to devices.yaml are picked up without restart.
        """
        try:
            data = _load_devices_config()
            if not data and not _DEVICES_CONFIG_PATH.exists():
                return "FLEET_INVENTORY: Single device mode (no devices.yaml found)."

            firewalls = data.get("firewalls", {}) if data else {}
            if not firewalls:
                return "FLEET_INVENTORY: No firewalls configured."

            lines = ["FLEET_INVENTORY: Managed devices:"]
            for name, info in firewalls.items():
                label = info.get("label", "")
                is_default = info.get("default", False)
                marker = " <- DEFAULT" if is_default else ""
                lines.append(f"  - {name}: {label}{marker}")

            lines.append("Use target_device=\"<alias>\" in tool calls to target a specific device.")
            return "\n".join(lines)

        except Exception as e:
            logger.warning(f"[FLEET] Failed to build fleet context: {e}")
            return "FLEET_INVENTORY: Unable to load (using default device)."

    def _build_card_context(self, user_query: str) -> str:
        """
        Build card context for the LLM. Two injection types:

        1. CARD_CONTEXT -- when user clicks "Investigate" on a card,
           the full finding is injected as prior art.
        2. ACTIVE_ALERTS -- top pending CRITICAL/CAUTION cards injected
           as ambient awareness on every query.

        Mirrors the _build_fleet_context() pattern.
        """
        if CardStore is None:
            return ""

        try:
            store = CardStore.get_instance()
        except Exception:
            return ""  # Card engine not available -- silent skip

        parts = []

        # --- CARD_CONTEXT: Specific card investigation ---
        if user_query.lower().startswith("investigate:"):
            search_title = user_query.split(":", 1)[1].strip()
            if search_title:
                try:
                    pending = store.get_pending(limit=50)
                    matched = None
                    for card in pending:
                        if search_title.lower() in card.get("title", "").lower():
                            matched = card
                            break

                    if matched:
                        evidence_str = "\n".join(f"  - {e}" for e in matched.get("evidence", []))
                        metrics_str = ", ".join(f"{k}={v}" for k, v in matched.get("metrics", {}).items())
                        ts = matched.get("timestamp", 0)
                        time_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "Unknown"

                        parts.append(
                            f"CARD_CONTEXT (Prior Art -- do NOT re-run these tools):\n"
                            f"  Card ID: {matched.get('card_id', 'N/A')}\n"
                            f"  Severity: {matched.get('severity', 'normal')}\n"
                            f"  Title: {matched.get('title', '')}\n"
                            f"  Finding: {matched.get('finding', '')}\n"
                            f"  Evidence:\n{evidence_str}\n"
                            f"  Metrics: {metrics_str}\n"
                            f"  Ran At: {time_str}\n"
                            f"\nStart your investigation from these findings. Go DEEPER."
                        )
                        logger.info(f"[CARDS] Injected CARD_CONTEXT: {matched.get('card_id')} into investigation")
                except Exception as e:
                    logger.debug(f"[CARDS] Card lookup failed: {e}")

        # --- ACTIVE_ALERTS: Ambient awareness ---
        try:
            critical = store.get_by_severity("critical", limit=3)
            caution = store.get_by_severity("caution", limit=3)
            alerts = critical + caution

            if alerts:
                alert_lines = []
                for a in alerts[:MAX_AMBIENT_ALERTS]:
                    alert_lines.append(
                        f"  [{a.get('severity','').upper()}] {a.get('card_id','')}: {a.get('title','')} -- {a.get('finding','')[:120]}"
                    )
                parts.append(
                    f"ACTIVE_ALERTS ({len(alerts)} pending):\n" + "\n".join(alert_lines)
                )
        except Exception as e:
            logger.debug(f"[CARDS] Active alerts query failed: {e}")

        return "\n\n".join(parts)

    # -------------------------------------------------------------------------
    # Private Investigation Step Handlers
    # -------------------------------------------------------------------------

    def _resolve_target_device(self, user_query: str, explicit_device: Optional[str] = None) -> Optional[str]:
        """Resolves target device alias from explicit parameter or query text."""
        if explicit_device:
            return explicit_device
        try:
            fw_dict = _load_devices_config().get("firewalls", {})
            for fw_alias in fw_dict:
                if fw_alias.lower() in user_query.lower():
                    return fw_alias
        except Exception as ex:
            logger.debug(f"[BRAIN] Device resolution failed: {ex}")
        return None

    def _create_workflow_tool_bridge(self) -> Callable[[str, dict], str]:
        """Creates a signature-safe tool dispatch bridge for deterministic workflows."""
        def _exec_workflow_tool(tname: str, targs: dict) -> str:
            matching_tool = next((t for t in self.tools if getattr(t, '__name__', '') == tname), None)
            if matching_tool:
                try:
                    sig = inspect.signature(matching_tool)
                    valid_args = {k: v for k, v in targs.items() if k in sig.parameters}
                    return str(matching_tool(**valid_args))
                except Exception as ex:
                    return f"Error executing {tname}: {ex}"
            try:
                from core.panos.ops import execute_operational_command
                target_dev = targs.get("target_device")
                return execute_operational_command(tname, target_device=target_dev)
            except Exception as ex:
                return f"Error executing {tname}: {ex}"
        return _exec_workflow_tool

    def _try_deterministic_workflow(
        self,
        user_query: str,
        reality_check: str,
        chat: Any,
        **kwargs
    ) -> Optional[str]:
        """Bypasses agentic loop for deterministic health check queries."""
        if run_health_check is None:
            return None

        health_keywords = ["firewall health", "system health", "hardware status", "health check"]
        if not any(k in user_query.lower() for k in health_keywords):
            return None

        trace_id = kwargs.get("trace_id", "workflow")
        logger.info(f"[{trace_id}] [WORKFLOW] Routing to deterministic health check")
        try:
            effective_device = self._resolve_target_device(user_query, kwargs.get("target_device"))
            tool_bridge = self._create_workflow_tool_bridge()

            health_summary = run_health_check(
                tool_executor=tool_bridge,
                target_device=effective_device
            )
            synthesis_prompt = f"{reality_check}\n\nSYNTHESIZE this health check report for the user:\n{health_summary}"
            base_config = kwargs.get("base_config") or get_generation_config()
            response = self._execute_with_quota_retry(
                lambda: chat.send_message(
                    synthesis_prompt,
                    generation_config=base_config,
                    request_options={"timeout": DEFAULT_REQUEST_TIMEOUT}
                ),
                operation_name="health check synthesis"
            )
            try:
                resp_text = getattr(response, 'text', None)
                if isinstance(resp_text, str) and resp_text:
                    return resp_text
                elif getattr(response, 'parts', None) and hasattr(response.parts[0], 'text'):
                    part_text = response.parts[0].text
                    if isinstance(part_text, str):
                        return part_text
                return health_summary
            except (ValueError, AttributeError):
                return health_summary
        except Exception as wf_err:
            logger.warning(f"[{trace_id}] [WORKFLOW] Health check failed: {wf_err}. Falling back to agentic loop.")
            return None

    def _init_investigation_state(
        self,
        user_query: str,
        user_id: str,
        status_callback: Optional[Callable[[str], None]],
        target_mode: Optional[str],
        abort_event: Optional[threading.Event] = None,
        chunk_callback: Optional[Callable[[str], None]] = None,
        temperature: Optional[float] = None,
    ) -> InvestigationState:
        """Initializes thread-safe, request-scoped safety governors and state."""
        trace_id = str(uuid.uuid4())[:DEFAULT_TRACE_ID_LEN]
        circuit_breaker = CircuitBreaker(max_steps=30, max_loops=4)
        drift_gate = SemanticDriftGate()

        tool_executor = ToolExecutor(
            policy=self.policy,
            hitl=self.hitl,
            circuit_breaker=circuit_breaker,
            tools=self.tools
        )

        all_tools = self.keeper.get_tools("#core")
        manifest_str = ", ".join([t.__name__ for t in all_tools])
        base_config = get_generation_config()
        if temperature is not None:
            try:
                base_config.temperature = temperature
            except Exception:
                pass

        if target_mode == "range":
            try:
                base_config = genai.types.GenerationConfig(
                    response_mime_type="application/json",
                    temperature=temperature if temperature is not None else 0.2
                )
            except Exception:
                pass

        if self.budget_guard:
            self.budget_guard.reset_investigation()

        mode = classify_mode(user_query)
        thinking_level = get_thinking_level(mode)
        logger.info(
            f"[{trace_id}] [ARCHITECT] Investigation Started. Mode: {mode}. "
            f"Thinking: {thinking_level}. Tools: [{manifest_str}]"
        )

        state = InvestigationState(
            trace_id=trace_id,
            user_id=user_id,
            manifest_str=manifest_str,
            base_config=base_config,
            circuit_breaker=circuit_breaker,
            drift_gate=drift_gate,
            tool_executor=tool_executor,
            status_callback=status_callback,
            target_mode=target_mode or "default",
            abort_event=abort_event,
            chunk_callback=chunk_callback
        )
        state.emit(f"Connecting to firewall -- {mode} mode...")
        return state

    def _build_reality_prompt(self, user_query: str, state: InvestigationState) -> str:
        """Builds grounded reality anchor string including fleet, cards, and cognitive depth."""
        fleet_context = self._build_fleet_context()
        card_context = self._build_card_context(user_query)
        mode = classify_mode(user_query)
        thinking_level = get_thinking_level(mode)

        reality_check = (
            f"REALITY_CHECK: You only have these tools: [{state.manifest_str}].\n"
            "Verify tool names against this list before every call.\n\n"
            f"{fleet_context}"
        )
        if card_context:
            reality_check += f"\n\n{card_context}"

        if self.license_context:
            reality_check += f"\n\n{self.license_context}"

        reality_check += f"\n\n[SYSTEM COGNITIVE BOUNDS: Execute with {thinking_level.upper()} reasoning depth.]"
        return reality_check

    def _execute_with_quota_retry(
        self,
        call_fn: Callable[[], Any],
        max_retries: int = 3,
        operation_name: str = "Model Call"
    ) -> Any:
        """Executes SDK model call with exponential backoff and jitter on 429 Rate Limit errors."""
        for attempt in range(max_retries + 1):
            try:
                return call_fn()
            except Exception as e:
                is_quota = "429" in str(e) or "Quota exceeded" in str(e) or "RESOURCE_EXHAUSTED" in str(e)
                if not is_quota or attempt >= max_retries:
                    raise
                wait = (2 ** attempt) + random.uniform(0, 1)
                logger.warning(
                    f"[QUOTA] {GEMINI_MODEL} rate-limited during {operation_name} "
                    f"(attempt {attempt + 1}/{max_retries}). Retrying in {wait:.1f}s..."
                )
                time.sleep(wait)

    def _execute_initial_turn(
        self,
        chat: Any,
        user_query: str,
        reality_check: str,
        state: InvestigationState,
        **kwargs
    ) -> tuple[Any, Optional[str]]:
        """Executes the initial prompt turn and handles immediate circuit breaker trips."""
        try:
            if state.target_mode == "range":
                from core.pipeline.prompt_assembler import load_range_prompt
                base_graph = kwargs.get("base_graph_json", "{}")
                range_instructions = load_range_prompt().format(user_query=user_query, base_graph_json=base_graph)
                user_msg = f"{reality_check}\n\n{range_instructions}"
            else:
                user_msg = f"{reality_check}\n\nINVESTIGATE: {user_query}"

            initial_payload = [user_msg]
            response = self._execute_with_quota_retry(
                lambda: chat.send_message(
                    initial_payload,
                    generation_config=state.base_config,
                    request_options={"timeout": DEFAULT_REQUEST_TIMEOUT}
                ),
                operation_name="initial turn"
            )
            return response, None
        except CircuitBreakerError as e:
            logger.error(f"[{state.trace_id}] [SHIELD] Circuit Breaker Tripped: {e}")
            try:
                reflection_response = self._execute_with_quota_retry(
                    lambda: chat.send_message(
                        CIRCUIT_BREAKER_REFLECTION_PROMPT,
                        generation_config=state.base_config,
                        request_options={"timeout": DEFAULT_REQUEST_TIMEOUT}
                    ),
                    operation_name="circuit break reflection"
                )
                partial_report = reflection_response.text
                logger.info(f"[{state.trace_id}] [REFLECT] Partial report generated on circuit break.")
                return None, f"[HALTED] Investigation halted by Safety Governor\n\n{partial_report}"
            except Exception as reflect_err:
                logger.warning(f"[{state.trace_id}] [REFLECT] Reflection failed: {reflect_err}")
                return None, "[HALTED] Investigation terminated by Safety Governor (Loop/Resource Guard)."
        except Exception as e:
            logger.exception(f"[{state.trace_id}] [ARCHITECT] Initial investigation turn failed: {e}")
            return None, "An internal error occurred during initial investigation. Please check server logs."

    def _track_turn_usage(self, response: Any, state: InvestigationState) -> None:
        """Records token usage and tool telemetry for the turn."""
        tool_summary = ", ".join(state.prev_turn_tools) if state.prev_turn_tools else ""
        self._track_usage(response, trace_id=state.trace_id, tool_summary=tool_summary)
        state.prev_turn_tools = []

    def _check_budget_limits(self, chat: Any, response: Any, state: InvestigationState) -> Optional[str]:
        """Evaluates token usage against BudgetGuard caps, requesting partial report if exceeded."""
        if not self.budget_guard or not hasattr(response, 'usage_metadata'):
            return None

        try:
            meta = response.usage_metadata
            self.budget_guard.record_usage(
                prompt_tokens=getattr(meta, 'prompt_token_count', 0),
                response_tokens=getattr(meta, 'candidates_token_count', 0),
            )
            return None
        except BudgetExceededError as be:
            logger.warning(f"[{state.trace_id}] [BUDGET] {be}")
            try:
                partial_resp = self._execute_with_quota_retry(
                    lambda: chat.send_message(
                        BUDGET_EXCEEDED_PROMPT,
                        generation_config=state.base_config,
                        request_options={"timeout": DEFAULT_REQUEST_TIMEOUT}
                    ),
                    operation_name="budget exceeded report"
                )
                return f"[BUDGET LIMIT] Budget limit reached ({self.budget_guard.get_status()})\n\n{partial_resp.text}"
            except Exception:
                return f"[BUDGET LIMIT] Budget limit reached: {be}"

    def _process_turn_parts(self, response: Any, state: InvestigationState, turn: int) -> TurnPartsResult:
        """Extracts Hi-CoT reasoning traces and executes function calls."""
        result = TurnPartsResult()
        thought_signatures = []

        # Safe parts extraction guarding against SDK ValueError on blocked responses
        parts = []
        try:
            parts = response.parts
        except (ValueError, AttributeError) as part_err:
            block_reason = getattr(getattr(response, 'prompt_feedback', None), 'block_reason', None)
            if block_reason:
                logger.warning(f"[{state.trace_id}] Prompt was blocked by safety filters: {block_reason}")
            else:
                logger.warning(f"[{state.trace_id}] Unable to access response.parts: {part_err}")
            return result

        for part in parts:
            if state.is_aborted():
                logger.info(f"[{state.trace_id}] Aborting pending turn processing due to user cancellation.")
                break

            # 1. Intercept Reasoning Trace (Hi-CoT Extraction)
            if hasattr(part, 'text') and part.text:
                match = re.search(r'<REASONING>(.*?)</REASONING>', part.text, re.DOTALL | re.IGNORECASE)
                if match:
                    reasoning_text = match.group(1).strip()
                    result.turn_reasoning_parts.append(reasoning_text)

                    clean_reasoning = " | ".join(line.strip() for line in reasoning_text.split('\n') if line.strip())
                    state.emit(f"[NEO-THINK] {clean_reasoning[:150]}...")

                    hyp_match = re.search(r'\[HYPOTHESIS_MATRIX\]:(.*?)(?=\[|$)', reasoning_text, re.DOTALL)
                    con_match = re.search(r'\[CONTRADICTION_CHECK\]:(.*?)(?=\[|$)', reasoning_text, re.DOTALL)
                    ev_match = re.search(r'\[EVIDENCE_REQUIRED\]:(.*?)(?=\[|$)', reasoning_text, re.DOTALL)

                    trace_turn = {
                        "turn": turn,
                        "hypothesis_len": len(hyp_match.group(1)) if hyp_match else 0,
                        "contradiction_len": len(con_match.group(1)) if con_match else 0,
                        "evidence_req_len": len(ev_match.group(1)) if ev_match else 0,
                        "raw_reasoning": reasoning_text
                    }
                    state.investigation_trace.append(trace_turn)

            # 2. Process function calls
            if part.function_call:
                if state.is_aborted():
                    logger.info(f"[{state.trace_id}] Skipping tool call execution due to cancellation.")
                    break
                exec_result = state.tool_executor.execute_function_call(
                    part=part,
                    manifest_str=state.manifest_str,
                    trace_id=state.trace_id,
                    user_id=state.user_id,
                    drive_call_history=state.drive_call_history,
                    turn=turn,
                    thought_signatures=thought_signatures,
                )
                result.tool_parts.append(exec_result.response_part)
                state.prev_turn_tools.append(exec_result.tool_name)
                state.history.append(part)
                result.turn_ops_count += exec_result.ops_count
                if exec_result.drive_slice_info:
                    state.drive_slices.append(exec_result.drive_slice_info)
                    if len(state.drive_slices) >= 3:
                        logger.warning(f"[{state.trace_id}] [EFFICIENCY] {len(state.drive_slices)} Drive slices read. Consider synthesis.")

        return result

    def _evaluate_semantic_drift(
        self,
        turn_result: TurnPartsResult,
        state: InvestigationState,
        turn: int,
        **kwargs
    ) -> Optional[str]:
        """Evaluates semantic drift gate on accumulated reasoning."""
        if not turn_result.turn_reasoning_parts:
            return None

        combined_reasoning = "\n".join(turn_result.turn_reasoning_parts)
        gate_result = state.drift_gate.check(combined_reasoning, state.trace_id, turn)

        if state.investigation_trace:
            state.investigation_trace[-1]["drift_score"] = round(gate_result.similarity, 3)
            state.investigation_trace[-1]["drift_severity"] = gate_result.severity

        state.emit(f"[DRIFT:{gate_result.severity}:{gate_result.similarity:.3f}:T{turn}]")
        if not gate_result.allowed:
            logger.error(f"[{state.trace_id}] [SHIELD] Semantic Drift Gate Tripped: {gate_result.message}")
            try:
                from core.pipeline.cognitive_trace import CognitiveTraceLogger
                trace_logger = CognitiveTraceLogger()
                trace_logger.log_trace(state.trace_id, kwargs.get('target_mode', state.target_mode), state.investigation_trace, turn + 1)
            except Exception as trace_err:
                logger.debug(f"[{state.trace_id}] Trace log skipped: {trace_err}")
            return f"[HALTED] Investigation halted by Semantic Drift Safety Gate\n\n{gate_result.message}"
        elif gate_result.severity == "caution":
            state.emit(f"[DRIFT-CAUTION] {gate_result.message}")

        return None

    def _handle_tool_tray_pivot(
        self,
        turn_result: TurnPartsResult,
        state: InvestigationState
    ) -> Optional[str]:
        """
        Detects summon_toolkit execution and hot-swaps active tool catalog mid-investigation.
        Updates state.tool_executor.tools and state.manifest_str so subsequent turns can call them.
        """
        if "summon_toolkit" not in state.prev_turn_tools:
            return None

        for part in reversed(state.history):
            fc = getattr(part, 'function_call', None)
            if fc and fc.name == "summon_toolkit":
                args = getattr(fc, 'args', {}) or {}
                tray_name = args.get("tray", "#core")
                new_tools = self.keeper.get_tools(active_tray=tray_name)

                state.tool_executor.tools = new_tools
                state.manifest_str = ", ".join([t.__name__ for t in new_tools])
                state.emit(f"[PIVOT] Swapped toolkit to {tray_name} ({len(new_tools)} tools active)")
                logger.info(f"[{state.trace_id}] [PIVOT] Hot-swapped tool tray to {tray_name} ({len(new_tools)} tools)")

                return (
                    f"[SYSTEM: Tool Tray '{tray_name}' ACTIVATED. "
                    f"Active tool catalog updated to: [{state.manifest_str}]. "
                    f"You may now execute specialized commands from this tray.]"
                )
        return None

    def _enforce_range_schema(self, raw_text: str, trace_id: str) -> str:
        """Validates and guarantees pure JSON output for Breach & Attack Simulation."""
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_text, re.DOTALL | re.IGNORECASE)
        if match:
            clean = match.group(1).strip()
        else:
            clean = re.sub(r'^```json\s*', '', raw_text.strip(), flags=re.IGNORECASE)
            clean = re.sub(r'\s*```$', '', clean).strip()
        try:
            parsed = json.loads(clean)
            validated = RangeSimulationPayload.model_validate(parsed)
            return validated.model_dump_json()
        except Exception as e:
            logger.warning(f"[{trace_id}] [RANGE] JSON schema validation failed: {e}. Generating clean fallback.")
            fallback = RangeSimulationPayload(
                mermaid="graph TD\n  Start[Attack Vector] --> Analysis[Policy Verification]",
                message=raw_text,
                threats=0,
                drops=0
            )
            return fallback.model_dump_json()

    def _step_tool_feedback(
        self,
        chat: Any,
        turn_result: TurnPartsResult,
        state: InvestigationState,
        turn: int,
        pivot_directive: Optional[str] = None
    ) -> Any:
        """Packages tool execution results and checkpoint prompts for the next turn."""
        tool_names_str = ', '.join(state.prev_turn_tools)
        logger.info(f"[{state.trace_id}] [*] Turn {turn+1}: Feeding back {len(turn_result.tool_parts)} results ({tool_names_str})")
        state.emit(f"Analyzing {tool_names_str}...")

        message_payload = self.context_mgr.build_message_payload(turn_result.tool_parts, state.trace_id)
        checkpoint_prompt = self.context_mgr.get_checkpoint_prompt(turn, state.prev_turn_tools, state.trace_id)
        compress_prompt = self.context_mgr.get_compression_prompt(turn, len(chat.history), state.trace_id)

        if checkpoint_prompt:
            message_payload.append(checkpoint_prompt)
        if compress_prompt:
            message_payload.append(compress_prompt)
        if pivot_directive:
            message_payload.append(pivot_directive)

        return self._execute_with_quota_retry(
            lambda: chat.send_message(
                message_payload,
                generation_config=state.base_config,
                request_options={"timeout": DEFAULT_REQUEST_TIMEOUT}
            ),
            operation_name=f"turn {turn + 1} feedback"
        )

    def _finalize_investigation(
        self,
        response: Any,
        state: InvestigationState,
        turn: int,
        **kwargs
    ) -> str:
        """Logs cognitive trace audit and generates the final structured investigation report."""
        try:
            from core.pipeline.cognitive_trace import CognitiveTraceLogger
            trace_logger = CognitiveTraceLogger()
            trace_logger.log_trace(
                state.trace_id,
                kwargs.get('target_mode', state.target_mode),
                state.investigation_trace,
                turn + 1
            )
        except Exception as trace_err:
            logger.debug(f"[{state.trace_id}] [TRACE] Cognitive trace logging skipped: {trace_err}")

        state.emit("Building your report...")
        final_text = self.synthesizer.synthesize_final(response, state.trace_id)

        # Enforce strict JSON schema for range simulation mode
        if state.target_mode == "range":
            final_text = self._enforce_range_schema(final_text, state.trace_id)

        state.emit_chunk(final_text)
        return final_text

    # -------------------------------------------------------------------------
    # Public Agentic Lifecycle Orchestrator
    # -------------------------------------------------------------------------

    def investigate(
        self,
        user_query: str,
        temperature: Optional[float] = None,
        user_id: str = "anonymous",
        status_callback: Optional[Callable[[str], None]] = None,
        target_mode: Optional[str] = None,
        abort_event: Optional[threading.Event] = None,
        chunk_callback: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> str:
        """
        Execute an agentic investigation loop with dynamic tool partitioning.

        Args:
            user_query: The natural language investigation prompt or command.
            temperature: Optional generation temperature override.
            user_id: User identifier for audit logging.
            status_callback: Optional callable for streaming real-time status updates.
            target_mode: Specialized execution mode (e.g. 'range' for attack graph simulation).
            abort_event: Optional threading.Event for graceful mid-flight cancellation.
            chunk_callback: Optional callable receiving streaming text tokens.
            **kwargs: Additional runtime arguments (e.g. base_graph_json).

        Returns:
            Structured investigation findings or partial report upon early termination.
        """
        if not self.api_key and not self.model:
            return "Error: Offline Mode (No API Key or Model configured)."

        # 1. State & Governor Initialization (Thread-safe request-scoped instances)
        state = self._init_investigation_state(
            user_query, user_id, status_callback, target_mode,
            abort_event=abort_event, chunk_callback=chunk_callback,
            temperature=temperature
        )
        reality_check = self._build_reality_prompt(user_query, state)
        chat = self.model.start_chat()

        # 2. Deterministic Workflow Routing (zero-hallucination bypass)
        workflow_report = self._try_deterministic_workflow(
            user_query, reality_check, chat, trace_id=state.trace_id, base_config=state.base_config, **kwargs
        )
        if workflow_report:
            state.emit_chunk(workflow_report)
            return workflow_report

        # 3. Initial Prompt Turn with Circuit Breaker Protection
        response, err = self._execute_initial_turn(chat, user_query, reality_check, state, **kwargs)
        if err:
            return err

        # 4. Multi-Turn Agentic Investigation Loop
        for turn in range(MAX_TURNS):
            if state.is_aborted():
                state.emit("[HALTED] Investigation cancelled by operator.")
                logger.info(f"[{state.trace_id}] Investigation halted via abort_event.")
                return "[HALTED] Investigation cancelled by user request."

            self._track_turn_usage(response, state)

            # Token budget guard
            budget_report = self._check_budget_limits(chat, response, state)
            if budget_report:
                return budget_report

            # Extract Hi-CoT reasoning and execute tool calls
            turn_result = self._process_turn_parts(response, state, turn)

            # Check for dynamic tool tray pivot (e.g. summon_toolkit)
            pivot_directive = self._handle_tool_tray_pivot(turn_result, state)

            # Enforce semantic drift safety boundary
            drift_error = self._evaluate_semantic_drift(turn_result, state, turn, **kwargs)
            if drift_error:
                return drift_error

            # Feed tool execution results back to model
            if turn_result.tool_parts:
                response = self._step_tool_feedback(
                    chat, turn_result, state, turn, pivot_directive=pivot_directive
                )
                continue

            # Evaluate synthesis guards
            guard_response = self.synthesizer.check_guards(
                turn, turn_result.tool_parts, response, chat, state.base_config, state.history, state.trace_id
            )
            if guard_response:
                response = guard_response
                continue

            # Final report generation
            return self._finalize_investigation(response, state, turn, **kwargs)

        return f"[TIMEOUT] Maximum turns ({MAX_TURNS}) reached."

    def investigate_stream(
        self,
        user_query: str,
        temperature: Optional[float] = None,
        user_id: str = "anonymous",
        status_callback: Optional[Callable[[str], None]] = None,
        target_mode: Optional[str] = None,
        abort_event: Optional[threading.Event] = None,
        **kwargs
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Executes investigation and streams SSE-compatible events in real time:
        yields {"type": "status", "content": "..."},
               {"type": "chunk", "content": "..."},
               {"type": "response", "content": "..."},
               {"type": "done"}
        """
        import queue
        event_queue: queue.Queue = queue.Queue()

        def _stream_status(msg: str):
            event_queue.put({"type": "status", "content": msg})
            if status_callback:
                try:
                    status_callback(msg)
                except Exception:
                    pass

        def _stream_chunk(chunk: str):
            event_queue.put({"type": "chunk", "content": chunk})

        investigation_result = [None]
        investigation_error = [None]

        local_abort = abort_event or threading.Event()

        def _worker():
            try:
                res = self.investigate(
                    user_query=user_query,
                    temperature=temperature,
                    user_id=user_id,
                    status_callback=_stream_status,
                    target_mode=target_mode,
                    abort_event=local_abort,
                    chunk_callback=_stream_chunk,
                    **kwargs
                )
                investigation_result[0] = res
            except Exception as ex:
                investigation_error[0] = ex

        worker_thread = threading.Thread(target=_worker, daemon=True)
        worker_thread.start()

        try:
            while worker_thread.is_alive() or not event_queue.empty():
                try:
                    event = event_queue.get(timeout=0.1)
                    yield event
                except queue.Empty:
                    continue

            worker_thread.join()

            if investigation_error[0]:
                yield {"type": "error", "content": str(investigation_error[0])}
            else:
                yield {"type": "response", "content": investigation_result[0]}
                yield {"type": "done"}
        finally:
            local_abort.set()
            worker_thread.join(timeout=2.0)

    def think(self, prompt_text: str, temperature: Optional[float] = None) -> str:
        """Executes the LLM Generation with Fallback Strategy."""
        if not self.api_key and not self.model:
            return "Error: Offline Mode."

        try:
            config = genai.types.GenerationConfig(temperature=temperature)
            prompt_payload = [prompt_text]

            start_ts = time.time()
            response = self._execute_with_quota_retry(
                lambda: self.model.generate_content(
                    prompt_payload,
                    generation_config=config,
                    tool_config={'function_calling_config': {'mode': 'NONE'}},
                    request_options={"timeout": DEFAULT_REQUEST_TIMEOUT}
                ),
                operation_name="think mode"
            )
            latency = int((time.time() - start_ts) * 1000)
            self._track_usage(response, latency)
            try:
                return response.text
            except ValueError:
                logger.warning("[BRAIN] Tool call requested in think mode")
                return "I cannot execute tool commands in think mode. Please use investigation mode."
        except Exception as e:
            if "429" in str(e) or "Quota exceeded" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                logger.error("[QUOTA] Primary model exhausted after retries. No fallback.")
                return (
                    "[QUOTA EXCEEDED] The primary model is rate-limited and all 3 retry attempts failed.\n\n"
                    "Please wait 60 seconds and try again."
                )

            logger.exception(f"Brain Defect: {e}")
            return "An error occurred during thinking. Please check server logs."

    def start_chat(self, history=None):
        """Starts a chat session."""
        if not self.api_key and not self.model:
            return None
        return self.model.start_chat(history=history or [])


# Thread-safe Lazy Singleton
_cortex = None
_cortex_lock = threading.Lock()

def get_brain():
    """Returns the singleton CoreBrain instance, creating it on first call (thread-safe)."""
    global _cortex
    if _cortex is None:
        with _cortex_lock:
            if _cortex is None:
                _cortex = CoreBrain()
    return _cortex


# Backward compatibility proxy -- defers CoreBrain creation until first attribute access.
class _LazyBrainProxy:
    """Proxy that defers CoreBrain creation until first use."""
    def __getattr__(self, name):
        return getattr(get_brain(), name)


cortex = _LazyBrainProxy()
