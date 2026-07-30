import os
import logging
import warnings
import time
import random  # Jitter for retry backoff
import uuid  # Trace ID generation

# Suppress google.generativeai deprecation warnings during import
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    import google.generativeai as genai
    # Import SDK types for ThinkingConfig
    try:
        from google.generativeai import types as genai_types
    except ImportError:
        genai_types = None

logger = logging.getLogger(__name__)

# Standard Absolute Imports
from core.pipeline.tool_keeper import ToolKeeper
from core.safety.circuit_breaker import CircuitBreaker, CircuitBreakerError
from core.safety.semantic_drift_gate import SemanticDriftGate

# Policy-gated execution
try:
    from core.safety.policy_engine import PolicyEngine
except ImportError:
    PolicyEngine = None
    logger.warning("[BRAIN] policy_engine not available — policy checks disabled.")

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
    logger.warning("[HITL] hitl module not available — write operations ungated.")

# =============================================================================
# Core Pipeline Modules
# =============================================================================
from core.pipeline.prompt_assembler import SYSTEM_PROMPT, PROMPT_ASSEMBLY_ORDER
from core.pipeline.model_config import (
    GEMINI_MODEL, PRICE_PER_M_INPUT, PRICE_PER_M_OUTPUT,
    TEMP_DEFAULT, MAX_TURNS,
    classify_mode, get_thinking_level, get_generation_config,
)
from core.pipeline.tool_executor import ToolExecutor
from core.pipeline.context_manager import ContextManager
from core.pipeline.synthesizer import ResponseSynthesizer
from core.integrations.telemetry import UsageTracker

# Budget guard — fail-soft if not available
try:
    from core.safety.budget_guard import BudgetGuard, BudgetExceededError
except ImportError:
    BudgetGuard = None
    BudgetExceededError = None
    logger.warning("[BUDGET] budget_guard not available — cost limits disabled.")



class CoreBrain:
    """
    Central Cognitive Core for PAN-OS investigation.
    Handles Gemini model connection, tool binding, and multi-turn investigation loops.
    """
    
    
    def __init__(self, model=None, tools=None, keeper=None):
        # Load Gemini API key from secrets backend
        from core.integrations.secrets import get_secret
        try:
            self.api_key = get_secret('gemini_api_key')
        except Exception as e:
            logger.error(f"[BRAIN] Failed to load Gemini API key: {e}")
            self.api_key = None
        
        # Dependency injection — accept injected keeper/tools/model for testing
        self.keeper = keeper or ToolKeeper()
        self.tools = tools if tools is not None else self.keeper.get_tools("#core")
        logger.info(f"[BRAIN] ToolKeeper initialized: {len(self.tools)} tools in #core tray.")
        
        if model is not None:
            # Injected model — skip SDK configuration
            self.model = model
            logger.info("[BRAIN] Initialized with injected model (test/mock mode)")
        elif not self.api_key:
            logger.error("[BRAIN] GEMINI_API_KEY not found — model unavailable.")
            self.model = None
        else:
            genai.configure(api_key=self.api_key)
            
            # Disable content safety filters for security audit context
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ]

            # Bind system prompt at the SDK level
            self.model = genai.GenerativeModel(
                model_name=GEMINI_MODEL,
                safety_settings=safety_settings,
                tools=self.tools,
                system_instruction=str(SYSTEM_PROMPT)
            )
            logger.info(f"[BRAIN] Model initialized: {GEMINI_MODEL} ({len(self.tools)} tools)")
        
        # License Awareness Context
        self.license_context = "License Status: UNKNOWN (Assume Capability). Check with 'request license info'."
        
        # Usage tracking
        self.usage_tracker = UsageTracker(
            model_name=GEMINI_MODEL,
            price_input=PRICE_PER_M_INPUT,
            price_output=PRICE_PER_M_OUTPUT
        )
        
        # Safety governor — prevents runaway tool loops
        self.circuit_breaker = CircuitBreaker(max_steps=30, max_loops=4)
        
        # Policy-gated execution
        self.policy = PolicyEngine() if PolicyEngine else None
        
        # Human-in-the-loop approval provider
        if get_hitl_provider:
            hitl_mode = os.getenv("HITL_MODE", "autopilot").lower()
            self.hitl = get_hitl_provider(mode=hitl_mode)
            logger.info(f"[HITL] Provider: {self.hitl.get_mode()}")
        else:
            self.hitl = None
            logger.warning("[HITL] No provider available — write operations ungated.")
        
        # Core pipeline modules
        self.tool_executor = ToolExecutor(
            policy=self.policy,
            hitl=self.hitl,
            circuit_breaker=self.circuit_breaker,
            tools=self.tools
        )
        self.context_mgr = ContextManager()
        self.synthesizer = ResponseSynthesizer()

        # Budget guard — per-investigation + daily cost caps
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
        """Delegates to UsageTracker."""
        self.usage_tracker.track(
            response, latency_ms=latency_ms, success=success, tray=tray,
            ops_count=ops_count, trace_id=trace_id, tool_summary=tool_summary
        )

    def set_license_context(self, status):
        """Updates the License State for prompt injection."""
        self.license_context = f"LICENSE STATE:\n{status}"

    def _build_fleet_context(self) -> str:
        """
        Reads devices.yaml and produces a structured fleet inventory string
        for injection into the LLM context. Called per-investigation so
        changes to devices.yaml are picked up without restart.
        """
        try:
            from pathlib import Path
            import yaml
            devices_path = Path(__file__).resolve().parent.parent / "config" / "devices.yaml"
            if not devices_path.exists():
                return "FLEET_INVENTORY: Single device mode (no devices.yaml found)."

            with open(devices_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            firewalls = data.get("firewalls", {})
            if not firewalls:
                return "FLEET_INVENTORY: No firewalls configured."

            lines = ["FLEET_INVENTORY: Managed devices:"]
            for name, info in firewalls.items():
                label = info.get("label", "")
                is_default = info.get("default", False)
                marker = " ← DEFAULT" if is_default else ""
                lines.append(f"  - {name}: {label}{marker}")

            lines.append("Use target_device=\"<alias>\" in tool calls to target a specific device.")
            return "\n".join(lines)

        except Exception as e:
            logger.warning(f"[FLEET] Failed to build fleet context: {e}")
            return "FLEET_INVENTORY: Unable to load (using default device)."

    def _build_card_context(self, user_query: str) -> str:
        """
        Build card context for the LLM. Two injection types:

        1. CARD_CONTEXT — when user clicks "Investigate" on a card,
           the full finding is injected as prior art.
        2. ACTIVE_ALERTS — top pending CRITICAL/CAUTION cards injected
           as ambient awareness on every query.

        Mirrors the _build_fleet_context() pattern.
        """
        try:
            from core.engine.card_store import CardStore
            store = CardStore.get_instance()
        except Exception:
            return ""  # Card engine not available — silent skip

        parts = []

        # --- CARD_CONTEXT: Specific card investigation ---
        # UI sends "Investigate: <card title>" when user clicks a card
        if user_query.lower().startswith("investigate:"):
            search_title = user_query.split(":", 1)[1].strip()
            if search_title:
                try:
                    # Search pending cards for a title match
                    pending = store.get_pending(limit=50)
                    matched = None
                    for card in pending:
                        if search_title.lower() in card.get("title", "").lower():
                            matched = card
                            break

                    if matched:
                        evidence_str = "\n".join(f"  - {e}" for e in matched.get("evidence", []))
                        metrics_str = ", ".join(f"{k}={v}" for k, v in matched.get("metrics", {}).items())
                        import datetime
                        ts = matched.get("timestamp", 0)
                        time_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "Unknown"

                        parts.append(
                            f"CARD_CONTEXT (Prior Art — do NOT re-run these tools):\n"
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
                for a in alerts[:5]:  # Cap at 5 to control token budget
                    alert_lines.append(
                        f"  [{a.get('severity','').upper()}] {a.get('card_id','')}: {a.get('title','')} — {a.get('finding','')[:120]}"
                    )
                parts.append(
                    f"ACTIVE_ALERTS ({len(alerts)} pending):\n" + "\n".join(alert_lines)
                )
        except Exception as e:
            logger.debug(f"[CARDS] Active alerts query failed: {e}")

        return "\n\n".join(parts)

    def investigate(self, user_query, temperature=None, user_id="anonymous", status_callback=None, target_mode=None, **kwargs):
        """
        Investigation loop with dynamic tool partitioning.
        Stateless, Hot-Swappable Tool Trays.
        Accepts user_id for identity-aware auditing.
        """
        if not self.api_key: return "Error: Offline Mode."
        
        # Unique trace ID for this investigation
        trace_id = str(uuid.uuid4())[:8]
        
        # 1. State Initialization
        active_tray = "#core" # Base state
        history = []
        self._tool_cache = {}  # Clear cache for fresh investigation
        
        # Status callback helper — safe to call even if no callback provided
        def emit_status(msg):
            if status_callback:
                try: status_callback(msg)
                except Exception: pass
        
        # Reset circuit breaker for this investigation (prevents cross-investigation accumulation)
        self.circuit_breaker = CircuitBreaker(max_steps=30, max_loops=4)
        
        # Initialize Semantic Drift Gate
        self.drift_gate = SemanticDriftGate()

        # Reset per-investigation budget counter
        if self.budget_guard:
            self.budget_guard.reset_investigation()
        
        # 2. Dynamic Tool Manifest (The Reality Anchor)
        all_tools = self.keeper.get_tools("#core") # Get all for manifest
        manifest_str = ", ".join([t.__name__ for t in all_tools])
        
        # 3. Runtime Reality Anchor (manifest only — persona is pinned at model init)
        # SYSTEM_PROMPT is set via system_instruction in __init__, not re-injected here.
        fleet_context = self._build_fleet_context()
        card_context = self._build_card_context(user_query)
        reality_check = (
            f"REALITY_CHECK: You only have these tools: [{manifest_str}].\n"
            "Verify tool names against this list before every call.\n\n"
            f"{fleet_context}"
        )
        if card_context:
            reality_check += f"\n\n{card_context}"

        # 4. Initialize Chat Session (Stable Tool Calling)
        chat = self.model.start_chat()
        
        # 5. Cognitive Scaling — G3: Dynamic thinking replaces temperature scaling
        mode = classify_mode(user_query)
        thinking_level = get_thinking_level(mode)
        base_config = get_generation_config()

        print(f"\n[{trace_id}] [ARCHITECT] Investigation Started. User: {user_id}. Mode: {mode}. Thinking: {thinking_level}. Tools: [{manifest_str}]")
        emit_status(f"Connecting to firewall — {mode} mode...")
        
        # Inject thinking_level explicitly into the reality check so the LLM respects the cognitive bounds
        reality_check += f"\n\n[SYSTEM COGNITIVE BOUNDS: Execute with {thinking_level.upper()} reasoning depth.]"
        
        # Route deterministic workflows before the agentic loop
        if run_health_check is not None:
            health_keywords = ["health", "status check", "hardware", "resources", "telemetry"]
            if any(k in user_query.lower() for k in health_keywords):
                logger.info(f"[{trace_id}] [WORKFLOW] Routing to deterministic health check")
                try:
                    health_summary = run_health_check(
                        tool_executor=lambda name, args: self._execute_tool(name, args)
                    )
                    # Send pre-digested summary to LLM for final synthesis (1 turn)
                    synthesis_prompt = f"{reality_check}\n\nSYNTHESIZE this health check report for the user:\n{health_summary}"
                    response = chat.send_message(synthesis_prompt, generation_config=base_config)
                    try:
                        return response.text
                    except ValueError:
                        return health_summary  # Fallback: return raw summary
                except Exception as wf_err:
                    logger.warning(f"[{trace_id}] [WORKFLOW] Health check failed: {wf_err}. Falling back to agentic loop.")
        
        try:
            # Inject runtime Reality Anchor, then user query or specialized mission
            if target_mode == "range":
                from core.pipeline.prompt_assembler import load_range_prompt
                # Option 2 Cartographer hook: receive base_graph_json from kwargs
                base_graph = kwargs.get("base_graph_json", "{}")
                range_instructions = load_range_prompt().format(user_query=user_query, base_graph_json=base_graph)
                user_msg = f"{reality_check}\n\n{range_instructions}"
            else:
                user_msg = f"{reality_check}\n\nINVESTIGATE: {user_query}"
            
            initial_payload = [user_msg]
            response = chat.send_message(initial_payload, generation_config=base_config)
        except CircuitBreakerError as e:
            logger.error(f"[{trace_id}] [SHIELD] Circuit Breaker Tripped: {e}")
            # Reflection governor — summarize findings before terminating
            try:
                reflection_prompt = (
                    "[SYSTEM: LOOP DETECTED. Your investigation is being terminated for safety. "
                    "Before shutdown, produce a PARTIAL REPORT: "
                    "1) WHAT_TRIED: List every tool you called and key findings. "
                    "2) WHY_STALLED: One sentence on why you were repeating actions. "
                    "3) RECOMMENDATION: What the human should investigate manually.]"
                )
                reflection_response = chat.send_message(
                    reflection_prompt,
                    generation_config=base_config  # Use default temp 1.0, not 0.0
                )
                partial_report = reflection_response.text
                logger.info(f"[{trace_id}] [REFLECT] Partial report generated on circuit break.")
                return f"⚠️ INVESTIGATION HALTED (Safety Governor)\n\n{partial_report}"
            except Exception as reflect_err:
                logger.warning(f"[{trace_id}] [REFLECT] Reflection failed: {reflect_err}")
                return f"PROCESS TERMINATED BY SAFETY GOVERNOR: {e}"
        except Exception as e:
            logger.error(f"[{trace_id}] [ARCHITECT] Investigation Failed: {e}")
            return f"Internal Error: {e}"

        # 6. Optimized Tool Loop — MAX_TURNS imported from model_config (G3: 14 turns)
        prev_turn_tools = []  # Track tools per turn for audit
        drive_call_history = {}  # Track Drive calls across all turns to prevent duplicates
        drive_slices = []  # Track Drive slice calls for efficiency monitoring
        investigation_trace = [] # Track Hi-CoT reasoning for Cognitive Analytics

        for turn in range(MAX_TURNS):
            # Telemetry
            tool_summary = ", ".join(prev_turn_tools) if prev_turn_tools else ""
            self._track_usage(response, trace_id=trace_id, tool_summary=tool_summary)
            prev_turn_tools = []

            # Budget enforcement — record token usage and check limits
            if self.budget_guard and hasattr(response, 'usage_metadata'):
                try:
                    meta = response.usage_metadata
                    self.budget_guard.record_usage(
                        prompt_tokens=getattr(meta, 'prompt_token_count', 0),
                        response_tokens=getattr(meta, 'candidates_token_count', 0),
                    )
                except BudgetExceededError as be:
                    logger.warning(f"[{trace_id}] [BUDGET] {be}")
                    # Synthesize partial results gracefully
                    try:
                        budget_prompt = (
                            "[SYSTEM: Budget limit reached. Produce a PARTIAL REPORT from the data "
                            "you have gathered so far. Include all findings and recommendations.]"
                        )
                        partial_resp = chat.send_message(budget_prompt, generation_config=base_config)
                        return f"⚠️ BUDGET LIMIT REACHED ({self.budget_guard.get_status()})\n\n{partial_resp.text}"
                    except Exception:
                        return f"⚠️ BUDGET LIMIT REACHED: {be}"
            
            # Context compression is now handled safely during payload building.
            
            # Process tool calls via ToolExecutor
            tool_parts = []
            turn_ops_count = 0
            thought_signatures = []
            turn_reasoning_parts = []  # Accumulate all reasoning text from this turn
            
            for part in response.parts:
                # 1. Intercept Reasoning Trace (Hi-CoT Extraction)
                if hasattr(part, 'text') and part.text:
                    import re
                    match = re.search(r'<REASONING>(.*?)</REASONING>', part.text, re.DOTALL | re.IGNORECASE)
                    if match:
                        reasoning_text = match.group(1).strip()
                        turn_reasoning_parts.append(reasoning_text)
                        
                        clean_reasoning = " | ".join(line.strip() for line in reasoning_text.split('\n') if line.strip())
                        emit_status(f"[NEO-THINK] {clean_reasoning[:150]}...")
                        
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
                        investigation_trace.append(trace_turn)

                # 2. Process function calls
                if part.function_call:
                    result = self.tool_executor.execute_function_call(
                        part=part,
                        manifest_str=manifest_str,
                        trace_id=trace_id,
                        user_id=user_id,
                        drive_call_history=drive_call_history,
                        turn=turn,
                        thought_signatures=thought_signatures,
                    )
                    tool_parts.append(result.response_part)
                    prev_turn_tools.append(result.tool_name)
                    # Update state history for Synthesizer guards
                    history.append(part)
                    turn_ops_count += result.ops_count
                    if result.drive_slice_info:
                        drive_slices.append(result.drive_slice_info)
                        if len(drive_slices) >= 3:
                            logger.warning(f"[{trace_id}] [EFFICIENCY] {len(drive_slices)} Drive slices read. Consider synthesis.")

            # --- SEMANTIC DRIFT CHECK (per-turn, after all parts processed) ---
            if turn_reasoning_parts:
                combined_reasoning = "\n".join(turn_reasoning_parts)
                gate_result = self.drift_gate.check(combined_reasoning, trace_id, turn)
                
                # Append drift telemetry to the trace log for auditing
                if investigation_trace:
                    investigation_trace[-1]["drift_score"] = round(gate_result.similarity, 3)
                    investigation_trace[-1]["drift_severity"] = gate_result.severity

                # Emit drift telemetry to frontend on every check (not just caution)
                emit_status(f"[DRIFT:{gate_result.severity}:{gate_result.similarity:.3f}:T{turn}]")
                if not gate_result.allowed:
                    logger.error(f"[{trace_id}] [SHIELD] Semantic Drift Gate Tripped: {gate_result.message}")
                    # Preserve audit trail before halting
                    try:
                        from core.pipeline.cognitive_trace import CognitiveTraceLogger
                        trace_logger = CognitiveTraceLogger()
                        trace_logger.log_trace(trace_id, kwargs.get('target_mode', 'default'), investigation_trace, turn + 1)
                    except Exception:
                        pass
                    return f"⚠️ INVESTIGATION HALTED (Semantic Drift Safety Gate)\n\n{gate_result.message}"
                elif gate_result.severity == "caution":
                    emit_status(f"[DRIFT-CAUTION] {gate_result.message}")

            if tool_parts:
                tool_names_str = ', '.join(prev_turn_tools)
                logger.info(f"[{trace_id}] [*] Turn {turn+1}: Feeding back {len(tool_parts)} results ({tool_names_str})")
                emit_status(f"Analyzing {tool_names_str}...")
                
                # Context manager handles Drive file extraction + payload building
                message_payload = self.context_mgr.build_message_payload(tool_parts, trace_id)
                
                # Check for context compression or checkpoint prompts to inject safely
                checkpoint_prompt = self.context_mgr.get_checkpoint_prompt(turn, prev_turn_tools, trace_id)
                compress_prompt = self.context_mgr.get_compression_prompt(turn, len(chat.history), trace_id)
                
                if checkpoint_prompt:
                    message_payload.append(checkpoint_prompt)
                if compress_prompt:
                    message_payload.append(compress_prompt)
                    
                response = chat.send_message(message_payload, generation_config=base_config)
                continue
            
            # Guards: first-turn retry, Drive follow-up (delegated to ResponseSynthesizer)
            guard_response = self.synthesizer.check_guards(
                turn, tool_parts, response, chat, base_config, history, trace_id
            )
            if guard_response:
                response = guard_response
                continue
            
            # Cognitive Trace Analytics
            try:
                from core.pipeline.cognitive_trace import CognitiveTraceLogger
                trace_logger = CognitiveTraceLogger()
                trace_logger.log_trace(trace_id, kwargs.get('target_mode', 'default'), investigation_trace, turn + 1)
            except Exception as trace_err:
                logger.error(f"[{trace_id}] [TRACE] Failed to log cognitive trace: {trace_err}")

            # Final synthesis (delegated to ResponseSynthesizer)
            emit_status("Building your report...")
            return self.synthesizer.synthesize_final(response, trace_id)

        return f"[TIMEOUT] Maximum turns ({MAX_TURNS}) reached."




    def think(self, prompt_text, temperature=None):
        """Executes the LLM Generation with Fallback Strategy."""
        if not self.api_key: return "Error: Offline Mode."
        
        # Primary Attempt
        try:
            config = genai.types.GenerationConfig(temperature=temperature)
            prompt_payload = [prompt_text]
                
            start_ts = time.time()
            response = self.model.generate_content(
                prompt_payload,
                generation_config=config,
                tool_config={'function_calling_config': {'mode': 'NONE'}} # Think mode = No tools
            )
            latency = int((time.time() - start_ts) * 1000)
            self._track_usage(response, latency)
            try:
                return response.text
            except ValueError:
                # Occurs if response is a Function Call but we are in 'think' mode (no chat loop)
                return f"[Brain Interrupted] I wanted to execute a tool actions but I am in 'Think' mode. Use --investigate to allow me to run commands.\nRaw Parts: {response.parts}"
        except Exception as e:
            if "429" in str(e) or "Quota exceeded" in str(e):
                # Exponential backoff with jitter — retry primary before degrading
                for attempt in range(3):
                    wait = (2 ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        f"[QUOTA] {GEMINI_MODEL} rate-limited (attempt {attempt + 1}/3). "
                        f"Retrying in {wait:.1f}s..."
                    )
                    time.sleep(wait)
                    try:
                        response = self.model.generate_content(
                            prompt_payload,
                            generation_config=config,
                            tool_config={'function_calling_config': {'mode': 'NONE'}}
                        )
                        latency = int((time.time() - start_ts) * 1000)
                        self._track_usage(response, latency)
                        try:
                            return response.text
                        except ValueError:
                            return f"[Brain Interrupted] Think mode received non-text response after retry.\nRaw Parts: {response.parts}"
                    except Exception as retry_exc:
                        if "429" not in str(retry_exc) and "Quota exceeded" not in str(retry_exc):
                            raise  # Non-quota error — don't retry, surface immediately
                
                # All 3 retries exhausted — return clean quota error
                logger.error(f"[QUOTA] Primary model exhausted after 3 retries. No fallback.")
                return (
                    "[QUOTA EXCEEDED] The primary model is rate-limited and all 3 retry attempts failed.\n\n"
                    "Please wait 60 seconds and try again."
                )
            
            logger.error(f"Brain Defect: {e}")
            return f"Thinking Error: {e}"

    def start_chat(self, history=None):
        """Starts a chat session."""
        if not self.api_key: return None
        return self.model.start_chat(history=history or [])

# Lazy Singleton — avoids side effects on import for testing
_cortex = None

def get_brain():
    """Returns the singleton CoreBrain instance, creating it on first call."""
    global _cortex
    if _cortex is None:
        _cortex = CoreBrain()
    return _cortex

# Backward compatibility proxy — defers CoreBrain creation until first attribute access.
class _LazyBrainProxy:
    """Proxy that defers CoreBrain creation until first use."""
    def __getattr__(self, name):
        return getattr(get_brain(), name)

cortex = _LazyBrainProxy()
