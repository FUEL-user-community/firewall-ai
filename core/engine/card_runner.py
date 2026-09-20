"""
CardRunner — Single-Card Execution Engine.

Takes a card definition from cards.yaml and executes its tool chain
through the existing ToolExecutor pipeline (preserving all safety gates).

Flow: Load card → Execute tool chain → LLM synthesis → Trigger evaluation
      → Baseline comparison → Store result.
"""

import os
import re
import json
import yaml
import time
import inspect
import logging
import warnings
import threading
import ipaddress
from pathlib import Path
from typing import Optional, Dict, Any, List

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        import google.generativeai as genai
    except ImportError:
        genai = None

from core.engine.card_store import CardStore, CardResult
from core.engine.baseline import BaselineEngine
from core.pipeline.model_config import (
    GEMINI_MODEL,
    EMBEDDING_MODEL,
    EMBEDDING_DIMENSIONS,
    get_card_generation_config,
)

# Fail-soft imports — mirrors brain.py pattern
try:
    from core.safety.policy_engine import PolicyEngine
except ImportError:
    PolicyEngine = None

try:
    from core.safety.budget_guard import BudgetGuard, BudgetExceededError
except ImportError:
    BudgetGuard = None
    BudgetExceededError = None

# Visibility modules — fail-soft
try:
    from core.visibility.logprobs import extract_logprobs
except ImportError:
    extract_logprobs = None

try:
    from core.visibility.auditor import Auditor
except ImportError:
    Auditor = None

logger = logging.getLogger(__name__)

# Severity ranking for max() comparison
_SEVERITY_RANK = {"normal": 0, "caution": 1, "critical": 2}

# Path to cards definition file
_CARDS_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "cards.yaml"

# Path to devices fleet definition file
_DEVICES_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "devices.yaml"

# Shared tool config disabling function calling during card synthesis
NO_TOOLS_CONFIG = {'function_calling_config': {'mode': 'NONE'}}


class CardRunner:
    """
    Executes a single card definition through the full pipeline.

    Uses the existing ToolKeeper → ToolExecutor infrastructure for
    tool execution, preserving Ghost Guard, Policy Gate, HITL, etc.
    """

    _cards_cache: Optional[Dict] = None
    _cards_mtime: float = 0
    _cards_lock = threading.Lock()
    _genai_configured = False

    def __init__(self):
        self.store = CardStore.get_instance()
        self.baseline = BaselineEngine.get_instance()

        # Card-specific budget guard (separate from chat budget)
        if BudgetGuard:
            self.budget_guard = BudgetGuard(
                max_per_investigation=float(os.getenv("CARD_BUDGET_PER_RUN", "1.00")),
                max_per_day=float(os.getenv("CARD_BUDGET_PER_DAY", "10.00")),
            )
            logger.info(f"[CardRunner] Budget: ${self.budget_guard.max_per_investigation}/card, ${self.budget_guard.max_per_day}/day")
        else:
            self.budget_guard = None

        # Policy engine for WRITE tool enforcement
        self.policy = PolicyEngine() if PolicyEngine else None

        # Initialize LLM model once (avoid reconfiguring global state per-card)
        self._model = self._init_model()

        # Cache ToolKeeper and tool map (avoid re-reading commands.yaml per-card)
        self._tool_map = None

    def _validate_device(self, device: Optional[str]) -> Optional[str]:
        """
        Validates target device name against known devices from devices.yaml (C1).
        Rejects special characters to prevent XML injection into PAN-OS commands.
        """
        if not device or device == "default":
            return None

        # Sanitize characters: allow only alphanumeric, underscores, hyphens
        if not re.match(r"^[a-zA-Z0-9_-]+$", device):
            raise ValueError(f"[CardRunner] Invalid device alias format: '{device}'")

        # If devices.yaml exists, verify device alias is declared
        if _DEVICES_PATH.exists():
            try:
                with open(_DEVICES_PATH, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                known_devices = data.get("firewalls", {})
                if known_devices and device not in known_devices:
                    raise ValueError(
                        f"[CardRunner] Device '{device}' not found in devices.yaml. "
                        f"Configured devices: {list(known_devices.keys())}"
                    )
            except ValueError:
                raise
            except Exception as e:
                logger.warning(f"[CardRunner] Could not load devices.yaml for validation: {e}")

        return device

    def _init_model(self):
        """Initialize the Gemini model once for reuse across all card executions."""
        if genai is None:
            logger.error("[CardRunner] google-generativeai package not available")
            return None

        try:
            from core.integrations.secrets import get_secret
            api_key = get_secret('gemini_api_key')
            if not CardRunner._genai_configured:
                genai.configure(api_key=api_key)
                CardRunner._genai_configured = True

            model = genai.GenerativeModel(
                model_name=GEMINI_MODEL,
                system_instruction=(
                    "You are a cybersecurity analysis engine. You receive PAN-OS firewall "
                    "telemetry and produce structured JSON assessments. Be precise, cite evidence, "
                    "and never fabricate data. Respond ONLY with valid JSON."
                )
            )
            logger.info(f"[CardRunner] Gemini model initialized ({GEMINI_MODEL})")
            return model
        except Exception as e:
            logger.error(f"[CardRunner] Model init failed (will retry per-card): {e}")
            return None

    def _get_tool_map(self) -> Dict:
        """Lazy-load and cache the complete tool map from ToolKeeper across all categories."""
        if self._tool_map is None:
            from core.pipeline.tool_keeper import ToolKeeper
            keeper = ToolKeeper()
            all_tools = keeper.get_all_tools()
            self._tool_map = {t.__name__: t for t in all_tools}
        return self._tool_map

    @classmethod
    def load_cards(cls) -> Dict:
        """
        Load and cache card definitions from cards.yaml.
        Hot-reloads if the file has changed. Thread-safe via class lock.
        """
        if not _CARDS_PATH.exists():
            logger.warning(f"[CardRunner] cards.yaml not found at {_CARDS_PATH}")
            return {}

        with cls._cards_lock:
            try:
                mtime = _CARDS_PATH.stat().st_mtime
                if cls._cards_cache is not None and mtime == cls._cards_mtime:
                    return cls._cards_cache

                with open(_CARDS_PATH, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                cls._cards_cache = data.get("cards", {})
                cls._cards_mtime = mtime
                logger.info(f"[CardRunner] Loaded {len(cls._cards_cache)} card definitions")
                return cls._cards_cache
            except Exception as e:
                logger.error(f"[CardRunner] Failed to load cards.yaml: {e}")
                return cls._cards_cache or {}

    def get_card_def(self, card_key: str) -> Optional[Dict]:
        """Get a single card definition by key."""
        cards = self.load_cards()
        return cards.get(card_key)

    def get_cards_by_schedule(self, schedule: str) -> Dict[str, Dict]:
        """Get all card definitions matching a schedule type."""
        cards = self.load_cards()
        return {k: v for k, v in cards.items() if v.get("schedule") == schedule}

    def execute(self, card_key: str, device: str = "default") -> Optional[CardResult]:
        """
        Execute a single card through the full pipeline.

        1. Load card definition
        2. Check if muted
        3. Execute tool chain (sequentially)
        4. Send tool outputs + reasoning prompt to LLM for synthesis
        5. Parse structured JSON output
        6. Compare against baseline
        7. Store result

        Returns CardResult or None if skipped (muted/dedup/error/budget).
        """
        card_def = self.get_card_def(card_key)
        if not card_def:
            logger.error(f"[CardRunner] Card '{card_key}' not found in registry")
            return None

        card_id = card_def.get("id", card_key)
        card_name = card_def.get("name", card_key)

        # Validate target device early
        try:
            device = self._validate_device(device) or "default"
        except ValueError as ve:
            logger.error(f"[CardRunner] {card_id} aborted — invalid device: {ve}")
            return None

        # Check mute
        if self.store.is_muted(card_key):
            logger.debug(f"[CardRunner] {card_id} muted — skipping")
            return None

        logger.info(f"[CardRunner] ▶ Executing: {card_id} ({card_name})")
        start_time = time.time()

        # Reset per-card budget counter
        if self.budget_guard:
            self.budget_guard.reset_investigation()

        try:
            # Step 1: Execute tool chain
            tool_outputs = self._run_tool_chain(card_def, device)

            # Step 2: LLM synthesis
            try:
                structured = self._synthesize(card_def, tool_outputs)
            except BudgetExceededError as be:
                logger.warning(f"[CardRunner] {card_id} halted due to budget exceedance: {be}")
                return None

            if not structured:
                logger.warning(f"[CardRunner] {card_id} — LLM synthesis returned no structured output")
                return None

            # Step 3: Baseline comparison (escalate only)
            metrics = structured.get("metrics", {})
            baseline_key = f"{device}:{card_id}" if device and device != "default" else card_id
            if metrics:
                drift = self.baseline.compare(baseline_key, metrics)
                if drift.has_drift:
                    # Escalate severity if baseline says so
                    current_rank = _SEVERITY_RANK.get(structured.get("severity", "normal"), 0)
                    drift_rank = _SEVERITY_RANK.get(drift.drift_severity, 0)
                    if drift_rank > current_rank:
                        structured["severity"] = drift.drift_severity
                        structured["finding"] += f"\nBASELINE DRIFT: {drift.drift_summary}"
                        logger.info(f"[CardRunner] {card_id} severity escalated by baseline: {drift.drift_severity}")

                # Record current metrics for future baseline
                self.baseline.record(baseline_key, metrics)

            # Step 4: Build CardResult
            # Safety enforcement: ALL WRITE tool actions require approval
            actions = card_def.get("actions", [])
            safe_actions = self._enforce_write_approval(actions)

            result = CardResult(
                card_id=card_id,
                card_key=card_key,
                name=card_name,
                severity=structured.get("severity", card_def.get("severity", "normal")),
                title=structured.get("title", card_name),
                finding=structured.get("finding", "No findings."),
                evidence=structured.get("evidence", []),
                metrics=metrics,
                actions=safe_actions,
                reasoning_trace=structured.get("reasoning_trace", []),
                trust_score=1.0,  # Will be updated by validation
                confidence_margin=structured.get("_confidence_margin"),  # From logprobs
                device=device,
                schedule=card_def.get("schedule", "daily"),
            )

            # Step 5: Fabrication cross-validation
            validation = self._validate_evidence(tool_outputs, result.evidence)
            result.trust_score = validation["trust_score"]
            if validation["unverified"]:
                logger.warning(
                    f"[CardRunner] [WARN] {card_id} trust_score={result.trust_score:.2f} — "
                    f"{len(validation['unverified'])} unverified evidence claims"
                )

            # Step 6: Debate Protocol (Gemini Flash auditor)
            if Auditor and result.reasoning_trace:
                try:
                    auditor = Auditor.get_instance()
                    audit = auditor.audit(
                        tool_outputs=tool_outputs,
                        reasoning_trace=result.reasoning_trace,
                        severity=result.severity,
                        finding=result.finding,
                    )
                    result.audit_result = {
                        "disputes": audit.disputes,
                        "confirmed": audit.confirmed,
                        "omissions": audit.omissions,
                        "audit_score": audit.audit_score,
                        "summary": audit.summary,
                    }
                    # Penalize trust score if auditor found disputes
                    if audit.disputes:
                        result.trust_score = min(result.trust_score, audit.audit_score)
                except Exception as audit_err:
                    logger.debug(f"[CardRunner] Auditor error (skipped): {audit_err}")

            # Step 7: Semantic Drift (Embedding)
            embedding = self._embed_reasoning(result.reasoning_trace)
            if embedding:
                result.reasoning_embedding = embedding
                # Record for future baseline comparisons
                self.baseline.record_embedding(baseline_key, embedding)
                # Compare against historical baseline
                drift = self.baseline.compare_embedding(baseline_key, embedding)
                if drift.has_drift:
                    current_rank = _SEVERITY_RANK.get(result.severity, 0)
                    drift_rank = _SEVERITY_RANK.get(drift.drift_severity, 0)
                    if drift_rank > current_rank:
                        result.finding += f"\n{drift.drift_summary}"
                        logger.warning(f"[CardRunner] {card_id} SEMANTIC DRIFT: {drift.drift_summary}")

            # Step 8: Only store if triggered (or if card has no trigger condition)
            triggered = structured.get("triggered", True)
            if not triggered:
                logger.info(f"[CardRunner] {card_id} — not triggered, skipping storage")
                return None

            # Step 9: Store result
            elapsed = time.time() - start_time
            result_id = self.store.store_result(result)

            if result_id:
                result.id = result_id
                logger.info(
                    f"[CardRunner] [OK] {card_id} completed in {elapsed:.1f}s — "
                    f"severity={result.severity}, stored={result_id}"
                )
                return result
            else:
                logger.info(f"[CardRunner] {card_id} — deduplicated (same finding exists)")
                return None

        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"[CardRunner] [FAIL] {card_id} failed after {elapsed:.1f}s: {e}")
            return None

    def _resolve_identities(self, tool_outputs: List[Dict], device: Optional[str]) -> List[Dict]:
        """
        Extracts valid IPv4 addresses from tool outputs and resolves User-ID
        context via PAN-OS, returning an augmented copy of tool outputs.

        Validates all IPs with ipaddress to prevent invalid IPs (C2).
        Validates target_device to prevent XML injection (C1).
        Preserves caller's input list immutability (M1).
        """
        try:
            from core.panos.ops import execute_operational_command
        except ImportError:
            return tool_outputs

        # Validate target device parameter
        try:
            validated_device = self._validate_device(device)
        except ValueError as ve:
            logger.warning(f"[IdentityMiddleware] Device validation failed: {ve}")
            return tool_outputs

        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        valid_ips = set()

        for t in tool_outputs:
            raw_text = t.get("output", "")
            # Strip XML tags and attributes before scanning for IPs
            clean_text = re.sub(r'<[^>]+>', ' ', raw_text)
            for candidate in ip_pattern.findall(clean_text):
                try:
                    ip_obj = ipaddress.IPv4Address(candidate)
                    # Filter loopback, multicast, link-local, unspecified, and reserved.
                    # Note: RFC1918 private IPs are intentionally KEPT for enterprise User-ID resolution (M2).
                    if not (
                        ip_obj.is_loopback
                        or ip_obj.is_multicast
                        or ip_obj.is_link_local
                        or ip_obj.is_unspecified
                        or ip_obj.is_reserved
                    ):
                        valid_ips.add(str(ip_obj))
                except ValueError:
                    # Invalid octet (e.g. 999.999.999.999 or version numbers)
                    continue

        if not valid_ips:
            return tool_outputs

        resolved_info = []

        try:
            cmd = "<show><user><ip-user-mapping><all/></ip-user-mapping></user></show>"
            uid_xml = execute_operational_command(cmd, target_device=validated_device)

            # Simple parser to map IPs to Users from the full table
            mapping = {}
            entries = re.findall(r'<entry[^>]*>(.*?)</entry>', str(uid_xml), re.DOTALL)
            for entry in entries:
                ip_match = re.search(r'<ip>(.*?)</ip>', entry)
                user_match = re.search(r'<user>(.*?)</user>', entry)
                if ip_match and user_match:
                    mapping[ip_match.group(1)] = user_match.group(1)

            for ip in sorted(valid_ips):
                if ip in mapping:
                    resolved_info.append(f"Entity Resolution: IP {ip} belongs to User '{mapping[ip]}'")

        except Exception as e:
            logger.debug(f"[IdentityMiddleware] Batch User-ID lookup failed: {e}")

        # Return a fresh shallow copy rather than mutating caller's list (M1)
        augmented_outputs = list(tool_outputs)
        if resolved_info:
            logger.info(f"[IdentityMiddleware] Auto-resolved {len(resolved_info)} user identities.")
            augmented_outputs.append({
                "tool": "Identity_Middleware",
                "output": "Automated Context Injection:\n" + "\n".join(resolved_info)
            })

        return augmented_outputs

    def _run_tool_chain(self, card_def: Dict, device: str) -> List[Dict[str, str]]:
        """
        Execute each tool in the card's tool_chain sequentially.
        Returns list of {tool_name, output} dicts.
        """
        tool_map = self._get_tool_map()
        tool_chain = card_def.get("tool_chain") or []
        outputs = []

        # Validate device alias
        validated_device = self._validate_device(device)

        for tool_name in tool_chain:
            tool_func = tool_map.get(tool_name)
            if not tool_func:
                outputs.append({
                    "tool": tool_name,
                    "output": f"ERROR: Tool '{tool_name}' not found in toolkit"
                })
                continue

            try:
                # Pass target_device if the tool accepts it
                sig = inspect.signature(tool_func)
                if 'target_device' in sig.parameters:
                    result = tool_func(target_device=validated_device)
                else:
                    result = tool_func()

                raw_str = str(result)
                # Cap per-tool output to prevent context explosion, notifying LLM of truncation (H4)
                if len(raw_str) > 8000:
                    truncated_str = raw_str[:8000] + f"\n[... OUTPUT TRUNCATED — original length: {len(raw_str)} chars]"
                else:
                    truncated_str = raw_str

                outputs.append({
                    "tool": tool_name,
                    "output": truncated_str
                })
                logger.debug(f"[CardRunner]   → {tool_name}: {len(raw_str)} chars")

            except Exception as e:
                outputs.append({
                    "tool": tool_name,
                    "output": f"ERROR: {e}"
                })
                logger.warning(f"[CardRunner]   → {tool_name} failed: {e}")

        # Execute Automated Identity Resolution Middleware
        outputs = self._resolve_identities(outputs, validated_device)

        return outputs

    def _synthesize(self, card_def: Dict, tool_outputs: List[Dict]) -> Optional[Dict[str, Any]]:
        """
        Send tool outputs + reasoning prompt to LLM for structured synthesis (L4).

        Returns:
            Dict containing parsed JSON assessment with keys:
            - 'severity' (str): 'normal' | 'caution' | 'critical'
            - 'title' (str): Short human-readable title
            - 'finding' (str): Core diagnosis narrative
            - 'evidence' (List[str]): Grounded claims from tool outputs
            - 'metrics' (Dict[str, Any]): Quantitative telemetry extracted
            - 'reasoning_trace' (List[str]): Step-by-step chain of thought
            - 'triggered' (bool): True if card alert condition met
            Or None if synthesis fails or budget exceeded.
        """
        reasoning_prompt = card_def.get("reasoning_prompt", "Analyze the tool outputs and report findings.")

        # Build the synthesis prompt
        tool_section = "\n\n".join([
            f"--- TOOL: {t['tool']} ---\n{t['output']}"
            for t in tool_outputs
        ])

        synthesis_prompt = (
            f"CARD: {card_def.get('name', 'Unknown')}\n"
            f"DESCRIPTION: {card_def.get('description', '')}\n\n"
            f"TOOL CHAIN OUTPUT:\n{tool_section}\n\n"
            f"REASONING INSTRUCTIONS:\n{reasoning_prompt}\n\n"
            "CRITICAL: Include a 'reasoning_trace' array in your JSON output. "
            "Each element should be one step of your analysis, e.g.:\n"
            '  "reasoning_trace": ["Step 1: Examined session_info — 0 active sessions", '
            '"Step 2: Cross-referenced with threat_logs — no entries", '
            '"Step 3: This indicates telemetry collection failure, not absence of threats"]\n\n'
            "Your evidence claims MUST be grounded in the tool output above. "
            "Do NOT fabricate data points, IP addresses, or statistics that do not appear in the tool output.\n\n"
            "IMPORTANT: Your response MUST be a single valid JSON object and nothing else. "
            "No markdown, no code fences, no explanation — just the JSON."
        )

        raw_text = ""

        try:
            model = self._model
            if model is None:
                # Retry model init if it failed during __init__
                model = self._init_model()
                if model is None:
                    logger.error("[CardRunner] No Gemini model available")
                    return None
                self._model = model

            # Fresh generation config instance without mutating shared object (H2)
            base_config = get_card_generation_config()
            config = genai.types.GenerationConfig(
                max_output_tokens=getattr(base_config, 'max_output_tokens', 4096),
                response_mime_type="application/json",
            )

            response = model.generate_content(
                synthesis_prompt,
                generation_config=config,
                tool_config=NO_TOOLS_CONFIG
            )

            # Track budget — propagate BudgetExceededError (H5)
            if self.budget_guard and hasattr(response, 'usage_metadata'):
                meta = response.usage_metadata
                prompt_tokens = getattr(meta, 'prompt_token_count', 0)
                response_tokens = getattr(meta, 'candidates_token_count', 0)
                try:
                    self.budget_guard.record_usage(
                        prompt_tokens=prompt_tokens,
                        response_tokens=response_tokens,
                    )
                except BudgetExceededError as be:
                    logger.warning(f"[CardRunner] Budget exceeded during card run: {be}")
                    raise
                except Exception as be:
                    logger.warning(f"[CardRunner] Budget tracking non-fatal error: {be}")

            # Safely access response.text to handle candidate blocking (BONUS Resilience)
            try:
                raw_text = response.text.strip() if hasattr(response, 'text') else ""
            except (ValueError, AttributeError) as ve:
                logger.warning(f"[CardRunner] Candidate text blocked by safety or empty: {ve}")
                return None

            if not raw_text:
                logger.warning("[CardRunner] Received empty text from Gemini synthesis")
                return None

            parsed = json.loads(raw_text)

            # Extract logprobs and attach confidence margin to the result if available
            if extract_logprobs:
                try:
                    logprob_result = extract_logprobs(response)
                    if logprob_result and getattr(logprob_result, "confidence_margin", None) is not None:
                        parsed["_confidence_margin"] = logprob_result.confidence_margin
                except Exception as lpe:
                    logger.debug(f"[CardRunner] Logprob extraction skipped: {lpe}")

            return parsed

        except BudgetExceededError:
            raise
        except json.JSONDecodeError as je:
            logger.error(f"[CardRunner] JSON parse error: {je}")
            logger.debug(f"[CardRunner] Raw LLM response: {raw_text[:500]}")
            return None
        except Exception as e:
            logger.error(f"[CardRunner] LLM synthesis failed: {e}")
            return None

    def _enforce_write_approval(self, actions: List[Dict]) -> List[Dict]:
        """
        Safety enforcement: ALL actions that use WRITE tools MUST have
        requires_approval: true, regardless of what cards.yaml says.
        """
        if not self.policy:
            return actions

        safe_actions = []
        for action in actions:
            action_copy = dict(action)
            tool_name = action_copy.get("tool")
            if tool_name and hasattr(self.policy, 'WRITE_TOOLS'):
                if tool_name in self.policy.WRITE_TOOLS:
                    action_copy["requires_approval"] = True
                    if not action.get("requires_approval"):
                        logger.warning(
                            f"[CardRunner] SAFETY: Forced requires_approval=true on WRITE tool '{tool_name}'"
                        )
            safe_actions.append(action_copy)

        return safe_actions

    def _validate_evidence(self, tool_outputs: List[Dict], evidence: List[str]) -> Dict[str, Any]:
        """
        Fabrication Cross-Validation — compare model's evidence claims
        against raw tool output to detect hallucinated data points.

        Strengthened heuristic (M3):
        - A claim cannot be validated solely by mentioning a tool name.
        - Requires matching factual data (IPs, numbers) OR high lexical overlap
          with the specific tool output cited.
        """
        if not evidence:
            return {"verified": [], "unverified": [], "trust_score": 1.0}

        # Combine all raw tool output into one searchable corpus
        raw_corpus = " ".join([t.get("output", "") for t in tool_outputs]).lower()
        tool_names = {t.get("tool", "").lower() for t in tool_outputs}

        verified = []
        unverified = []

        for claim in evidence:
            claim_lower = claim.lower()
            grounded = False

            # Extract key data points from the claim
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', claim)
            numbers = re.findall(r'\b\d+(?:\.\d+)?(?:%|sessions?|rules?|entries|connections?)?\b', claim)
            tool_refs = re.findall(r'(\w+):', claim_lower)
            matching_tool_refs = [ref for ref in tool_refs if ref in tool_names]

            # 1. IP match — strong signal: verified if candidate IP exists in corpus
            if ips and any(ip in raw_corpus for ip in ips):
                grounded = True

            # 2. Tool name reference — MUST be corroborated by numbers, IPs, or specific tool text (M3)
            elif matching_tool_refs:
                sig_numbers = [n for n in numbers if len(n) > 1 and n not in ('0', '1', '2')]
                if sig_numbers and any(n in raw_corpus for n in sig_numbers):
                    grounded = True
                elif not sig_numbers and not ips:
                    # Pure text assertion citing a tool — compare overlap against that specific tool's output
                    tool_specific_corpus = " ".join([
                        t.get("output", "") for t in tool_outputs
                        if t.get("tool", "").lower() in matching_tool_refs
                    ]).lower()
                    claim_words = set(re.findall(r'[a-z]{4,}', claim_lower))
                    tool_words = set(re.findall(r'[a-z]{4,}', tool_specific_corpus))
                    if claim_words and len(claim_words & tool_words) / len(claim_words) >= 0.4:
                        grounded = True

            # 3. Numeric match without tool reference
            elif numbers:
                sig_numbers = [n for n in numbers if len(n) > 1 and n not in ('0', '1', '2')]
                if sig_numbers and any(n in raw_corpus for n in sig_numbers):
                    grounded = True

            # 4. Keyword overlap fallback
            if not grounded:
                claim_words = set(re.findall(r'[a-z]{4,}', claim_lower))
                corpus_words = set(re.findall(r'[a-z]{4,}', raw_corpus))
                overlap = claim_words & corpus_words
                if len(claim_words) > 0 and len(overlap) / len(claim_words) > 0.5:
                    grounded = True

            if grounded:
                verified.append(claim)
            else:
                unverified.append(claim)

        total = len(evidence)
        trust_score = len(verified) / total if total > 0 else 1.0

        return {
            "verified": verified,
            "unverified": unverified,
            "trust_score": round(trust_score, 2)
        }

    def _embed_reasoning(self, reasoning_trace: List[str]) -> List[float]:
        """
        Embed the reasoning trace text using the Gemini Embeddings API.
        Returns a vector matching EMBEDDING_DIMENSIONS (default 3072) (L1),
        or empty list on failure / if disabled.
        """
        # Default DISABLE_EMBEDDINGS to 'false' so semantic drift operates by default (M5)
        if os.getenv("DISABLE_EMBEDDINGS", "false").lower() in ("true", "1", "yes"):
            return []

        if not reasoning_trace or genai is None:
            return []

        try:
            # Concatenate reasoning steps into a single text
            trace_text = " ".join(reasoning_trace)
            if len(trace_text) < 20:
                return []  # Too short to be meaningful

            result = genai.embed_content(
                model=f"models/{EMBEDDING_MODEL}",
                content=trace_text,
                output_dimensionality=EMBEDDING_DIMENSIONS,
            )

            embedding = result.get('embedding', [])
            if embedding:
                logger.debug(f"[CardRunner] Embedded reasoning trace: {len(embedding)} dimensions")
            return embedding

        except Exception as e:
            logger.debug(f"[CardRunner] Embedding failed (skipped): {e}")
            return []
