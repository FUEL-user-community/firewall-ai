"""
Core Defense — AI-Powered Firewall Assistant

Browser-based web interface for PAN-OS firewall diagnostics.
Run: python server.py
Open: http://localhost:8888
"""

import os
import ipaddress
import json
import time
import logging
import asyncio
import queue
import threading
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional
from collections import OrderedDict

# Load .env before anything else
from dotenv import load_dotenv, set_key
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

import uvicorn
from fastapi import FastAPI, Request
import mimetypes
from fastapi.staticfiles import StaticFiles
mimetypes.add_type('application/javascript; charset=utf-8', '.js')
mimetypes.add_type('text/css; charset=utf-8', '.css')
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("core-defense")

# In-memory LRU cache for recent investigation receipts (thread-safe, max 50)
_RECENT_INVESTIGATIONS: "OrderedDict[str, dict]" = OrderedDict()
_CACHE_LOCK = threading.Lock()

# Zero-drop dual-slot connection draining state
_STREAM_LOCK = threading.Lock()
_ACTIVE_STREAMS: int = 0
_DRAINING: bool = False


def _persist_traces_enabled() -> bool:
    return os.getenv("NEO_PERSIST_TRACES", "0").strip() in ("1", "true", "yes")


def _cache_investigation(trace_id: str, query: str, verdict: str, receipts: list) -> None:
    with _CACHE_LOCK:
        if len(_RECENT_INVESTIGATIONS) >= 50:
            _RECENT_INVESTIGATIONS.popitem(last=False)
        _RECENT_INVESTIGATIONS[trace_id] = {
            "trace_id": trace_id,
            "query": query,
            "verdict": verdict,
            "receipts": receipts,
            "timestamp": time.time(),
        }
    if _persist_traces_enabled():
        try:
            from core.forge.state_store import get_shared_store
            get_shared_store().save_investigation(trace_id, query, verdict, receipts)
        except Exception as e:
            logger.debug(f"[CACHE] SharedStateStore save skipped: {e}")


def _lookup_investigation(trace_id: str) -> tuple[str, Optional[dict]]:
    clean_id = (trace_id or "").strip()
    with _CACHE_LOCK:
        if (not clean_id or clean_id == "latest") and _RECENT_INVESTIGATIONS:
            clean_id = next(reversed(_RECENT_INVESTIGATIONS))
        cached = _RECENT_INVESTIGATIONS.get(clean_id)
    if cached:
        return clean_id, cached
    if _persist_traces_enabled():
        try:
            from core.forge.state_store import get_shared_store
            persisted = get_shared_store().get_investigation(clean_id or "latest")
            if persisted:
                return persisted["trace_id"], persisted
        except Exception as e:
            logger.debug(f"[CACHE] SharedStateStore lookup skipped: {e}")
    return clean_id, None


def _is_direct_loopback(request: Request) -> bool:
    if request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip"):
        return False
    if not request.client or not request.client.host:
        return False
    raw_host = request.client.host
    if raw_host in ("testclient", "localhost"):
        return True
    try:
        ip = ipaddress.ip_address(raw_host)
        if ip.is_loopback:
            return True
        if hasattr(ip, "ipv4_mapped") and ip.ipv4_mapped and ip.ipv4_mapped.is_loopback:
            return True
    except ValueError:
        pass
    return False


def _verify_stem_request(request: Request) -> bool:
    import hmac as _hmac
    if not _is_direct_loopback(request):
        return False
    expected = os.getenv("NEO_STEM_TOKEN", "").strip()
    provided = (request.headers.get("X-Stem-Token") or "").strip()
    if not expected or not provided:
        return False
    return _hmac.compare_digest(provided, expected)


def _has_configured_fleet_devices() -> bool:
    try:
        import yaml
        dev_path = Path(__file__).parent / "config" / "devices.yaml"
        if dev_path.is_file():
            data = yaml.safe_load(dev_path.read_text(encoding="utf-8")) or {}
            firewalls = data.get("firewalls") or {}
            return bool(firewalls)
    except Exception:
        pass
    return False


# =============================================================================
# Pydantic Request Models
# =============================================================================

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Investigation query or message")
    device: Optional[str] = Field("default", description="Target firewall device alias from devices.yaml")
    mode: Optional[str] = Field("default", description="Execution mode: 'default', 'investigate', 'diagnostic', or 'advisory'")

class ExportDocRequest(BaseModel):
    trace_id: str = Field(..., min_length=1, description="Trace ID of the investigation to export")
    folder_id: Optional[str] = Field(None, description="Optional Google Drive destination folder ID")

class RangeSimulateRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Attack scenario or simulation prompt")
    device: str = Field("default", description="Target firewall device alias from devices.yaml")

class HitlDecisionRequest(BaseModel):
    request_id: str = Field(..., min_length=1, description="Approval request ID to decide")
    approved: bool = Field(..., description="Whether the operator approves or rejects")
    reason: Optional[str] = Field("", description="Optional justification for the decision")
    approver_id: Optional[str] = Field("operator", description="Operator identity")

class SetupRequest(BaseModel):
    backend_type: Optional[str] = Field("dotenv", description="Secrets backend: 'dotenv' or 'vault'")
    backend: Optional[str] = None
    firewall_ip: Optional[str] = Field(None, description="Target firewall hostname or IP")
    panos_hostname: Optional[str] = None
    panos_key: Optional[str] = Field(None, description="PAN-OS API Key")
    panos_api_key: Optional[str] = None
    gemini_key: Optional[str] = Field(None, description="Gemini API Key")
    gemini_api_key: Optional[str] = None
    vault_addr: Optional[str] = Field(None, description="Vault address")
    vault_url: Optional[str] = None
    vault_role: Optional[str] = Field(None, description="Vault Role ID")
    vault_role_id: Optional[str] = None
    vault_secret: Optional[str] = Field(None, description="Vault Secret ID")
    vault_secret_id: Optional[str] = None

# Lazy-loaded brain instance with thread lock
_brain = None
_brain_lock = threading.Lock()

def get_brain():
    """Lazy-load CoreBrain on first use (thread-safe)."""
    global _brain
    if _brain is None:
        with _brain_lock:
            if _brain is None:
                logger.info("[SERVER] Initializing Core Defense engine...")
                from core.brain import CoreBrain
                _brain = CoreBrain()
                logger.info("[SERVER] Core Defense engine ready.")
    return _brain


# =============================================================================
# Application Lifespan
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application background services during startup and shutdown."""
    # Pre-flight diagnostic check and initialization banner
    try:
        from core.utils.startup_validator import run_preflight_check
        _, diag = run_preflight_check(quiet=False)
        app.state.diagnostic_matrix = diag
    except Exception as e:
        logger.warning(f"[SERVER] Pre-flight diagnostic non-fatal exception: {e}")
        app.state.diagnostic_matrix = {}

    app.state.slot_id = os.getenv("NEO_SLOT_ID", "STANDALONE")
    if app.state.slot_id != "STANDALONE":
        # Eagerly validate CoreBrain & prompt integrity before /readyz reports 200 to Stem
        get_brain()
        try:
            from core.forge.state_store import get_shared_store
            pending_autopsy = get_shared_store().get_kv("pending_autopsy")
            if pending_autopsy:
                app.state.last_autopsy = pending_autopsy
                logger.warning(
                    f"[AWAKEN] Slot {app.state.slot_id} awakened after sibling rollback: "
                    f"{str(pending_autopsy)[:240]}"
                )
        except Exception as ae:
            logger.debug(f"[AWAKEN] Autopsy check skipped: {ae}")

    logger.info(f"[SERVER] Engine initialized in on-demand diagnostic mode (slot={app.state.slot_id}).")
    yield
    logger.info("[SERVER] Engine shutdown complete.")


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="Core Defense",
    description="AI-Powered Firewall Assistant",
    version="1.0.0",
    lifespan=lifespan,
)

# Add Auth Middleware
from core.safety.auth import AuthMiddleware
app.add_middleware(AuthMiddleware)


# =============================================================================
# API Routes
# =============================================================================

@app.get("/healthz")
async def liveness_probe():
    """Kubernetes liveness probe: returns 200 if the server process is alive."""
    return JSONResponse(content={"status": "alive"})


@app.get("/readyz")
async def readiness_probe():
    """Kubernetes & Stem supervisor readiness probe."""
    diag = getattr(app.state, "diagnostic_matrix", None)
    if not diag:
        from core.utils.startup_validator import get_diagnostic_matrix
        diag = get_diagnostic_matrix()

    with _STREAM_LOCK:
        is_draining = _DRAINING
        active_streams = _ACTIVE_STREAMS

    payload = {
        "status": "draining" if is_draining else "ready",
        "slot": os.getenv("NEO_SLOT_ID", "STANDALONE"),
        "active_streams": active_streams,
        "mode": diag.get("mode", "LIVE_CONNECTED"),
        "gemini_authenticated": diag.get("gemini_authenticated", False),
        "tools_loaded": diag.get("tool_count", 0),
        "fleet": {
            name: {
                "ip": p.get("ip"),
                "status": p.get("status"),
                "latency_ms": p.get("latency_ms"),
            }
            for name, p in diag.get("fleet", {}).items()
        },
    }
    return JSONResponse(status_code=503 if is_draining else 200, content=payload)


@app.get("/internal/status")
async def internal_slot_status(request: Request):
    """Loopback + X-Stem-Token supervisor telemetry endpoint."""
    if not _verify_stem_request(request):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    with _STREAM_LOCK:
        return JSONResponse(
            content={
                "slot": os.getenv("NEO_SLOT_ID", "STANDALONE"),
                "draining": _DRAINING,
                "active_streams": _ACTIVE_STREAMS,
                "probation_shadow": os.getenv("NEO_PROBATION_SHADOW", "0") == "1",
            }
        )


@app.post("/internal/drain")
async def internal_slot_drain(request: Request):
    """Transition slot into graceful SSE drain mode prior to Stem termination."""
    global _DRAINING
    if not _verify_stem_request(request):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    with _STREAM_LOCK:
        _DRAINING = True
        remaining = _ACTIVE_STREAMS
    logger.info(f"[DRAIN] Slot entering graceful drain ({remaining} active streams).")
    return JSONResponse(content={"draining": True, "active_streams": remaining})


@app.post("/internal/promote")
async def internal_slot_promote(request: Request):
    """Lift NEO_PROBATION_SHADOW in-place on a probation-verified slot without cold restart."""
    if not _verify_stem_request(request):
        return JSONResponse(status_code=403, content={"error": "Forbidden"})
    os.environ["NEO_PROBATION_SHADOW"] = "0"
    slot_id = os.getenv("NEO_SLOT_ID", "STANDALONE")
    logger.info(f"[PROMOTE] Slot {slot_id} promoted in-place from probation shadow to active sovereign.")
    return JSONResponse(
        content={
            "promoted": True,
            "slot": slot_id,
            "probation_shadow": False,
        }
    )


@app.get("/api/health")
async def health_check(request: Request):
    """Check if the system is configured and the firewall is reachable."""
    diag = getattr(app.state, "diagnostic_matrix", None)
    if not diag:
        from core.utils.startup_validator import get_diagnostic_matrix
        diag = get_diagnostic_matrix()

    status = {
        "configured": False,
        "gemini_key": False,
        "panos_key": False,
        "firewall_reachable": False,
        "firewall_ip": None,
        "mode": diag.get("mode", "LIVE_CONNECTED"),
        "fleet": diag.get("fleet", {}),
    }

    # Check for Gemini API key
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    if gemini_key and gemini_key != "your-gemini-api-key-here":
        status["gemini_key"] = True

    # Check for PAN-OS API key
    panos_key = os.getenv("PANOS_API_KEY", "") or os.getenv("PANOS_API_KEY_FW_HQ", "")
    if panos_key and panos_key != "your-panos-api-key-here":
        status["panos_key"] = True

    # Check firewall IP
    fw_ip = os.getenv("PANOS_HOSTNAME", "").strip()
    if fw_ip:
        status["firewall_ip"] = fw_ip
    elif diag.get("fleet"):
        for name, p in diag["fleet"].items():
            if p.get("default"):
                status["firewall_ip"] = p.get("ip")
                break

    # Check firewall connectivity
    status["firewall_reachable"] = diag.get("any_online", False)

    status["configured"] = status["gemini_key"] and status["panos_key"]

    # Hybrid Dev/Shared Access Token Gating:
    # Vends master token only if DEV_AUTO_AUTH is true, environment is non-production,
    # and the request connects directly from loopback without external proxy forwarding.
    auto_auth_enabled = (
        os.getenv("DEV_AUTO_AUTH", "true").lower() in ("true", "1", "yes") and
        os.getenv("ENVIRONMENT", "development").lower() not in ("production", "prod")
    )
    has_proxy_headers = bool(request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip"))

    is_loopback = False
    if not has_proxy_headers and request.client and request.client.host:
        raw_host = request.client.host
        if raw_host in ("testclient", "localhost"):
            is_loopback = True
        else:
            try:
                ip = ipaddress.ip_address(raw_host)
                if ip.is_loopback:
                    is_loopback = True
                elif hasattr(ip, "ipv4_mapped") and ip.ipv4_mapped and ip.ipv4_mapped.is_loopback:
                    is_loopback = True
            except ValueError:
                is_loopback = False

    if auto_auth_enabled and is_loopback:
        status["access_token"] = os.getenv("API_ACCESS_KEY", "")

    return JSONResponse(content=status)


def _create_sse_investigation_stream(
    *,
    request: Request,
    user_message: str,
    target_device: Optional[str],
    target_mode: str,
    log_tag: str,
    error_message: str,
    pre_status_messages: list[str],
) -> StreamingResponse:
    """Shared reference-counted SSE stream generator for /api/chat and /api/range/simulate."""
    async def generate():
        global _ACTIVE_STREAMS
        with _STREAM_LOCK:
            _ACTIVE_STREAMS += 1
        try:
            brain = get_brain()
            status_queue = queue.Queue()
            abort_event = threading.Event()

            def status_callback(msg: str):
                status_queue.put(msg)

            for pre_msg in pre_status_messages:
                yield f"data: {json.dumps({'type': 'status', 'content': pre_msg})}\n\n"

            if target_mode == "range":
                from core.panos.cartographer import Cartographer
                cartographer = Cartographer(target_device=target_device)
                base_graph_json = cartographer.build_graph()
            else:
                # Cartographer is now a callable tool (map_home_topology) rather than pre-dumped on every chat message
                base_graph_json = "{}"

            loop = asyncio.get_running_loop()
            result_future = loop.run_in_executor(
                None,
                lambda: brain.investigate(
                    user_message,
                    user_id="web-user",
                    status_callback=status_callback,
                    target_device=target_device,
                    target_mode=target_mode,
                    base_graph_json=base_graph_json,
                    abort_event=abort_event,
                    return_details=True,
                ),
            )

            last_heartbeat = time.time()
            try:
                while not result_future.done():
                    if await request.is_disconnected():
                        abort_event.set()
                        logger.info(f"[{log_tag}] Client disconnected -- aborted stream.")
                        break

                    await asyncio.sleep(0.3)
                    sent_status = False
                    while not status_queue.empty():
                        try:
                            msg = status_queue.get_nowait()
                            yield f"data: {json.dumps({'type': 'status', 'content': msg})}\n\n"
                            sent_status = True
                            last_heartbeat = time.time()
                        except queue.Empty:
                            break

                    if not sent_status and time.time() - last_heartbeat > 5.0:
                        yield ": heartbeat\n\n"
                        last_heartbeat = time.time()

                while not status_queue.empty():
                    try:
                        msg = status_queue.get_nowait()
                        yield f"data: {json.dumps({'type': 'status', 'content': msg})}\n\n"
                    except queue.Empty:
                        break

                if not abort_event.is_set():
                    result = await result_future
                    if isinstance(result, dict):
                        verdict = result.get("verdict", "")
                        receipts = result.get("receipts", [])
                        trace_id = result.get("trace_id", "")
                    else:
                        verdict = str(result)
                        receipts = []
                        trace_id = ""

                    if trace_id:
                        _cache_investigation(trace_id, user_message, verdict, receipts)

                    if receipts:
                        yield f"data: {json.dumps({'type': 'receipts', 'content': receipts, 'trace_id': trace_id})}\n\n"
                    yield f"data: {json.dumps({'type': 'response', 'content': verdict, 'trace_id': trace_id, 'mode': target_mode})}\n\n"
                    yield f"data: {json.dumps({'type': 'done', 'trace_id': trace_id})}\n\n"
            finally:
                abort_event.set()
        except Exception as e:
            logger.exception(f"[{log_tag}] Stream error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': error_message})}\n\n"
        finally:
            with _STREAM_LOCK:
                _ACTIVE_STREAMS = max(0, _ACTIVE_STREAMS - 1)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/chat")
async def chat(payload: ChatRequest, request: Request):
    """
    Send a message to the Core Defense agent and get a response.
    Streams the response via Server-Sent Events (SSE).
    """
    user_message = payload.message.strip()
    if not user_message:
        return JSONResponse(content={"error": "Empty message"}, status_code=400)

    target_device = (payload.device or "default").strip()
    effective_device = None if target_device in ("all", "default", "") else target_device
    target_mode = (payload.mode or "default").strip()
    pre_msgs = []

    return _create_sse_investigation_stream(
        request=request,
        user_message=user_message,
        target_device=effective_device,
        target_mode=target_mode,
        log_tag="CHAT",
        error_message="Investigation failed. Please check server logs.",
        pre_status_messages=pre_msgs,
    )


@app.post("/api/chat/reset")
async def reset_chat_session():
    """Clear the Cybersec Resident rolling session memory."""
    brain = get_brain()
    if hasattr(brain, "reset_resident_session"):
        brain.reset_resident_session()
    return JSONResponse(content={"success": True, "message": "Resident session memory cleared."})


@app.get("/api/telemetry")
async def get_telemetry(device: Optional[str] = "default"):
    """
    Returns real-time telemetry snapshot (active sessions, throughput, cps, CPU)
    for the specified firewall without running dangerous unbounded CLI dumps.
    """
    try:
        from core.panos.ops import get_telemetry_snapshot
        effective_device = None if device in ("all", "default", "", None) else device.strip()
        stats = get_telemetry_snapshot(target_device=effective_device)
        return JSONResponse(content={
            "success": True,
            "device": device or "default",
            **stats
        })
    except Exception as e:
        logger.warning(f"[TELEMETRY] Failed to capture snapshot: {e}")
        return JSONResponse(content={
            "success": False,
            "device": device or "default",
            "active_sessions": 0,
            "mgmt_cpu": 0.0,
            "data_cpu": 0.0,
            "cps": 0,
            "throughput_kbps": 0,
            "error": str(e)
        })


@app.get("/api/cartographer/base-graph")
async def get_cartographer_base_graph(device: Optional[str] = "default"):
    """
    Returns the deterministic physical base graph and operational posture
    compiled directly from the target firewall by Cartographer.
    """
    try:
        from core.panos.cartographer import Cartographer
        target_dev = (device or "default").strip()
        effective_dev = None if target_dev in ("all", "default", "") else target_dev
        cartographer = Cartographer(target_device=effective_dev)
        graph_json = cartographer.build_graph()
        return JSONResponse(content=json.loads(graph_json))
    except Exception as e:
        logger.error(f"[CARTOGRAPHER] Failed to build base graph: {e}")
        return JSONResponse(content={"nodes": [], "edges": [], "error": str(e)}, status_code=500)


@app.get("/api/investigations/{trace_id}/receipts")
async def get_investigation_receipts(trace_id: str):
    """Retrieve raw receipts for a completed investigation trace."""
    _, data = _lookup_investigation(trace_id)
    if not data:
        return JSONResponse(status_code=404, content={"error": "Investigation not found or expired"})
    return JSONResponse(content=data)


@app.post("/api/export/markdown")
async def export_incident_to_markdown(payload: ExportDocRequest):
    """Generates direct structured Markdown report for 1-click client-side download."""
    trace_id, cached = _lookup_investigation(payload.trace_id)
    if not cached:
        return JSONResponse(status_code=404, content={"error": f"No investigation found for trace '{trace_id}'"})

    from core.integrations.google_export import export_to_markdown_report
    result = export_to_markdown_report(
        trace_id=trace_id,
        query=cached["query"],
        verdict=cached["verdict"],
        receipts=cached["receipts"]
    )
    return JSONResponse(content=result)


@app.post("/api/export/google-doc")
async def export_incident_to_doc(payload: ExportDocRequest):
    """
    Exports a cached investigation trace and its CLI execution receipts to a Google Doc,
    or returns the structured Markdown report for 1-click download.
    """
    trace_id, cached = _lookup_investigation(payload.trace_id)
    if not cached:
        return JSONResponse(status_code=404, content={"error": f"No investigation found for trace '{trace_id}'"})

    from core.integrations.google_export import export_to_google_doc
    result = export_to_google_doc(
        trace_id=trace_id,
        query=cached["query"],
        verdict=cached["verdict"],
        receipts=cached["receipts"],
        folder_id=payload.folder_id
    )
    return JSONResponse(content=result)


@app.post("/api/range/simulate")
async def range_simulate(payload: RangeSimulateRequest, request: Request):
    """
    Dedicated endpoint for the Range Simulation tab.
    Passes target_mode="range" to CoreBrain to force JSON Mermaid output.
    """
    user_message = payload.message.strip()
    if not user_message:
        return JSONResponse(content={"error": "Empty message"}, status_code=400)

    target_device = (payload.device or "default").strip()
    return _create_sse_investigation_stream(
        request=request,
        user_message=user_message,
        target_device=target_device,
        target_mode="range",
        log_tag="RANGE",
        error_message="Simulation encountered an error. Please check server logs.",
        pre_status_messages=[
            "Initializing Simulation...",
            "Cartographer mapping physical network...",
        ],
    )




@app.post("/api/setup")
async def setup(payload: SetupRequest, request: Request):
    """
    Dynamic setup wizard handler.
    Configures either local .env variables or Vault connection details.
    Generates and returns the GUI passphrase.
    """
    existing_key = os.getenv("API_ACCESS_KEY")
    # Security bootstrap guard: require valid X-API-Key if reconfiguring an already configured system
    if existing_key and (os.getenv("PANOS_HOSTNAME") or _has_configured_fleet_devices()):
        provided_key = request.headers.get("X-API-Key")
        import hmac as _hmac
        if not provided_key or not _hmac.compare_digest(provided_key, existing_key):
            client_ip = request.client.host if request.client else "unknown"
            logger.warning(f"[SETUP] Unauthorized reconfiguration attempt from {client_ip}")
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "System is already configured. Reconfiguration requires existing X-API-Key."}
            )

    backend_type = (payload.backend_type or payload.backend or "dotenv").lower()
    fw_ip = (payload.firewall_ip or payload.panos_hostname or "").strip()
    panos_key = (payload.panos_key or payload.panos_api_key or "").strip()
    gemini_key = (payload.gemini_key or payload.gemini_api_key or "").strip()
    vault_addr = (payload.vault_addr or payload.vault_url or "").strip()
    vault_role = (payload.vault_role or payload.vault_role_id or "").strip()
    vault_secret = (payload.vault_secret or payload.vault_secret_id or "").strip()
    
    if not fw_ip:
        return JSONResponse(status_code=400, content={"success": False, "error": "Firewall IP or hostname is required."})
        
    keys_to_set = {
        "PANOS_HOSTNAME": fw_ip,
        "SECRETS_BACKEND": backend_type
    }
    
    if backend_type == "dotenv":
        if not panos_key or not gemini_key:
            return JSONResponse(status_code=400, content={"success": False, "error": "Both PAN-OS and Gemini API keys are required for local setup."})
        keys_to_set["PANOS_API_KEY_FW_HQ"] = panos_key
        keys_to_set["GEMINI_API_KEY"] = gemini_key
        
    elif backend_type == "vault":
        if not all([vault_addr, vault_role, vault_secret]):
            return JSONResponse(status_code=400, content={"success": False, "error": "Vault details are required."})
        keys_to_set["VAULT_ADDR"] = vault_addr
        keys_to_set["VAULT_ROLE_ID"] = vault_role
        keys_to_set["VAULT_SECRET_ID"] = vault_secret
    else:
        return JSONResponse(status_code=400, content={"success": False, "error": f"Unknown backend type: {backend_type}"})
        
    try:
        env_path = Path(__file__).parent / ".env"
        
        # Preserve or generate API_ACCESS_KEY
        import secrets
        api_access_key = existing_key
        if not api_access_key:
            api_access_key = secrets.token_hex(16)
        keys_to_set["API_ACCESS_KEY"] = api_access_key
        
        # Persist safely using dotenv.set_key
        for k, v in keys_to_set.items():
            set_key(dotenv_path=str(env_path), key_to_set=k, value_to_set=v, quote_mode="auto")
            os.environ[k] = v
            
        # Reset brain so it picks up new credentials
        global _brain
        with _brain_lock:
            _brain = None

        try:
            from core.panos.client import PanOSClientPool
            PanOSClientPool.reset()
        except Exception as e:
            logger.debug(f"[SETUP] PanOSClientPool reset: {e}")

        try:
            from core.integrations.secrets import reset_provider
            reset_provider()
        except Exception as e:
            logger.debug(f"[SETUP] Secrets provider reset: {e}")

        return JSONResponse(content={
            "success": True,
            "passphrase": api_access_key,
            "token": api_access_key
        })
    except Exception as e:
        logger.exception(f"[SETUP] Failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": "Configuration save failed. Check server logs."})


@app.post("/api/login")
async def login(request: Request):
    """
    Validates the X-API-Key header.
    If this endpoint is reached, the AuthMiddleware has already accepted the key.
    """
    return JSONResponse(content={"success": True})






@app.get("/api/devices")
async def list_devices():
    """List configured firewalls from devices.yaml."""
    try:
        import yaml
        devices_path = Path(__file__).parent / "config" / "devices.yaml"
        if not devices_path.exists():
            return JSONResponse(content={"firewalls": {}})
        
        with open(devices_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        return JSONResponse(content=data or {"firewalls": {}})
    except Exception as e:
        logger.exception(f"[DEVICES] Error: {e}")
        return JSONResponse(
            content={"error": "Failed to load device list."},
            status_code=500
        )


@app.get("/api/hitl/pending")
async def list_pending_hitl_approvals():
    """List all pending write operation approval requests requiring operator sign-off."""
    from core.safety.hitl import get_pending_approvals
    pending = get_pending_approvals()
    return JSONResponse(
        content={
            "success": True,
            "count": len(pending),
            "pending": pending
        }
    )


@app.post("/api/hitl/decide")
async def submit_hitl_decision(payload: HitlDecisionRequest):
    """Approve or reject a pending write operation request in the interactive HITL queue."""
    from core.safety.hitl import submit_approval_decision
    success, message = submit_approval_decision(
        request_id=payload.request_id,
        approved=payload.approved,
        approver_id=payload.approver_id or "operator",
        reason=payload.reason or ""
    )
    if not success:
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": message}
        )
    return JSONResponse(
        content={
            "success": True,
            "request_id": payload.request_id,
            "approved": payload.approved,
            "message": message
        }
    )



# =============================================================================
# Static Files (Web UI)
# =============================================================================

web_dir = Path(__file__).parent / "web"
if web_dir.exists():
    app.mount("/", StaticFiles(directory=str(web_dir), html=True), name="web")
else:
    @app.get("/")
    async def no_web_ui():
        return HTMLResponse(
            "<h1>Core Defense</h1><p>Web UI not found. Create a /web directory.</p>"
        )


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Core Defense — Conversational PAN-OS Diagnostic & Telemetry Server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run pre-flight diagnostics, display banner, and exit (0=passed, 1=failed). Ideal for CI/CD.",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=os.getenv("HOST", "0.0.0.0"),
        help="Host network interface to bind the API server.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", "8888")),
        help="TCP port to listen on.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the pre-flight executive banner during startup.",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable uvicorn hot-reloading for local development.",
    )

    args = parser.parse_args()

    if args.check:
        from core.utils.startup_validator import run_preflight_check
        success, _ = run_preflight_check(quiet=False)
        sys.exit(0 if success else 1)

    logger.info(f"[SERVER] Starting Core Defense on http://{args.host}:{args.port}")
    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )




