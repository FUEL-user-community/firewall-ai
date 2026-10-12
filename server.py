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


# =============================================================================
# Pydantic Request Models
# =============================================================================

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Investigation query or message")
    device: Optional[str] = Field("default", description="Target firewall device alias from devices.yaml")

class ExportDocRequest(BaseModel):
    trace_id: str = Field(..., min_length=1, description="Trace ID of the investigation to export")
    folder_id: Optional[str] = Field(None, description="Optional Google Drive destination folder ID")

class RangeSimulateRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Attack scenario or simulation prompt")
    device: str = Field("default", description="Target firewall device alias from devices.yaml")

class SetupRequest(BaseModel):
    backend_type: str = Field("dotenv", description="Secrets backend: 'dotenv' or 'vault'")
    firewall_ip: str = Field(..., min_length=1, description="Target firewall hostname or IP")
    panos_key: Optional[str] = Field(None, description="PAN-OS API Key")
    gemini_key: Optional[str] = Field(None, description="Gemini API Key")
    vault_addr: Optional[str] = Field(None, description="Vault address")
    vault_role: Optional[str] = Field(None, description="Vault Role ID")
    vault_secret: Optional[str] = Field(None, description="Vault Secret ID")

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

    logger.info("[SERVER] Engine initialized in on-demand diagnostic mode.")
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
    """Kubernetes readiness probe: checks diagnostic engine and fleet connectivity."""
    diag = getattr(app.state, "diagnostic_matrix", None)
    if not diag:
        from core.utils.startup_validator import get_diagnostic_matrix
        diag = get_diagnostic_matrix()

    return JSONResponse(
        content={
            "status": "ready",
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


@app.post("/api/chat")
async def chat(payload: ChatRequest, request: Request):
    """
    Send a message to the Core Defense agent and get a response.
    Streams the response via Server-Sent Events (SSE).
    """
    user_message = payload.message.strip()
    if not user_message:
        return JSONResponse(
            content={"error": "Empty message"},
            status_code=400
        )
    
    target_device = (payload.device or "default").strip()
    effective_device = None if target_device in ("all", "default", "") else target_device

    async def generate():
        """Stream the investigation response with granular status updates."""
        try:
            brain = get_brain()
            status_queue = queue.Queue()
            abort_event = threading.Event()
            
            def status_callback(msg: str):
                status_queue.put(msg)
            
            yield f"data: {json.dumps({'type': 'status', 'content': 'Investigating...'})}\n\n"
            
            loop = asyncio.get_running_loop()
            result_future = loop.run_in_executor(
                None,
                lambda: brain.investigate(
                    user_message,
                    user_id="web-user",
                    status_callback=status_callback,
                    target_device=effective_device,
                    abort_event=abort_event,
                    return_details=True
                )
            )
            
            last_heartbeat = time.time()
            try:
                while not result_future.done():
                    if await request.is_disconnected():
                        abort_event.set()
                        logger.info("[CHAT] Client disconnected -- aborted investigation.")
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

                    # SSE Heartbeat: keep connection alive during model thinking pauses
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
                    yield f"data: {json.dumps({'type': 'response', 'content': verdict, 'trace_id': trace_id})}\n\n"
                    yield f"data: {json.dumps({'type': 'done', 'trace_id': trace_id})}\n\n"
            finally:
                abort_event.set()
            
        except Exception as e:
            logger.exception(f"[CHAT] Investigation error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': 'Investigation failed. Please check server logs.'})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


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


@app.get("/api/investigations/{trace_id}/receipts")
async def get_investigation_receipts(trace_id: str):
    """Retrieve raw receipts for a completed investigation trace."""
    with _CACHE_LOCK:
        data = _RECENT_INVESTIGATIONS.get(trace_id)
    if not data:
        return JSONResponse(status_code=404, content={"error": "Investigation not found or expired"})
    return JSONResponse(content=data)


@app.post("/api/export/markdown")
async def export_incident_to_markdown(payload: ExportDocRequest):
    """Generates direct structured Markdown report for 1-click client-side download."""
    trace_id = payload.trace_id.strip()
    with _CACHE_LOCK:
        cached = _RECENT_INVESTIGATIONS.get(trace_id)

    if not cached:
        return JSONResponse(status_code=404, content={"error": f"No investigation found for trace {trace_id}"})

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
    trace_id = payload.trace_id.strip()
    with _CACHE_LOCK:
        cached = _RECENT_INVESTIGATIONS.get(trace_id)

    if not cached:
        return JSONResponse(status_code=404, content={"error": f"No investigation found for trace {trace_id}"})

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
        return JSONResponse(
            content={"error": "Empty message"},
            status_code=400
        )
    
    async def generate():
        try:
            brain = get_brain()
            status_queue = queue.Queue()
            abort_event = threading.Event()
            
            def status_callback(msg: str):
                status_queue.put(msg)
            
            yield f"data: {json.dumps({'type': 'status', 'content': 'Initializing Simulation...'})}\n\n"
            yield f"data: {json.dumps({'type': 'status', 'content': 'Cartographer mapping physical network...'})}\n\n"
            from core.panos.cartographer import Cartographer
            target_device = (payload.device or "default").strip()
            cartographer = Cartographer(target_device=target_device)
            base_graph_json = cartographer.build_graph()
            
            loop = asyncio.get_running_loop()
            result_future = loop.run_in_executor(
                None,
                lambda: brain.investigate(
                    user_message,
                    user_id="web-user",
                    status_callback=status_callback,
                    target_mode="range",
                    target_device=target_device,
                    base_graph_json=base_graph_json,
                    abort_event=abort_event
                )
            )
            
            last_heartbeat = time.time()
            try:
                while not result_future.done():
                    if await request.is_disconnected():
                        abort_event.set()
                        logger.info("[RANGE] Client disconnected -- aborted simulation.")
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
                    
                    # SSE Heartbeat: keep connection alive during model thinking pauses
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
                    yield f"data: {json.dumps({'type': 'response', 'content': verdict, 'trace_id': trace_id})}\n\n"
                    yield f"data: {json.dumps({'type': 'done', 'trace_id': trace_id})}\n\n"
            finally:
                abort_event.set()
            
        except Exception as e:
            logger.exception(f"[RANGE] Simulation error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': 'Simulation encountered an error. Please check server logs.'})}\n\n"
    
    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
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
    if existing_key:
        provided_key = request.headers.get("X-API-Key")
        import hmac as _hmac
        if not provided_key or not _hmac.compare_digest(provided_key, existing_key):
            client_ip = request.client.host if request.client else "unknown"
            logger.warning(f"[SETUP] Unauthorized reconfiguration attempt from {client_ip}")
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": "System is already configured. Reconfiguration requires existing X-API-Key."}
            )

    backend_type = payload.backend_type.lower()
    fw_ip = payload.firewall_ip.strip()
    
    if not fw_ip:
        return JSONResponse(status_code=400, content={"success": False, "error": "Firewall IP is required."})
        
    keys_to_set = {
        "PANOS_HOSTNAME": fw_ip,
        "SECRETS_BACKEND": backend_type
    }
    
    if backend_type == "dotenv":
        if not payload.panos_key or not payload.gemini_key:
            return JSONResponse(status_code=400, content={"success": False, "error": "Both PAN-OS and Gemini API keys are required for local setup."})
        keys_to_set["PANOS_API_KEY_FW_HQ"] = payload.panos_key.strip()
        keys_to_set["GEMINI_API_KEY"] = payload.gemini_key.strip()
        
    elif backend_type == "vault":
        if not all([payload.vault_addr, payload.vault_role, payload.vault_secret]):
            return JSONResponse(status_code=400, content={"success": False, "error": "Vault details are required."})
        keys_to_set["VAULT_ADDR"] = payload.vault_addr.strip()
        keys_to_set["VAULT_ROLE_ID"] = payload.vault_role.strip()
        keys_to_set["VAULT_SECRET_ID"] = payload.vault_secret.strip()
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
            "passphrase": api_access_key
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




