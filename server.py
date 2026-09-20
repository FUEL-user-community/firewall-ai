"""
Core Defense — AI-Powered Firewall Assistant

Browser-based web interface for PAN-OS firewall diagnostics.
Run: python server.py
Open: http://localhost:8888
"""

import os
import json
import time
import logging
import asyncio
import queue
import threading
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any

# Load .env before anything else
from dotenv import load_dotenv, set_key
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("core-defense")

# =============================================================================
# Pydantic Request Models
# =============================================================================

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="Investigation query or message")

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

class CardScheduleUpdateRequest(BaseModel):
    card_key: str = Field(..., min_length=1, description="Key of the card to update")
    enabled: bool = Field(True, description="Enable or disable the card")

class CardMuteRequest(BaseModel):
    hours: int = Field(24, ge=1, le=720, description="Hours to mute this card type")

class CardRunRequest(BaseModel):
    card_key: str = Field(..., min_length=1, description="Key of the card to run")
    device: str = Field("default", description="Device name from devices.yaml")


# =============================================================================
# Card Engine — SSE Broadcast Hub
# =============================================================================

_card_event_queues: list = []  # List of queue.Queue — one per SSE client
_card_event_lock = threading.Lock()


def broadcast_card_event(card_result: dict):
    """Push a new card result to all connected SSE clients."""
    with _card_event_lock:
        dead_queues = []
        for q in _card_event_queues:
            try:
                q.put_nowait(card_result)
            except queue.Full:
                pass
            except Exception:
                dead_queues.append(q)
        for dq in dead_queues:
            if dq in _card_event_queues:
                _card_event_queues.remove(dq)

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

    scheduler_task = None
    try:
        from core.engine.card_scheduler import CardScheduler
        scheduler = CardScheduler.get_instance()
        scheduler.subscribe(broadcast_card_event)
        scheduler_task = asyncio.create_task(scheduler.run())
        logger.info("[SERVER] Card engine scheduled for startup")
    except Exception as e:
        logger.warning(f"[SERVER] Card engine startup failed (non-fatal): {e}")

    yield

    # Clean shutdown of scheduler background task
    if scheduler_task and not scheduler_task.done():
        scheduler_task.cancel()
        try:
            await scheduler_task
        except asyncio.CancelledError:
            pass
        logger.info("[SERVER] Card engine background scheduler stopped.")


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
    """Kubernetes readiness probe: checks cognitive reasoning fabric and fleet posture."""
    diag = getattr(app.state, "diagnostic_matrix", None)
    if not diag:
        from core.utils.startup_validator import get_diagnostic_matrix
        diag = get_diagnostic_matrix()

    return JSONResponse(
        content={
            "status": "ready",
            "mode": diag.get("mode", "DATAPLANE_EMULATION"),
            "gemini_authenticated": diag.get("gemini_authenticated", False),
            "playbooks_loaded": diag.get("playbook_count", 0),
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
async def health_check():
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
        "mode": diag.get("mode", "DATAPLANE_EMULATION"),
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
                    abort_event=abort_event
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
                    yield f"data: {json.dumps({'type': 'response', 'content': result})}\n\n"
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
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
                    yield f"data: {json.dumps({'type': 'response', 'content': result})}\n\n"
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
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

        try:
            from core.visibility.auditor import Auditor
            Auditor.reset()
        except Exception as e:
            logger.debug(f"[SETUP] Auditor reset: {e}")
        
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


@app.post("/api/briefing")
async def briefing(request: Request):
    """
    Run a proactive morning briefing.
    Uses the deterministic health check workflow.
    """
    async def generate():
        try:
            brain = get_brain()
            status_queue = queue.Queue()
            
            def status_callback(msg: str):
                status_queue.put(msg)
            
            yield f"data: {json.dumps({'type': 'status', 'content': 'Running morning briefing...'})}\n\n"
            
            loop = asyncio.get_running_loop()
            result_future = loop.run_in_executor(
                None,
                lambda: brain.investigate(
                    "Give me a proactive morning briefing based on the firewall health.",
                    user_id="web-user",
                    status_callback=status_callback
                )
            )
            
            while not result_future.done():
                await asyncio.sleep(0.3)
                while not status_queue.empty():
                    try:
                        msg = status_queue.get_nowait()
                        yield f"data: {json.dumps({'type': 'status', 'content': msg})}\n\n"
                    except queue.Empty:
                        break
            
            while not status_queue.empty():
                try:
                    msg = status_queue.get_nowait()
                    yield f"data: {json.dumps({'type': 'status', 'content': msg})}\n\n"
                except queue.Empty:
                    break
            
            result = await result_future
            yield f"data: {json.dumps({'type': 'response', 'content': result})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
            
        except Exception as e:
            logger.exception(f"[BRIEFING] Error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': 'Morning briefing failed. Please check server logs.'})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


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
# Card Engine API Routes
# =============================================================================

@app.get("/api/cards")
async def list_cards(severity: Optional[str] = None, status: str = "pending", limit: int = 50):
    """Fetch card results from the card store."""
    try:
        from core.engine.card_store import CardStore
        store = CardStore.get_instance()

        if severity:
            cards = store.get_by_severity(severity, limit=limit)
        elif status == "all":
            cards = store.get_all(limit=limit)
        else:
            cards = store.get_pending(limit=limit)

        counts = store.get_counts()
        return JSONResponse(content={"cards": cards, "counts": counts})
    except Exception as e:
        logger.exception(f"[CARDS] List error: {e}")
        return JSONResponse(content={"cards": [], "counts": {"critical": 0, "caution": 0, "normal": 0}, "error": "Failed to load cards."}, status_code=500)


# ── Fixed-path routes MUST come before parameterized {result_id} routes ──

@app.get("/api/cards/schedule")
async def get_schedule():
    """View current card execution schedule."""
    try:
        from core.engine.card_scheduler import CardScheduler
        scheduler = CardScheduler.get_instance()
        return JSONResponse(content={"schedule": scheduler.get_schedule_status()})
    except Exception as e:
        logger.exception(f"[CARDS] Schedule error: {e}")
        return JSONResponse(content={"schedule": [], "error": "Failed to load schedule."}, status_code=500)


@app.post("/api/cards/schedule")
async def update_schedule(payload: CardScheduleUpdateRequest):
    """Enable/disable specific cards or all cards."""
    try:
        from core.engine.card_scheduler import CardScheduler
        scheduler = CardScheduler.get_instance()

        if payload.card_key == "all":
            scheduler.set_all_cards(payload.enabled)
        elif payload.enabled:
            scheduler.enable_card(payload.card_key)
        else:
            scheduler.disable_card(payload.card_key)

        return JSONResponse(content={"success": True, "card_key": payload.card_key, "enabled": payload.enabled})
    except Exception as e:
        logger.exception(f"[CARDS] Update schedule error: {e}")
        return JSONResponse(content={"success": False, "error": "Failed to update schedule."}, status_code=500)


@app.get("/api/cards/stream")
async def card_stream():
    """SSE stream for real-time card delivery."""
    async def generate():
        q = queue.Queue(maxsize=100)
        with _card_event_lock:
            _card_event_queues.append(q)
        try:
            heartbeat_counter = 0
            while True:
                await asyncio.sleep(1)
                heartbeat_counter += 1
                # Heartbeat every 30s — prevents proxy/LB idle disconnect
                if heartbeat_counter >= 30:
                    yield ": heartbeat\n\n"
                    heartbeat_counter = 0
                while not q.empty():
                    try:
                        card_data = q.get_nowait()
                        yield f"data: {json.dumps({'type': 'card', 'data': card_data})}\n\n"
                        heartbeat_counter = 0
                    except queue.Empty:
                        break
        finally:
            with _card_event_lock:
                if q in _card_event_queues:
                    _card_event_queues.remove(q)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )


@app.get("/api/cards/registry")
async def get_card_registry():
    """
    List all available card definitions from cards.yaml.
    Shows card_keys you can use with POST /api/cards/run.
    """
    try:
        from core.engine.card_runner import CardRunner
        cards = CardRunner.load_cards()

        registry = []
        for key, card in cards.items():
            registry.append({
                "card_key": key,
                "card_id": card.get("id", key),
                "name": card.get("name", key),
                "description": card.get("description", ""),
                "severity": card.get("severity", "normal"),
                "schedule": card.get("schedule", "daily"),
                "tool_chain": card.get("tool_chain") or [],
            })

        return JSONResponse(content={"cards": registry, "total": len(registry)})
    except Exception as e:
        logger.exception(f"[CARDS] Registry fetch error: {e}")
        return JSONResponse(content={"error": "Failed to load card registry."}, status_code=500)


@app.post("/api/cards/run")
async def run_card_once(payload: CardRunRequest):
    """
    Execute a single card by key and return the full result immediately.
    Use this for testing individual cards without the scheduler loop.
    """
    try:
        card_key = payload.card_key.strip()
        device = payload.device.strip()

        from core.engine.card_runner import CardRunner
        # Validate card key exists before initializing CardRunner
        cards = CardRunner.load_cards()

        if card_key not in cards:
            available = list(cards.keys())
            return JSONResponse(
                content={
                    "success": False,
                    "error": f"Card '{card_key}' not found",
                    "available_cards": available
                },
                status_code=404
            )

        runner = CardRunner()
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, runner.execute, card_key, device)

        if result:
            broadcast_card_event(result.__dict__ if hasattr(result, '__dict__') else result)
            return JSONResponse(content={
                "success": True,
                "card_id": result.card_id,
                "card_key": result.card_key,
                "severity": result.severity,
                "trust_score": result.trust_score,
                "title": result.title,
                "finding": result.finding,
                "reasoning_trace": result.reasoning_trace,
                "evidence": result.evidence,
                "metrics": result.metrics,
                "actions": result.actions,
            })
        else:
            return JSONResponse(content={
                "success": True,
                "card_key": card_key,
                "result": "not_triggered",
                "message": "Card executed but did not trigger (no alert condition met), or was deduplicated."
            })

    except Exception as e:
        logger.exception(f"[SERVER] One-shot card run failed: {e}")
        return JSONResponse(content={"success": False, "error": "Card execution failed. Check server logs."}, status_code=500)


# ── Parameterized routes AFTER fixed-path routes ──

@app.get("/api/cards/{result_id}")
async def get_card(result_id: str):
    """Get a single card result by ID."""
    try:
        from core.engine.card_store import CardStore
        store = CardStore.get_instance()
        card = store.get_by_id(result_id)
        if card:
            return JSONResponse(content=card)
        return JSONResponse(content={"error": "Card not found"}, status_code=404)
    except Exception as e:
        logger.exception(f"[CARDS] Get card error: {e}")
        return JSONResponse(content={"error": "Failed to fetch card."}, status_code=500)


@app.get("/api/cards/{result_id}/audit")
async def get_card_audit(result_id: str):
    """Get the Debate Protocol audit trace for a card."""
    try:
        from core.engine.card_store import CardStore
        store = CardStore.get_instance()
        card = store.get_by_id(result_id)
        if card:
            return JSONResponse(content=card.get("audit_result", {}))
        return JSONResponse(content={"error": "Card not found"}, status_code=404)
    except Exception as e:
        logger.exception(f"[CARDS] Get audit error: {e}")
        return JSONResponse(content={"error": "Failed to fetch audit data."}, status_code=500)


@app.get("/api/cards/{result_id}/logprobs")
async def get_card_logprobs(result_id: str):
    """Get the logprob confidence distribution for a card."""
    try:
        from core.engine.card_store import CardStore
        store = CardStore.get_instance()
        card = store.get_by_id(result_id)
        if card:
            return JSONResponse(content={
                "confidence_margin": card.get("confidence_margin"),
            })
        return JSONResponse(content={"error": "Card not found"}, status_code=404)
    except Exception as e:
        logger.exception(f"[CARDS] Get logprobs error: {e}")
        return JSONResponse(content={"error": "Failed to fetch logprob confidence."}, status_code=500)


@app.get("/api/drift/timeline")
async def get_drift_timeline(card_id: Optional[str] = None, limit: int = 50):
    """Get semantic drift timeline scores over time."""
    try:
        from core.engine.baseline import BaselineEngine
        engine = BaselineEngine.get_instance()
        conn = engine._get_conn()
        
        query = "SELECT card_id, timestamp, value FROM card_baselines WHERE metric_name = '__embedding__'"
        params = []
        if card_id:
            query += " AND card_id = ?"
            params.append(card_id)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        rows = conn.execute(query, params).fetchall()
        
        timeline = []
        for r in rows:
            timeline.append({
                "card_id": r["card_id"],
                "timestamp": r["timestamp"],
                "has_embedding": True 
            })
            
        return JSONResponse(content={"timeline": timeline})
    except Exception as e:
        logger.exception(f"[DRIFT] Timeline error: {e}")
        return JSONResponse(content={"error": "Failed to fetch drift timeline."}, status_code=500)


@app.post("/api/cards/{result_id}/approve")
async def approve_card(result_id: str):
    """Approve a card's recommended action."""
    try:
        from core.engine.card_store import CardStore
        store = CardStore.get_instance()
        success = store.approve(result_id)
        if success:
            return JSONResponse(content={"success": True, "status": "approved"})
        return JSONResponse(content={"success": False, "error": "Card not found or already actioned"}, status_code=404)
    except Exception as e:
        logger.exception(f"[CARDS] Approve error: {e}")
        return JSONResponse(content={"success": False, "error": "Failed to approve card."}, status_code=500)


@app.post("/api/cards/{result_id}/deny")
async def deny_card(result_id: str):
    """Deny/dismiss a card."""
    try:
        from core.engine.card_store import CardStore
        store = CardStore.get_instance()
        success = store.deny(result_id)
        if success:
            return JSONResponse(content={"success": True, "status": "denied"})
        return JSONResponse(content={"success": False, "error": "Card not found or already actioned"}, status_code=404)
    except Exception as e:
        logger.exception(f"[CARDS] Deny error: {e}")
        return JSONResponse(content={"success": False, "error": "Failed to deny card."}, status_code=500)


@app.post("/api/cards/{result_id}/mute")
async def mute_card(result_id: str, payload: CardMuteRequest = CardMuteRequest()):
    """Mute a card type for N hours."""
    try:
        from core.engine.card_store import CardStore
        store = CardStore.get_instance()
        card = store.get_by_id(result_id)
        if not card:
            return JSONResponse(content={"success": False, "error": "Card not found"}, status_code=404)

        store.mute(card["card_key"], hours=payload.hours)
        store.deny(result_id)  # Also dismiss the current card
        return JSONResponse(content={"success": True, "muted_hours": payload.hours})
    except Exception as e:
        logger.exception(f"[CARDS] Mute error: {e}")
        return JSONResponse(content={"success": False, "error": "Failed to mute card."}, status_code=500)


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
        description="Core Defense — Autonomous SOC & Dataplane Investigation Server",
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
