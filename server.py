"""
Core Defense — AI-Powered Firewall Assistant

Browser-based web interface for PAN-OS firewall diagnostics.
Run: python server.py
Open: http://localhost:8888
"""

import os
import json
import logging
import asyncio
import queue
import threading
from pathlib import Path

# Load .env before anything else
from dotenv import load_dotenv
env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

import uvicorn
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("core-defense")

# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="Core Defense",
    description="AI-Powered Firewall Assistant",
    version="1.0.0",
)

# Add Auth Middleware
from core.safety.auth import AuthMiddleware
app.add_middleware(AuthMiddleware)

# =============================================================================
# Card Engine — SSE Broadcast Hub
# =============================================================================

# Thread-safe queue for broadcasting new card results to all connected SSE clients
_card_event_queues: list = []  # List of queue.Queue — one per SSE client
_card_event_lock = threading.Lock()


def broadcast_card_event(card_result: dict):
    """Push a new card result to all connected SSE clients."""
    with _card_event_lock:
        dead_queues = []
        for q in _card_event_queues:
            try:
                q.put_nowait(card_result)
            except Exception:
                dead_queues.append(q)
        for dq in dead_queues:
            _card_event_queues.remove(dq)

# Lazy-loaded brain instance
_brain = None

def get_brain():
    """Lazy-load CoreBrain on first use."""
    global _brain
    if _brain is None:
        logger.info("[SERVER] Initializing Core Defense engine...")
        from core.brain import CoreBrain
        _brain = CoreBrain()
        logger.info("[SERVER] Core Defense engine ready.")
    return _brain


# =============================================================================
# API Routes
# =============================================================================

@app.get("/api/health")
async def health_check():
    """Check if the system is configured and the firewall is reachable."""
    status = {
        "configured": False,
        "gemini_key": False,
        "panos_key": False,
        "firewall_reachable": False,
        "firewall_ip": None,
    }
    
    # Check for Gemini API key
    gemini_key = os.getenv("GEMINI_API_KEY", "")
    if gemini_key and gemini_key != "your-gemini-api-key-here":
        status["gemini_key"] = True
    
    # Check for PAN-OS API key
    panos_key = os.getenv("PANOS_API_KEY", "")
    if panos_key and panos_key != "your-panos-api-key-here":
        status["panos_key"] = True
    
    # Check firewall IP
    fw_ip = os.getenv("PANOS_HOSTNAME", "")
    if fw_ip and fw_ip != "192.168.1.254":
        status["firewall_ip"] = fw_ip
    elif fw_ip:
        status["firewall_ip"] = fw_ip  # Use default if set
    
    # Check firewall connectivity (quick TCP check)
    if status["panos_key"] and status["firewall_ip"]:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((status["firewall_ip"], 443))
            sock.close()
            status["firewall_reachable"] = (result == 0)
        except Exception:
            status["firewall_reachable"] = False
    
    status["configured"] = status["gemini_key"] and status["panos_key"]
    
    return JSONResponse(content=status)


@app.post("/api/chat")
async def chat(request: Request):
    """
    Send a message to the Core Defense agent and get a response.
    Streams the response via Server-Sent Events (SSE).
    """
    body = await request.json()
    user_message = body.get("message", "").strip()
    
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
            
            # Thread-safe status callback — brain calls this during investigation
            def status_callback(msg: str):
                status_queue.put(msg)
            
            # Send initial status
            yield f"data: {json.dumps({'type': 'status', 'content': 'Investigating...'})}\n\n"
            
            # Run investigation in background thread
            loop = asyncio.get_running_loop()
            result_future = loop.run_in_executor(
                None,
                lambda: brain.investigate(
                    user_message,
                    user_id="web-user",
                    status_callback=status_callback
                )
            )
            
            # Poll for status updates while investigation runs
            while not result_future.done():
                await asyncio.sleep(0.3)
                # Drain all queued status messages
                while not status_queue.empty():
                    try:
                        msg = status_queue.get_nowait()
                        yield f"data: {json.dumps({'type': 'status', 'content': msg})}\n\n"
                    except queue.Empty:
                        break
            
            # Final drain for any messages pushed right before completion
            while not status_queue.empty():
                try:
                    msg = status_queue.get_nowait()
                    yield f"data: {json.dumps({'type': 'status', 'content': msg})}\n\n"
                except queue.Empty:
                    break
            
            result = await result_future
            
            # Send the final result
            yield f"data: {json.dumps({'type': 'response', 'content': result})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
            
        except Exception as e:
            logger.error(f"[CHAT] Investigation error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
    
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
async def range_simulate(request: Request):
    """
    Dedicated endpoint for the Range Simulation tab.
    Passes target_mode="range" to CoreBrain to force JSON Mermaid output.
    """
    body = await request.json()
    user_message = body.get("message", "").strip()
    
    if not user_message:
        return JSONResponse(
            content={"error": "Empty message"},
            status_code=400
        )
    
    async def generate():
        try:
            brain = get_brain()
            status_queue = queue.Queue()
            
            def status_callback(msg: str):
                status_queue.put(msg)
            
            yield f"data: {json.dumps({'type': 'status', 'content': 'Initializing Simulation...'})}\n\n"
            
            # Step 1: Deterministically map the network
            yield f"data: {json.dumps({'type': 'status', 'content': 'Cartographer mapping physical network...'})}\n\n"
            from core.panos.cartographer import Cartographer
            cartographer = Cartographer()
            base_graph_json = cartographer.build_graph()
            
            loop = asyncio.get_running_loop()
            result_future = loop.run_in_executor(
                None,
                lambda: brain.investigate(
                    user_message,
                    user_id="web-user",
                    status_callback=status_callback,
                    target_mode="range",
                    base_graph_json=base_graph_json
                )
            )
            
            import time
            last_heartbeat = time.time()
            
            while not result_future.done():
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
                
                # SSE Heartbeat: if the model is thinking for >5 seconds without sending a status,
                # we send an empty SSE comment to keep the connection alive.
                if not sent_status and time.time() - last_heartbeat > 5.0:
                    yield f": heartbeat\n\n"
                    last_heartbeat = time.time()
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
            logger.error(f"[RANGE] Simulation error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
    
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
async def setup(request: Request):
    """
    Dynamic setup wizard handler.
    Configures either local .env variables or Vault connection details.
    Generates and returns the GUI passphrase.
    """
    body = await request.json()
    backend_type = body.get("backend_type", "dotenv")
    fw_ip = body.get("firewall_ip", "").strip()
    
    if not fw_ip:
        return JSONResponse(status_code=400, content={"success": False, "error": "Firewall IP is required."})
        
    keys_to_set = {
        "PANOS_HOSTNAME": fw_ip,
        "SECRETS_BACKEND": backend_type
    }
    
    if backend_type == "dotenv":
        panos_key = body.get("panos_key", "").strip()
        gemini_key = body.get("gemini_key", "").strip()
        if not all([panos_key, gemini_key]):
            return JSONResponse(status_code=400, content={"success": False, "error": "API keys are required for local setup."})
        keys_to_set["PANOS_API_KEY_FW_HQ"] = panos_key
        keys_to_set["GEMINI_API_KEY"] = gemini_key
        
    elif backend_type == "vault":
        vault_addr = body.get("vault_addr", "").strip()
        vault_role = body.get("vault_role", "").strip()
        vault_secret = body.get("vault_secret", "").strip()
        if not all([vault_addr, vault_role, vault_secret]):
            return JSONResponse(status_code=400, content={"success": False, "error": "Vault details are required."})
        keys_to_set["VAULT_ADDR"] = vault_addr
        keys_to_set["VAULT_ROLE_ID"] = vault_role
        keys_to_set["VAULT_SECRET_ID"] = vault_secret
    else:
        return JSONResponse(status_code=400, content={"success": False, "error": "Unknown backend type."})
        
    try:
        env_path = Path(__file__).parent / ".env"
        env_lines = []
        if env_path.exists():
            with open(env_path, "r") as f:
                env_lines = f.readlines()
                
        # Generate API_ACCESS_KEY if not exists
        import secrets
        api_access_key = os.getenv("API_ACCESS_KEY")
        if not api_access_key:
            for line in env_lines:
                if line.startswith("API_ACCESS_KEY="):
                    api_access_key = line.split("=")[1].strip()
                    break
        
        if not api_access_key:
            api_access_key = secrets.token_hex(16)
            
        keys_to_set["API_ACCESS_KEY"] = api_access_key
        
        updated_keys = set()
        new_lines = []
        for line in env_lines:
            key = line.split("=")[0].strip() if "=" in line else ""
            if key in keys_to_set:
                new_lines.append(f"{key}={keys_to_set[key]}\n")
                updated_keys.add(key)
            else:
                new_lines.append(line)
                
        for key, value in keys_to_set.items():
            if key not in updated_keys:
                new_lines.append(f"{key}={value}\n")
                
        with open(env_path, "w") as f:
            f.writelines(new_lines)
            
        # Update OS environ
        for k, v in keys_to_set.items():
            os.environ[k] = v
            
        # Reset brain so it picks up new credentials
        global _brain
        _brain = None
        
        return JSONResponse(content={
            "success": True,
            "passphrase": api_access_key
        })
    except Exception as e:
        logger.error(f"[SETUP] Failed: {e}")
        return JSONResponse(status_code=500, content={"success": False, "error": str(e)})


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
            logger.error(f"[BRIEFING] Error: {e}")
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

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
        
        with open(devices_path, "r") as f:
            data = yaml.safe_load(f)
        
        return JSONResponse(content=data or {"firewalls": {}})
    except Exception as e:
        return JSONResponse(
            content={"error": str(e)},
            status_code=500
        )


# =============================================================================
# Card Engine API Routes
# =============================================================================

@app.get("/api/cards")
async def list_cards(severity: str = None, status: str = "pending", limit: int = 50):
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
        logger.error(f"[CARDS] List error: {e}")
        return JSONResponse(content={"cards": [], "counts": {"critical": 0, "caution": 0, "normal": 0}, "error": str(e)})


# ── Fixed-path routes MUST come before parameterized {result_id} routes ──

@app.get("/api/cards/schedule")
async def get_schedule():
    """View current card execution schedule."""
    try:
        from core.engine.card_scheduler import CardScheduler
        scheduler = CardScheduler.get_instance()
        return JSONResponse(content={"schedule": scheduler.get_schedule_status()})
    except Exception as e:
        return JSONResponse(content={"schedule": [], "error": str(e)})


@app.post("/api/cards/schedule")
async def update_schedule(request: Request):
    """Enable/disable specific cards."""
    try:
        body = await request.json()
        card_key = body.get("card_key")
        enabled = body.get("enabled", True)

        from core.engine.card_scheduler import CardScheduler
        scheduler = CardScheduler.get_instance()

        if enabled:
            scheduler.enable_card(card_key)
        else:
            scheduler.disable_card(card_key)

        return JSONResponse(content={"success": True, "card_key": card_key, "enabled": enabled})
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)


@app.get("/api/cards/stream")
async def card_stream():
    """SSE stream for real-time card delivery."""
    async def generate():
        q = queue.Queue()
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
                        heartbeat_counter = 0  # Reset after real data
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
        return JSONResponse(content={"error": str(e)}, status_code=500)


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
        return JSONResponse(content={"error": str(e)}, status_code=500)


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
                # Expose the confidence margin metric derived from logprobs analysis.
            })
        return JSONResponse(content={"error": "Card not found"}, status_code=404)
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


@app.get("/api/drift/timeline")
async def get_drift_timeline(card_id: str = None, limit: int = 50):
    """Get semantic drift timeline scores over time."""
    try:
        from core.engine.baseline import BaselineEngine
        engine = BaselineEngine.get_instance()
        # Direct DB query for timeline visualization
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
                # We do not send the 768 float array back to the UI, 
                # just the existence of the reading for timeline plotting
                "has_embedding": True 
            })
            
        return JSONResponse(content={"timeline": timeline})
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


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
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)


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
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)


@app.post("/api/cards/{result_id}/mute")
async def mute_card(result_id: str, request: Request):
    """Mute a card type for N hours."""
    try:
        body = await request.json()
        hours = body.get("hours", 24)

        from core.engine.card_store import CardStore
        store = CardStore.get_instance()
        card = store.get_by_id(result_id)
        if not card:
            return JSONResponse(content={"success": False, "error": "Card not found"}, status_code=404)

        store.mute(card["card_key"], hours=hours)
        store.deny(result_id)  # Also dismiss the current card
        return JSONResponse(content={"success": True, "muted_hours": hours})
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)


# =============================================================================
# One-Shot Card Execution (Manual Testing)
# =============================================================================

@app.post("/api/cards/run")
async def run_card_once(request: Request):
    """
    Execute a single card by key and return the full result immediately.
    Use this for testing individual cards without the scheduler loop.

    POST body: {"card_key": "autonomous_chain_breaker"}
    Optional:  {"card_key": "...", "device": "fw-hq"}
    """
    try:
        body = await request.json()
        card_key = body.get("card_key")
        device = body.get("device", "default")

        if not card_key:
            return JSONResponse(
                content={"success": False, "error": "card_key is required"},
                status_code=400
            )

        from core.engine.card_runner import CardRunner
        runner = CardRunner()
        cards = runner.load_cards()

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

        # Run in thread executor to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, runner.execute, card_key, device)

        if result:
            # Broadcast via SSE if subscribers exist
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
        logger.error(f"[SERVER] One-shot card run failed: {e}")
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)


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
        return JSONResponse(content={"error": str(e)}, status_code=500)


# =============================================================================
# Card Engine Startup
# =============================================================================

@app.on_event("startup")
async def start_card_engine():
    """Launch the card scheduler daemon as a background task."""
    try:
        from core.engine.card_scheduler import CardScheduler
        scheduler = CardScheduler.get_instance()
        scheduler.subscribe(broadcast_card_event)
        asyncio.create_task(scheduler.run())
        logger.info("[SERVER] Card engine scheduled for startup")
    except Exception as e:
        logger.warning(f"[SERVER] Card engine startup failed (non-fatal): {e}")


# =============================================================================
# Static Files (Web UI)
# =============================================================================

# Serve the web UI from /web directory
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
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8888"))
    logger.info(f"[SERVER] Starting Core Defense on http://{host}:{port}")
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )

