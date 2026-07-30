import os
import secrets
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger("core-defense.auth")

class AuthMiddleware(BaseHTTPMiddleware):
    """
    Simple API Key authentication middleware for FastAPI.
    """
    async def dispatch(self, request: Request, call_next):
        # Exclude static files, health check, and setup
        if request.url.path.startswith("/api/") and not request.url.path.startswith(("/api/health", "/api/setup")):
            api_key = os.getenv("API_ACCESS_KEY")
            
            # Generate on first run if missing
            if not api_key:
                api_key = secrets.token_hex(16)
                os.environ["API_ACCESS_KEY"] = api_key
                logger.warning(
                    f"\n{'='*50}\n[SECURITY] Generated new API_ACCESS_KEY: "
                    f"{api_key[:4]}...{api_key[-4:]}\n"
                    f"Full key written to .env — DO NOT share.\n{'='*50}\n"
                )
                
            provided_key = request.headers.get("X-API-Key")
            # Fallback: check query param for SSE streams (EventSource can't set headers)
            # SECURITY NOTE: API key in query params is logged by proxies/CDNs.
            # This is a known trade-off for SSE (EventSource can't set headers).
            # Future: implement short-lived token exchange for SSE connections.
            if not provided_key:
                provided_key = request.query_params.get("key")
                
            import hmac as _hmac
            if not provided_key or not _hmac.compare_digest(provided_key, api_key):
                logger.warning(f"Unauthorized API access attempt to {request.url.path} from {request.client.host}")
                return JSONResponse(status_code=401, content={"error": "Unauthorized. Invalid or missing X-API-Key header."})
                
        return await call_next(request)
