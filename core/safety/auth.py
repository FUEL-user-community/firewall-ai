import os
import hmac
import secrets
import logging
from pathlib import Path
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("core-defense.auth")

__all__ = ["AuthMiddleware"]

_ENV_FILE = Path(__file__).resolve().parent.parent.parent / ".env"


class AuthMiddleware(BaseHTTPMiddleware):
    """
    API Key authentication middleware for FastAPI with constant-time verification
    and guaranteed persistence of generated bootstrap keys (H2, H3).
    """

    async def dispatch(self, request: Request, call_next):
        # Exclude static files, health check, and setup endpoints
        if request.url.path.startswith("/api/") and not request.url.path.startswith(("/api/health", "/api/setup")):
            api_key = os.getenv("API_ACCESS_KEY")

            # Bootstrap: generate and persist key if missing on first run (H2)
            if not api_key:
                api_key = secrets.token_hex(16)
                os.environ["API_ACCESS_KEY"] = api_key
                try:
                    from dotenv import set_key
                    if not _ENV_FILE.exists():
                        _ENV_FILE.touch(exist_ok=True)
                    set_key(str(_ENV_FILE), "API_ACCESS_KEY", api_key)
                    logger.warning(
                        f"\n{'='*50}\n[SECURITY] Generated new API_ACCESS_KEY: "
                        f"{api_key[:4]}...{api_key[-4:]}\n"
                        f"Key successfully persisted to {_ENV_FILE}\n{'='*50}\n"
                    )
                except Exception as e:
                    logger.error(f"[SECURITY] Failed to persist generated API_ACCESS_KEY to .env: {e}")

            provided_key = request.headers.get("X-API-Key")
            # Fallback for SSE streams where EventSource cannot set custom headers
            if not provided_key:
                provided_key = request.query_params.get("key")

            # Constant-time comparison
            is_valid = bool(provided_key and hmac.compare_digest(provided_key, api_key))
            if not is_valid:
                # Defensive check preventing crash when request.client is None (H3)
                client_ip = request.client.host if request.client else "unknown"
                logger.warning(f"[AUTH] Unauthorized access attempt to {request.url.path} from {client_ip}")
                return JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized. Invalid or missing X-API-Key."}
                )

        return await call_next(request)
