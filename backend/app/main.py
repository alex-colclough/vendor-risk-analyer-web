"""FastAPI application entry point with security configuration."""

import logging
import sys
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.routes import analysis, chat, connection, export, upload
from app.api.websocket import handlers as ws_handlers
from app.config import settings
from app.rate_limiter import limiter

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Add the compliance analyzer to path if configured
if settings.analyzer_package_path:
    sys.path.insert(0, settings.analyzer_package_path)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add comprehensive security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Basic security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

        # Permissions Policy
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # HSTS for production
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request body size for file uploads."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            if int(content_length) > settings.max_file_size_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request body too large"},
                )
        return await call_next(request)


class JSONBodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit JSON request body size to prevent memory exhaustion."""

    MAX_JSON_BODY_SIZE = 1024 * 1024  # 1MB for JSON payloads

    async def dispatch(self, request: Request, call_next):
        content_type = request.headers.get("content-type", "")
        content_length = request.headers.get("content-length")

        if "application/json" in content_type and content_length:
            if int(content_length) > self.MAX_JSON_BODY_SIZE:
                return JSONResponse(
                    status_code=413,
                    content={"error": "JSON payload too large"},
                )
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    settings.upload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    logger.info(f"Upload directory: {settings.upload_dir}")
    logger.info(f"Environment: {settings.environment}")

    # Start background cleanup task
    import asyncio
    from app.services.file_manager import file_manager

    async def cleanup_loop():
        """Periodically clean up expired sessions."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                deleted = await file_manager.cleanup_expired_sessions(max_age_hours=24)
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} expired sessions")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

    cleanup_task = asyncio.create_task(cleanup_loop())

    yield

    # Shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    logger.info("Application shutdown complete")


app = FastAPI(
    title=settings.app_name,
    description="AI-powered vendor security compliance analyzer",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

# Add rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security middleware (order matters - first added = last executed)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(JSONBodySizeLimitMiddleware)

# CORS middleware with explicit headers (not wildcard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "Accept",
        "Origin",
    ],
    expose_headers=["Content-Disposition"],
    max_age=3600,  # Cache preflight for 1 hour
)

# Include API routes
app.include_router(upload.router, prefix=settings.api_prefix, tags=["upload"])
app.include_router(analysis.router, prefix=settings.api_prefix, tags=["analysis"])
app.include_router(connection.router, prefix=settings.api_prefix, tags=["connection"])
app.include_router(export.router, prefix=settings.api_prefix, tags=["export"])
app.include_router(chat.router, prefix=settings.api_prefix, tags=["chat"])

# WebSocket routes
app.include_router(ws_handlers.router, tags=["websocket"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "1.0.0"}


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler - log details but return safe error to client."""
    # Generate error ID for tracking
    error_id = str(uuid.uuid4())[:8]

    # Log full details server-side
    logger.error(
        f"Error ID: {error_id} | Path: {request.url.path} | "
        f"Method: {request.method} | Exception: {type(exc).__name__} | "
        f"Message: {str(exc)}",
        exc_info=True,
    )

    # Return safe error to client (never expose internals in production)
    if settings.debug:
        return JSONResponse(
            status_code=500,
            content={
                "error": str(exc),
                "type": type(exc).__name__,
                "error_id": error_id,
            },
        )
    return JSONResponse(
        status_code=500,
        content={
            "error": "An internal error occurred",
            "error_id": error_id,
            "support": "Please contact support with this error ID",
        },
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
