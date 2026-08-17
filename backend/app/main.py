"""
Omni Cyber Guard — Enterprise Cybersecurity & Vulnerability Management Platform
Powered by Omni Digital Solution

FastAPI application entrypoint. Defensive security platform only: no exploit
execution, malware delivery, credential attack, or offensive capability is
implemented or permitted anywhere in this codebase.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.api.v1.router import api_router
from app.services.bootstrap import ensure_bootstrap_admin

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=f"{settings.PROJECT_NAME} — Powered by {settings.COMPANY_NAME}",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard secure HTTP headers, including a Content-Security-Policy."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


from app.services.threat_monitor import start_sniffer

@app.on_event("startup")
def on_startup() -> None:
    # Creates exactly one super admin account (from .env) if the database is
    # completely empty. No demo/sample data is ever created automatically.
    ensure_bootstrap_admin()
    
    # Start the real-time threat monitor daemon
    start_sniffer()


@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": settings.PROJECT_NAME,
        "powered_by": settings.COMPANY_NAME,
    }
