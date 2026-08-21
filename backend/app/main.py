"""
Omni Cyber Guard — Enterprise Exposure Management Platform
Powered by Omni Digital Solution

FastAPI application entrypoint. Defensive security platform only: no exploit
execution, malware delivery, credential attack, or offensive capability is
implemented or permitted anywhere in this codebase.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.rate_limit import limiter
from app.services.bootstrap import ensure_bootstrap_admin

logger = logging.getLogger(__name__)


def _verify_row_level_security() -> None:
    from app.db.session import SessionLocal
    from app.db.tenancy import rls_effective

    db = SessionLocal()
    try:
        effective, explanation = rls_effective(db)
    except Exception as exc:
        logger.warning("Could not verify row-level security: %s", exc)
        return
    finally:
        db.close()

    if effective:
        logger.info(explanation)
        return

    if settings.is_production:
        raise RuntimeError(
            "ENABLE_ROW_LEVEL_SECURITY is on but the policies are not actually "
            f"in force. {explanation}"
        )
    logger.warning("Row-level security is NOT in force. %s", explanation)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fails loudly rather than silently running production on shipped defaults.
    settings.assert_production_ready()

    for name in settings.insecure_defaults_in_use():
        logger.warning(
            "%s is still set to its shipped default value. This is acceptable "
            "for local development only.", name,
        )

    # Row-level security is silently inert for a superuser connection, so its
    # effectiveness is verified rather than assumed. In production an inert
    # policy set is a startup failure, not a warning.
    if settings.ENABLE_ROW_LEVEL_SECURITY:
        _verify_row_level_security()

    # Creates exactly one super admin account (from .env) if the database is
    # completely empty. No demo or sample data is ever created automatically.
    ensure_bootstrap_admin()

    # Packet capture runs in the worker container, which holds CAP_NET_RAW.
    # The API reads the events the worker recorded (see
    # app/services/threat_monitor.py).

    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=f"{settings.PROJECT_NAME} — Powered by {settings.COMPANY_NAME}",
    version="0.2.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds standard secure HTTP headers.

    The CSP applies to responses this API serves — chiefly the OpenAPI docs.
    The Next.js frontend is served by its own process and sets its own policy;
    the previous blanket `default-src 'self'` here was too strict for the docs
    UI (which loads Swagger from a CDN) and too loose to be meaningful for the
    application itself.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        if not request.url.path.startswith("/api/docs") and not request.url.path.startswith("/api/redoc"):
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/api/health", tags=["Health"])
def health_check():
    """Liveness only. Component-level checks (database, Redis, scanner
    availability) are at /api/v1/system/status."""
    return {
        "status": "ok",
        "service": settings.PROJECT_NAME,
        "powered_by": settings.COMPANY_NAME,
    }
