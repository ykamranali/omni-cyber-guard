"""
Omni Cyber Guard — Enterprise Exposure Management Platform
Powered by Omni Digital Solution

FastAPI application entrypoint. Defensive security platform only: no exploit
execution, malware delivery, credential attack, or offensive capability is
implemented or permitted anywhere in this codebase.
"""
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.rate_limit import limiter
from app.services.events import build_bridge
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

    # Subscribe to the event channel so work finishing in the Celery worker can
    # reach a browser. Without this the WebSocket carries almost nothing: the
    # connection manager lives in this process's memory and the worker has no
    # way to reach it, so every scan completion, discovery result and
    # intelligence sync was invisible until the operator navigated somewhere.
    bridge = build_bridge()
    bridge.start()
    app.state.event_bridge = bridge

    try:
        yield
    finally:
        await bridge.stop()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=f"{settings.PROJECT_NAME} — Powered by {settings.COMPANY_NAME}",
    version="0.2.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

class UnhandledErrorMiddleware(BaseHTTPMiddleware):
    """
    Turn an unhandled exception into a JSON 500 that the browser can read.

    Without this, a route that raises produces a response assembled above the
    CORS middleware, so it carries no Access-Control-Allow-Origin header. The
    browser then refuses to hand the response to the page and `fetch` rejects
    with a bare TypeError — the same rejection it gives when the server is
    unreachable. The operator sees "could not reach the API" for a backend that
    is running fine and answering every other request, and the actual 500 is
    visible only in the container logs.

    That is how a create-scan failure read as a dead API for two days.

    This is registered before the CORS middleware, which makes it the inner of
    the two: the response it produces travels back out through CORS and picks
    up the headers it needs.

    The body names an error id, not a traceback. The id is logged alongside the
    stack so a report of "error 3f2a…" can be tied to the exact failure, and
    outside production the exception class and message are included too, since
    hiding them from a developer helps nobody.
    """

    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception as exc:  # noqa: BLE001 — this is the catch-all by design
            error_id = uuid.uuid4().hex[:12]
            logger.exception(
                "unhandled error %s on %s %s", error_id, request.method, request.url.path
            )
            detail = (
                f"The server failed while handling this request (error {error_id}). "
                f"The failure is recorded in the backend log."
            )
            if not settings.is_production:
                detail += f" {type(exc).__name__}: {exc}"
            return JSONResponse(status_code=500, content={"detail": detail})


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# Added first, so it ends up innermost — inside CORS, where its response can
# still be given the headers the browser requires.
app.add_middleware(UnhandledErrorMiddleware)
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
