"""
Shared slowapi limiter.

`slowapi` was already a declared dependency and `RATE_LIMIT_PER_MINUTE` was
already in config, but neither was ever wired into the application. This module
provides the single Limiter instance the app and its routes share.

Storage: Redis, so the limit holds across API replicas.

Failure behaviour matters here. With the default configuration a Redis outage
makes every rate-limited request raise ConnectionError and return 500 — losing
Redis would take down login for everyone. The limiter is therefore configured
to fall back to in-process memory and to swallow storage errors: an outage
degrades the limit from cluster-wide to per-replica instead of denying service.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings


def _client_key(request) -> str:
    """Rate-limit on the originating client address, honouring one layer of
    proxy. Only trust X-Forwarded-For when the app is actually behind a proxy
    you control."""
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return get_remote_address(request)


limiter = Limiter(
    key_func=_client_key,
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"],
    storage_uri=settings.REDIS_URL,
    strategy="fixed-window",
    # Degrade rather than deny if the shared store is unreachable.
    in_memory_fallback_enabled=True,
    swallow_errors=True,
)
