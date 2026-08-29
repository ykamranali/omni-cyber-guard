"""
Cross-process event delivery, from the worker to the browser.

The WebSocket layer was only ever half-built. `ConnectionManager` holds its
sockets in a dictionary in memory, so only the process holding that dictionary
can send anything. Every event worth pushing — a scan finishing, hosts
discovered, intelligence synced, a packet-capture observation — happens in the
Celery worker, a different process in a different container with no route to
that dictionary. The single message the platform ever managed to send was
"Scan initiated", emitted by the API about its own request.

The frontend, meanwhile, declares handlers for eleven event types. Ten of them
could never arrive. The result was a product that looked live and was not: the
Scan Centre polled, and every other page was accurate at the moment it was
opened and static afterwards.

Redis is already the Celery broker, so it is already a dependency, already
running, and already reachable from both sides. Publishers push a JSON envelope
onto one channel; each API process subscribes and fans out to the sockets it
holds. Running several API replicas needs no coordination — each receives every
event and delivers to its own connections.

Two deliberate properties:

  * Publishing never raises. An event is a notification about work, not the
    work. A scan that finished must not be recorded as failed because Redis was
    briefly unavailable, so `publish_event` returns False and logs instead.

  * The subscriber reconnects rather than dying. If it exits, the application
    goes quietly back to being not-live, which is precisely the failure this
    module exists to end.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

#: One channel for every organization. The envelope carries the tenant, and the
#: subscriber routes on it. Per-organization channels would mean the API had to
#: subscribe and unsubscribe as sockets come and go, for no benefit: it holds
#: connections for many tenants at once and would be subscribed to most of them
#: anyway.
EVENT_CHANNEL = "ocg:events"

#: Event types the frontend knows how to act on. Publishing anything else still
#: works — the client falls back to refreshing the dashboard — but a typo in a
#: task would otherwise be invisible, so it is logged.
KNOWN_EVENT_TYPES = frozenset({
    "scan_started",
    "scan_progress",
    "scan_completed",
    "scan_failed",
    "finding_created",
    "finding_resolved",
    "threat_event",
    "remediation_updated",
    "compliance_assessed",
    "discovery_completed",
    "intel_synced",
    "info",
})

_publisher = None


def _get_publisher():
    """A lazily created synchronous Redis client for publishers."""
    global _publisher
    if _publisher is None:
        import redis

        _publisher = redis.from_url(
            settings.REDIS_URL,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=True,
        )
    return _publisher


def reset_publisher() -> None:
    """Drop the cached client. For tests, and after a configuration change."""
    global _publisher
    _publisher = None


def publish_event(
    organization_id: str | uuid.UUID,
    event_type: str,
    message: str | None = None,
    **data: Any,
) -> bool:
    """
    Announce something that happened, to whoever is watching that organization.

    Returns True if the event reached Redis. Never raises: the caller has
    already done the real work, and a notification failure must not be able to
    rewrite the record of it.
    """
    if event_type not in KNOWN_EVENT_TYPES:
        logger.warning(
            "publishing unknown event type %r; the browser will fall back to a "
            "dashboard refresh", event_type,
        )

    envelope: dict[str, Any] = {
        "type": event_type,
        "organization_id": str(organization_id),
        "at": datetime.now(timezone.utc).isoformat(),
        **data,
    }
    if message is not None:
        envelope["message"] = message

    try:
        _get_publisher().publish(EVENT_CHANNEL, json.dumps(envelope, default=str))
        return True
    except Exception as exc:  # noqa: BLE001 — broker down, timeout, anything
        logger.warning(
            "could not publish %s for organization %s: %s",
            event_type, organization_id, exc,
        )
        reset_publisher()
        return False


class EventBridge:
    """
    Subscribes to the event channel and delivers onto local WebSockets.

    One of these runs per API process, started and stopped by the application
    lifespan.
    """

    #: Reconnect backoff, seconds. Capped so a long outage does not turn into a
    #: long silence after the broker returns.
    BASE_DELAY = 1.0
    MAX_DELAY = 30.0

    def __init__(self, manager, redis_url: str | None = None) -> None:
        self._manager = manager
        self._redis_url = redis_url or settings.REDIS_URL
        self._task: asyncio.Task | None = None
        self._delivered = 0
        self._received = 0

    @property
    def stats(self) -> dict[str, int]:
        """Received from Redis, and delivered to sockets. Used by diagnostics —
        the difference between them is "nobody was watching", not an error."""
        return {"received": self._received, "delivered": self._delivered}

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._run(), name="ocg-event-bridge")
        logger.info("event bridge started, subscribing to %s", EVENT_CHANNEL)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001
            logger.exception("event bridge did not stop cleanly")
        self._task = None
        logger.info("event bridge stopped")

    async def _run(self) -> None:
        delay = self.BASE_DELAY
        while True:
            try:
                await self._consume()
                # A clean return means the subscription ended without an error,
                # which should not happen while the process is alive.
                logger.warning("event subscription ended unexpectedly; reconnecting")
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("event subscription failed (%s); reconnecting in %.0fs", exc, delay)

            await asyncio.sleep(delay)
            delay = min(delay * 2, self.MAX_DELAY)

    async def _consume(self) -> None:
        import redis.asyncio as aioredis

        client = aioredis.from_url(self._redis_url, decode_responses=True)
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        try:
            await pubsub.subscribe(EVENT_CHANNEL)
            logger.info("event bridge listening on %s", EVENT_CHANNEL)
            async for raw in pubsub.listen():
                if raw.get("type") != "message":
                    continue
                await self._dispatch(raw.get("data"))
        finally:
            await _shut(pubsub)
            await _shut(client)

    async def _dispatch(self, raw: str | bytes | None) -> None:
        if not raw:
            return
        try:
            envelope = json.loads(raw)
        except (TypeError, ValueError):
            logger.warning("discarding a malformed event payload")
            return

        organization_id = envelope.pop("organization_id", None)
        if not organization_id:
            logger.warning("discarding an event with no organization: %s", envelope.get("type"))
            return

        self._received += 1
        try:
            self._delivered += await self._manager.broadcast_to_org(organization_id, envelope)
        except Exception:  # noqa: BLE001
            logger.exception("failed to deliver %s", envelope.get("type"))


async def _shut(resource) -> None:
    """
    Close a redis-py asyncio object across versions.

    `close()` was renamed to `aclose()` in redis-py 5.0.1 and the old name now
    warns; which one exists depends on the installed version, so try the
    current name first and fall back rather than leaking the connection when
    the attribute is missing.
    """
    closer = getattr(resource, "aclose", None) or getattr(resource, "close", None)
    if closer is None:
        return
    try:
        result = closer()
        if asyncio.iscoroutine(result):
            await result
    except Exception:  # noqa: BLE001 — shutting down; nothing to salvage
        pass


def build_bridge() -> EventBridge:
    from app.services.websocket import manager

    return EventBridge(manager)
