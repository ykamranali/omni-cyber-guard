"""
Live notification fan-out.

Connections are grouped by organization. The key is normalised to a string at
every entry point because the two sides disagreed: `connect` was called with
the JWT's `org_id` claim (a string) and `broadcast_to_org` with
`current_user.organization_id` (a UUID object). The dictionary lookup therefore
never matched, and every "Scan initiated" notification was silently dropped
while the request that sent it returned 202.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List

from fastapi import WebSocket

logger = logging.getLogger(__name__)


def _key(organization_id: str | uuid.UUID) -> str:
    return str(organization_id)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, organization_id: str | uuid.UUID) -> None:
        key = _key(organization_id)
        await websocket.accept()
        self.active_connections.setdefault(key, []).append(websocket)
        logger.info(
            "WebSocket connected for organization %s (%d open)",
            key, len(self.active_connections[key]),
        )

    def disconnect(self, websocket: WebSocket, organization_id: str | uuid.UUID) -> None:
        key = _key(organization_id)
        connections = self.active_connections.get(key)
        if not connections:
            return
        if websocket in connections:
            connections.remove(websocket)
        if not connections:
            del self.active_connections[key]
        logger.info("WebSocket disconnected for organization %s", key)

    def connection_count(self, organization_id: str | uuid.UUID) -> int:
        """How many live connections this organization has. Used by tests and
        by the delivery report, so "notified" can mean something checkable."""
        return len(self.active_connections.get(_key(organization_id), ()))

    async def broadcast_to_org(
        self, organization_id: str | uuid.UUID, message: dict[str, Any]
    ) -> int:
        """
        Send to every connection for one organization.

        Returns the number of clients the message actually reached, so a caller
        that cares can tell "delivered to nobody" from "delivered".
        """
        key = _key(organization_id)
        delivered = 0
        for connection in list(self.active_connections.get(key, ())):
            try:
                await connection.send_json(message)
                delivered += 1
            except Exception as exc:  # noqa: BLE001 — a dead socket is expected
                logger.warning("Dropping a WebSocket that failed to receive: %s", exc)
                self.disconnect(connection, key)
        return delivered


manager = ConnectionManager()
