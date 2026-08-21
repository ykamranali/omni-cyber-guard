from typing import Dict, List, Any
from fastapi import WebSocket
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        # Maps organization_id to a list of active WebSockets
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, organization_id: str):
        await websocket.accept()
        if organization_id not in self.active_connections:
            self.active_connections[organization_id] = []
        self.active_connections[organization_id].append(websocket)
        logger.info(f"Client connected to org {organization_id}. Total connections for org: {len(self.active_connections[organization_id])}")

    def disconnect(self, websocket: WebSocket, organization_id: str):
        if organization_id in self.active_connections:
            if websocket in self.active_connections[organization_id]:
                self.active_connections[organization_id].remove(websocket)
            if not self.active_connections[organization_id]:
                del self.active_connections[organization_id]
        logger.info(f"Client disconnected from org {organization_id}.")

    async def broadcast_to_org(self, organization_id: str, message: dict):
        """Broadcasts a JSON message to all connected clients in a specific organization."""
        if organization_id in self.active_connections:
            # Create a copy of the list to avoid issues if connections drop during iteration
            for connection in list(self.active_connections[organization_id]):
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error sending message to websocket: {e}")
                    self.disconnect(connection, organization_id)

manager = ConnectionManager()
