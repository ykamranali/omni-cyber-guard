from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.security import decode_token
from app.services.websocket import manager
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(None),
    db: Session = Depends(get_db)
):
    if not token:
        await websocket.close(code=1008)
        return

    # Verify token
    try:
        payload = decode_token(token)
        organization_id = payload.get("org_id")
        if not organization_id:
            await websocket.close(code=1008)
            return
    except Exception as e:
        logger.error(f"WebSocket auth failed: {e}")
        await websocket.close(code=1008)
        return

    await manager.connect(websocket, organization_id)
    try:
        while True:
            # We don't expect the client to send much, but we need to keep the connection open
            # and listen for disconnects or simple ping/pongs.
            data = await websocket.receive_text()
            # if data == "ping": await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket, organization_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket, organization_id)
