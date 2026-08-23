"""
Live event stream.

The socket carries an organization's scan and alert notifications, so opening
one is a read of that organization's data and has to be authenticated to the
same standard as an HTTP request. It previously was not: the handler decoded
the token, took the `org_id` claim, and connected — without checking that the
token was an access token rather than a refresh token, without loading the
user, and without checking the account was still active. A refresh token, or a
token belonging to a deactivated account, opened a live feed.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.rbac import Permission
from app.core.security import decode_token
from app.db.session import get_db
from app.models.user import User
from app.services.websocket import manager

logger = logging.getLogger(__name__)

router = APIRouter()

# Matches the permission the dashboard itself requires. A socket must not be a
# way around the permission model.
REQUIRED_PERMISSION = Permission.VIEW_ASSETS

POLICY_VIOLATION = 1008


def _resolve_user(db: Session, token: str) -> User | None:
    try:
        payload = decode_token(token)
    except JWTError:
        return None
    if payload.get("type") != "access":
        return None
    subject = payload.get("sub")
    if not subject:
        return None
    try:
        user_id = uuid.UUID(str(subject))
    except ValueError:
        return None

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        return None

    if user.is_super_admin:
        return user
    held = {perm.code for role in user.roles for perm in role.permissions}
    if REQUIRED_PERMISSION.value not in held:
        return None
    return user


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(default=""),
    db: Session = Depends(get_db),
):
    if not token:
        await websocket.close(code=POLICY_VIOLATION)
        return

    user = _resolve_user(db, token)
    if user is None:
        # Deliberately undifferentiated: a client learns that it may not
        # connect, not which of the checks it failed.
        await websocket.close(code=POLICY_VIOLATION)
        return

    # The organization comes from the resolved user record, not from a claim in
    # the token, so a forged or stale `org_id` cannot select a tenant.
    organization_id = str(user.organization_id)

    await manager.connect(websocket, organization_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, organization_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("WebSocket closed unexpectedly: %s", exc)
        manager.disconnect(websocket, organization_id)
