import uuid
from typing import Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.deps import get_db, get_current_active_user, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.notification import Notification

router = APIRouter()


@router.get("")
def list_notifications(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    unread_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    query = db.query(Notification).filter(
        Notification.organization_id == current_user.organization_id,
        Notification.user_id == current_user.id
    )

    if unread_only:
        query = query.filter(Notification.read_at.is_(None))

    total = query.count()
    notifications = query.order_by(desc(Notification.created_at)).offset(skip).limit(limit).all()

    # Calculate global unread count for the user
    unread_count = db.query(Notification).filter(
        Notification.organization_id == current_user.organization_id,
        Notification.user_id == current_user.id,
        Notification.read_at.is_(None)
    ).count()

    return {
        "items": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "reference_link": n.reference_link,
                "created_at": n.created_at,
                "read_at": n.read_at,
            }
            for n in notifications
        ],
        "total": total,
        "unread_count": unread_count,
        "skip": skip,
        "limit": limit
    }


@router.patch("/{notification_id}/read")
def mark_notification_as_read(
    notification_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.organization_id == current_user.organization_id,
        Notification.user_id == current_user.id
    ).first()

    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    if notification.read_at is None:
        notification.read_at = datetime.now(timezone.utc)
        db.commit()

    return {"status": "ok", "read_at": notification.read_at}


@router.post("/read-all")
def mark_all_as_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    db.query(Notification).filter(
        Notification.organization_id == current_user.organization_id,
        Notification.user_id == current_user.id,
        Notification.read_at.is_(None)
    ).update({"read_at": datetime.now(timezone.utc)})
    
    db.commit()
    return {"status": "ok"}
