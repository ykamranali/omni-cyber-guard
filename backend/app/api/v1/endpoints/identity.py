import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.deps import get_current_user, get_db, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.discovery import IdentityProfile

router = APIRouter()

@router.get("/")
def get_identities(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> Any:
    """
    Retrieve corporate identities discovered from IdPs.
    """
    profiles = db.scalars(
        select(IdentityProfile).where(
            IdentityProfile.organization_id == current_user.organization_id
        ).order_by(IdentityProfile.email)
    ).all()
    
    return [
        {
            "id": str(p.id),
            "email": p.email,
            "full_name": p.full_name,
            "provider": p.provider,
            "is_active": p.is_active,
            "mfa_enabled": p.mfa_enabled,
            "last_login": p.last_login,
            "privilege_level": p.privilege_level,
        }
        for p in profiles
    ]

from pydantic import BaseModel
class IdentityScanRequest(BaseModel):
    provider: str

@router.post("/scan")
def run_discovery(
    payload: IdentityScanRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    from app.tasks.discovery_tasks import discover_identity
    discover_identity.delay(payload.provider, str(current_user.organization_id))
    return {"status": "Discovery task queued"}
