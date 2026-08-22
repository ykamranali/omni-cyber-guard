import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.deps import get_current_user, get_db, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.discovery import AttackSurfaceDomain

router = APIRouter()

@router.get("/")
def get_attack_surface(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> Any:
    """
    Retrieve external attack surface domains and certificates.
    """
    domains = db.scalars(
        select(AttackSurfaceDomain).where(
            AttackSurfaceDomain.organization_id == current_user.organization_id
        ).order_by(AttackSurfaceDomain.domain_name)
    ).all()
    
    return [
        {
            "id": str(d.id),
            "domain_name": d.domain_name,
            "ip_addresses": d.ip_addresses.split(",") if d.ip_addresses else [],
            "registrar": d.registrar,
            "is_active": d.is_active,
            "cert_issuer": d.cert_issuer,
            "cert_valid_from": d.cert_valid_from,
            "cert_valid_to": d.cert_valid_to,
        }
        for d in domains
    ]

from pydantic import BaseModel
class DomainScanRequest(BaseModel):
    domain: str

@router.post("/scan")
def run_discovery(
    payload: DomainScanRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    from app.tasks.discovery_tasks import discover_attack_surface
    discover_attack_surface.delay(payload.domain, str(current_user.organization_id))
    return {"status": "Discovery task queued"}
