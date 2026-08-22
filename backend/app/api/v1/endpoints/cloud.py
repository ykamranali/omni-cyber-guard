import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.deps import get_current_user, get_db, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.discovery import CloudResource

router = APIRouter()

@router.get("/")
def get_cloud_resources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> Any:
    """
    Retrieve cloud resources discovered from CSPM.
    """
    resources = db.scalars(
        select(CloudResource).where(
            CloudResource.organization_id == current_user.organization_id
        ).order_by(CloudResource.provider, CloudResource.name)
    ).all()
    
    return [
        {
            "id": str(r.id),
            "provider": r.provider,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "name": r.name,
            "region": r.region,
            "status": r.status,
            "compliance_status": r.compliance_status,
        }
        for r in resources
    ]

from pydantic import BaseModel
class CloudScanRequest(BaseModel):
    provider: str

@router.post("/scan")
def run_discovery(
    payload: CloudScanRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    from app.tasks.discovery_tasks import discover_cloud_assets
    discover_cloud_assets.delay(payload.provider, str(current_user.organization_id))
    return {"status": "Discovery task queued"}
