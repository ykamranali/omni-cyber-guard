import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.compliance import ComplianceFramework
from app.models.user import User
from app.schemas.compliance import ComplianceFrameworkOut, ComplianceFrameworkUpdate

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.get("/frameworks", response_model=list[ComplianceFrameworkOut])
def list_frameworks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_COMPLIANCE)),
):
    return (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.organization_id == current_user.organization_id)
        .order_by(ComplianceFramework.name)
        .all()
    )


@router.patch("/frameworks/{framework_id}", response_model=ComplianceFrameworkOut)
def update_framework_coverage(
    framework_id: uuid.UUID,
    payload: ComplianceFrameworkUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
):
    framework = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == framework_id, ComplianceFramework.organization_id == current_user.organization_id)
        .first()
    )
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    framework.coverage_percent = max(0.0, min(100.0, payload.coverage_percent))
    db.commit()
    db.refresh(framework)
    return framework
