import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.finding import Finding
from app.models.asset import Asset
from app.models.user import User
from app.schemas.finding import FindingOut, FindingCreate, FindingUpdate
from app.services.audit import log_action
from app.services.risk_scoring import recompute_asset_risk_score

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(
    scan_id: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    query = db.query(Finding).filter(Finding.organization_id == current_user.organization_id)
    if scan_id:
        try:
            query = query.filter(Finding.scan_job_id == uuid.UUID(scan_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan_id format")
    return query.all()


@router.post("", response_model=FindingOut, status_code=201)
def create_finding(
    payload: FindingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == payload.asset_id, Asset.organization_id == current_user.organization_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    finding = Finding(organization_id=current_user.organization_id, **payload.model_dump())
    db.add(finding)
    db.commit()
    db.refresh(finding)
    recompute_asset_risk_score(db, asset)
    log_action(db, "create", "finding", current_user.organization_id, current_user.id, str(finding.id))
    return finding


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.organization_id == current_user.organization_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)
    db.commit()
    db.refresh(finding)

    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
    if asset:
        recompute_asset_risk_score(db, asset)

    log_action(db, "update", "finding", current_user.organization_id, current_user.id, str(finding.id))
    return finding

@router.delete("/bulk", status_code=204)
def delete_findings_bulk(
    finding_ids: list[uuid.UUID],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    findings = (
        db.query(Finding)
        .filter(Finding.id.in_(finding_ids), Finding.organization_id == current_user.organization_id)
        .all()
    )
    assets_to_recompute = set()
    for finding in findings:
        assets_to_recompute.add(finding.asset_id)
        db.delete(finding)
        log_action(db, "delete", "finding", current_user.organization_id, current_user.id, str(finding.id))
    db.commit()

    for asset_id in assets_to_recompute:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            recompute_asset_risk_score(db, asset)

@router.delete("/{finding_id}", status_code=204)
def delete_finding(
    finding_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.organization_id == current_user.organization_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    asset_id = finding.asset_id
    db.delete(finding)
    db.commit()
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset:
        recompute_asset_risk_score(db, asset)
    
    log_action(db, "delete", "finding", current_user.organization_id, current_user.id, str(finding_id))
