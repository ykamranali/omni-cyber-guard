import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from sqlalchemy import func, select

from app.models.finding import (
    CLOSED_STATUSES, Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.models.asset import Asset
from app.models.user import User
from app.schemas.finding import FindingOut, FindingCreate, FindingUpdate
from app.services.audit import log_action
from app.services.risk_scoring import recompute_asset_risk_score

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(
    scan_id: str | None = None,
    asset_id: str | None = None,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    finding_class: FindingClass | None = None,
    confidence: Confidence | None = None,
    open_only: bool = False,
    search: str | None = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    query = db.query(Finding).filter(Finding.organization_id == current_user.organization_id)
    if scan_id:
        try:
            query = query.filter(Finding.scan_job_id == uuid.UUID(scan_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan_id format")
    if asset_id:
        try:
            query = query.filter(Finding.asset_id == uuid.UUID(asset_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid asset_id format")
    if severity:
        query = query.filter(Finding.severity == severity)
    if status:
        query = query.filter(Finding.status == status)
    if finding_class:
        query = query.filter(Finding.finding_class == finding_class)
    if confidence:
        query = query.filter(Finding.confidence == confidence)
    if open_only:
        query = query.filter(Finding.status.notin_(list(CLOSED_STATUSES)))
    if search:
        like = f"%{search}%"
        query = query.filter(
            (Finding.title.ilike(like)) | (Finding.cve_id.ilike(like)) | (Finding.evidence.ilike(like))
        )

    limit = max(1, min(limit, 1000))
    return (
        query.order_by(Finding.last_seen.desc())
        .offset(max(0, offset))
        .limit(limit)
        .all()
    )


@router.get("/summary")
def findings_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    """
    Counts by severity and by class, computed in the database.

    Splitting by class matters: an estate with 400 open ports and 3 matched
    CVEs is in a very different position from one with 3 open ports and 400
    CVEs, and a single "403 findings" number hides that entirely.
    """
    org_id = current_user.organization_id
    open_filter = [Finding.organization_id == org_id, Finding.status.notin_(list(CLOSED_STATUSES))]

    by_severity = dict(
        db.execute(
            select(Finding.severity, func.count(Finding.id)).where(*open_filter).group_by(Finding.severity)
        ).all()
    )
    by_class = dict(
        db.execute(
            select(Finding.finding_class, func.count(Finding.id)).where(*open_filter).group_by(Finding.finding_class)
        ).all()
    )
    by_confidence = dict(
        db.execute(
            select(Finding.confidence, func.count(Finding.id)).where(*open_filter).group_by(Finding.confidence)
        ).all()
    )
    resolved = db.execute(
        select(func.count(Finding.id)).where(
            Finding.organization_id == org_id, Finding.status == FindingStatus.REMEDIATED
        )
    ).scalar_one()

    return {
        "open_by_severity": {item.value: 0 for item in Severity} | {k.value: v for k, v in by_severity.items()},
        "open_by_class": {item.value: 0 for item in FindingClass} | {k.value: v for k, v in by_class.items()},
        "open_by_confidence": {item.value: 0 for item in Confidence} | {k.value: v for k, v in by_confidence.items()},
        "total_open": sum(by_severity.values()),
        "total_resolved": resolved,
    }


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
    # Manual findings get the same stable identity as scanner findings, so a
    # later scan that observes the same issue updates this row instead of
    # creating a second one beside it.
    from app.services.finding_identity import compute_fingerprint

    finding = Finding(
        organization_id=current_user.organization_id,
        fingerprint=compute_fingerprint(
            asset_id=payload.asset_id,
            finding_class=payload.finding_class,
            source=payload.source,
            identifier=payload.cve_id or payload.title,
        ),
        **payload.model_dump(),
    )
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
