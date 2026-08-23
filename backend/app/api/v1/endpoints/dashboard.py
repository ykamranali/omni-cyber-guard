import datetime as datetime_module
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset, AssetStatus
from app.models.finding import Finding, Severity, FindingStatus
from app.models.compliance import ComplianceFramework
from app.models.dashboard_snapshot import DashboardSnapshot
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User
from app.schemas.asset import AssetOut
from app.schemas.dashboard import DashboardSummary, SeverityCounts, TrendPoint
from app.services.snapshots import record_snapshot_if_needed

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    org_id = current_user.organization_id

    total_assets = db.query(func.count(Asset.id)).filter(Asset.organization_id == org_id).scalar() or 0
    active_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.organization_id == org_id, Asset.status == AssetStatus.ACTIVE)
        .scalar()
        or 0
    )

    severity_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.organization_id == org_id, Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
        .all()
    )
    counts = {s.value: 0 for s in Severity}
    for sev, cnt in severity_rows:
        counts[sev.value] = cnt

    open_findings = sum(counts.values())
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    remediated_30d = (
        db.query(func.count(Finding.id))
        .filter(
            Finding.organization_id == org_id,
            Finding.status == FindingStatus.REMEDIATED,
            Finding.updated_at >= thirty_days_ago,
        )
        .scalar()
        or 0
    )

    total_findings_ever = db.query(func.count(Finding.id)).filter(Finding.organization_id == org_id).scalar() or 0
    remediated_ever = (
        db.query(func.count(Finding.id))
        .filter(Finding.organization_id == org_id, Finding.status == FindingStatus.REMEDIATED)
        .scalar()
        or 0
    )
    remediation_progress = (remediated_ever / total_findings_ever * 100) if total_findings_ever else 100.0

    weight = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0}
    risk_raw = sum(counts[k] * weight[k] for k in weight)
    risk_score = min(100.0, risk_raw)
    security_score = round(max(0.0, 100.0 - risk_score), 1)

    asset_health = round((active_assets / total_assets * 100) if total_assets else 100.0, 1)

    # Compliance figures come from the most recent assessment of each framework.
    # A framework that has never been assessed is omitted rather than shown at
    # zero — "not assessed" and "zero percent compliant" are different claims,
    # and the dashboard must not turn the first into the second.
    from app.models.compliance import ComplianceAssessment

    compliance_status: dict[str, float] = {}
    frameworks = db.query(ComplianceFramework).filter(
        ComplianceFramework.organization_id == org_id
    ).all()

    for framework in frameworks:
        latest = (
            db.query(ComplianceAssessment)
            .filter(ComplianceAssessment.framework_id == framework.id)
            .order_by(ComplianceAssessment.started_at.desc())
            .first()
        )
        if latest is not None and latest.compliance_percent is not None:
            compliance_status[framework.name] = latest.compliance_percent

    record_snapshot_if_needed(db, org_id, security_score, round(risk_score, 1), open_findings)

    # Coverage, so a zero finding count can be read correctly. Zero findings
    # after ten scans and zero findings after no scans are entirely different
    # statements, and the dashboard previously showed them identically.
    completed_scans = db.query(func.count(ScanJob.id)).filter(
        ScanJob.organization_id == org_id,
        ScanJob.status == ScanStatus.COMPLETED,
    ).scalar() or 0
    last_scan = db.query(func.max(ScanJob.updated_at)).filter(
        ScanJob.organization_id == org_id,
        ScanJob.status == ScanStatus.COMPLETED,
    ).scalar()

    return DashboardSummary(
        security_score=security_score,
        risk_score=round(risk_score, 1),
        findings_by_severity=SeverityCounts(**counts),
        total_assets=total_assets,
        active_assets=active_assets,
        asset_health_percent=asset_health,
        compliance_status=compliance_status,
        remediation_progress_percent=round(remediation_progress, 1),
        open_findings=open_findings,
        remediated_findings_last_30_days=remediated_30d,
        completed_scans=completed_scans,
        last_scan_at=last_scan.isoformat() if last_scan else None,
    )


@router.get("/trend", response_model=list[TrendPoint])
def dashboard_trend(
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    """Real recorded history only — no interpolated or fabricated points."""
    since = datetime_module.date.today() - timedelta(days=days)
    rows = (
        db.query(DashboardSnapshot)
        .filter(DashboardSnapshot.organization_id == current_user.organization_id, DashboardSnapshot.snapshot_date >= since)
        .order_by(DashboardSnapshot.snapshot_date.asc())
        .all()
    )
    return [
        TrendPoint(date=r.snapshot_date.isoformat(), security_score=r.security_score, risk_score=r.risk_score, open_findings=r.open_findings)
        for r in rows
    ]


@router.get("/top-risky-assets", response_model=list[AssetOut])
def top_risky_assets(
    limit: int = Query(default=5, ge=1, le=25),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    return (
        db.query(Asset)
        .filter(Asset.organization_id == current_user.organization_id, Asset.risk_score > 0)
        .order_by(Asset.risk_score.desc())
        .limit(limit)
        .all()
    )


@router.get("/geo-assets", response_model=list[AssetOut])
def geo_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    """Assets with real recorded coordinates, for the geographic distribution map."""
    return (
        db.query(Asset)
        .filter(
            Asset.organization_id == current_user.organization_id,
            Asset.latitude.isnot(None),
            Asset.longitude.isnot(None),
        )
        .all()
    )
