"""
Deterministic, real risk-scoring logic — computed from an asset's actual
linked findings. No random or placeholder values.
"""
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding, Severity, FindingStatus

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 12.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 1.5,
    Severity.INFO: 0.0,
}


def compute_asset_risk_score(db: Session, asset_id) -> float:
    open_findings = (
        db.query(Finding)
        .filter(Finding.asset_id == asset_id, Finding.status == FindingStatus.OPEN)
        .all()
    )
    raw = sum(SEVERITY_WEIGHT[f.severity] for f in open_findings)
    return round(min(100.0, raw), 1)


def recompute_asset_risk_score(db: Session, asset: Asset) -> None:
    asset.risk_score = compute_asset_risk_score(db, asset.id)
    db.add(asset)
    db.commit()
