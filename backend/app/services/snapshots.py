"""
Records a real, single daily snapshot of an organization's computed
dashboard scores. Called opportunistically whenever the dashboard summary
is requested — at most one row is written per organization per calendar
day, so the resulting trend chart is built entirely from genuine history.
"""
import datetime

from sqlalchemy.orm import Session

from app.models.dashboard_snapshot import DashboardSnapshot


def record_snapshot_if_needed(db: Session, organization_id, security_score: float, risk_score: float, open_findings: int) -> None:
    today = datetime.date.today()
    existing = (
        db.query(DashboardSnapshot)
        .filter(DashboardSnapshot.organization_id == organization_id, DashboardSnapshot.snapshot_date == today)
        .first()
    )
    if existing:
        existing.security_score = security_score
        existing.risk_score = risk_score
        existing.open_findings = open_findings
        db.add(existing)
    else:
        db.add(DashboardSnapshot(
            organization_id=organization_id, snapshot_date=today,
            security_score=security_score, risk_score=risk_score, open_findings=open_findings,
        ))
    db.commit()
