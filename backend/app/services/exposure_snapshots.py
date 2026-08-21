"""
Daily exposure posture snapshots.

The trend line on the dashboard is drawn from these rows and nothing else. A
chart that interpolates between two current values is a drawing; this is a
record. If the platform was not running on a given day, that day is absent from
the chart, which is the truth.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.exposure_snapshot import ExposureSnapshot
from app.models.finding import CLOSED_STATUSES, Finding, Severity
from app.services.exposure_engine import recompute_organization_exposure


def capture_snapshot(
    db: Session, organization_id: uuid.UUID, on_date: date | None = None
) -> ExposureSnapshot:
    """
    Record today's posture, recomputing exposure first.

    One row per organization per day. Running twice in a day updates the day's
    row rather than adding a second, so a manual refresh does not distort the
    shape of the trend.
    """
    on_date = on_date or datetime.now(timezone.utc).date()

    exposure = recompute_organization_exposure(db, organization_id)

    open_filter = [
        Finding.organization_id == organization_id,
        Finding.status.notin_(list(CLOSED_STATUSES)),
    ]

    open_findings = db.execute(
        select(func.count(Finding.id)).where(*open_filter)
    ).scalar_one()
    critical_findings = db.execute(
        select(func.count(Finding.id)).where(*open_filter, Finding.severity == Severity.CRITICAL)
    ).scalar_one()
    known_exploited = db.execute(
        select(func.count(Finding.id)).where(*open_filter, Finding.is_known_exploited.is_(True))
    ).scalar_one()
    internet_exposed = db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == organization_id,
            Asset.is_internet_facing.is_(True),
        )
    ).scalar_one()

    snapshot = db.execute(
        select(ExposureSnapshot).where(
            ExposureSnapshot.organization_id == organization_id,
            ExposureSnapshot.snapshot_date == on_date,
        )
    ).scalar_one_or_none()

    if snapshot is None:
        snapshot = ExposureSnapshot(organization_id=organization_id, snapshot_date=on_date)
        db.add(snapshot)

    snapshot.exposure_score = exposure["organization_exposure_score"]
    snapshot.assets_total = exposure["assets_total"]
    snapshot.assets_assessed = exposure["assets_assessed"]
    snapshot.open_findings = open_findings
    snapshot.critical_findings = critical_findings
    snapshot.known_exploited_findings = known_exploited
    snapshot.internet_exposed_assets = internet_exposed

    db.commit()
    return snapshot


def get_trend(db: Session, organization_id: uuid.UUID, days: int = 30) -> list[dict]:
    """
    Recorded history only.

    Gaps are left as gaps. Filling them by carrying the previous value forward
    would invent posture for days the platform did not observe.
    """
    from datetime import timedelta

    since = datetime.now(timezone.utc).date() - timedelta(days=days)
    rows = db.execute(
        select(ExposureSnapshot)
        .where(
            ExposureSnapshot.organization_id == organization_id,
            ExposureSnapshot.snapshot_date >= since,
        )
        .order_by(ExposureSnapshot.snapshot_date.asc())
    ).scalars().all()

    return [
        {
            "date": row.snapshot_date.isoformat(),
            "exposure_score": row.exposure_score,
            "assets_total": row.assets_total,
            "assets_assessed": row.assets_assessed,
            "open_findings": row.open_findings,
            "critical_findings": row.critical_findings,
            "known_exploited_findings": row.known_exploited_findings,
            "internet_exposed_assets": row.internet_exposed_assets,
        }
        for row in rows
    ]
