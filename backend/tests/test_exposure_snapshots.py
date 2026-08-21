"""
Exposure history.

The trend line must be a record, not a drawing. These tests hold that: one row
per day, updated rather than duplicated on a re-run, and gaps left as gaps.
"""
from datetime import date, datetime, timedelta, timezone

from app.models.asset import Criticality
from app.models.exposure_snapshot import ExposureSnapshot
from app.models.finding import Confidence, Finding, FindingClass, Severity
from app.services.exposure_snapshots import capture_snapshot, get_trend
from app.services.finding_ingest import FindingInput, ingest_findings

NOW = datetime.now(timezone.utc)
TODAY = NOW.date()


def _seed(db, organization, asset):
    asset.criticality = Criticality.HIGH
    asset.is_internet_facing = True
    db.flush()
    ingest_findings(db, organization.id, [FindingInput(
        asset_id=asset.id,
        title="Critical finding",
        finding_class=FindingClass.VULNERABILITY,
        confidence=Confidence.PROBABLE,
        severity=Severity.CRITICAL,
        source="test",
        identifier="crit-1",
    )], None, NOW)
    db.flush()


def test_a_snapshot_records_the_days_posture(db, organization, asset):
    _seed(db, organization, asset)
    snapshot = capture_snapshot(db, organization.id, TODAY)

    assert snapshot.snapshot_date == TODAY
    assert snapshot.assets_total == 1
    assert snapshot.assets_assessed == 1
    assert snapshot.open_findings == 1
    assert snapshot.critical_findings == 1
    assert snapshot.internet_exposed_assets == 1
    assert snapshot.exposure_score is not None


def test_capturing_twice_in_a_day_updates_rather_than_duplicating(db, organization, asset):
    """A manual refresh must not distort the shape of the trend."""
    _seed(db, organization, asset)
    capture_snapshot(db, organization.id, TODAY)
    capture_snapshot(db, organization.id, TODAY)

    rows = db.query(ExposureSnapshot).filter(
        ExposureSnapshot.organization_id == organization.id
    ).all()
    assert len(rows) == 1


def test_an_unassessed_estate_records_a_null_score_not_zero(db, organization, asset):
    snapshot = capture_snapshot(db, organization.id, TODAY)
    assert snapshot.exposure_score is None
    assert snapshot.assets_assessed == 0


def test_the_trend_returns_recorded_days_only(db, organization, asset):
    """Gaps are left as gaps — carrying values forward would invent posture."""
    _seed(db, organization, asset)
    capture_snapshot(db, organization.id, TODAY - timedelta(days=5))
    capture_snapshot(db, organization.id, TODAY)

    points = get_trend(db, organization.id, days=30)
    assert len(points) == 2
    assert points[0]["date"] < points[1]["date"]


def test_the_trend_is_empty_before_anything_is_recorded(db, organization):
    assert get_trend(db, organization.id, days=30) == []


def test_snapshots_are_tenant_isolated(db, organization, second_organization, asset):
    from app.db.tenancy import set_tenant

    _seed(db, organization, asset)
    capture_snapshot(db, organization.id, TODAY)

    set_tenant(db, second_organization.id)
    assert get_trend(db, second_organization.id, days=30) == []
