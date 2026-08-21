"""Risk scoring must be deterministic and derived only from open findings."""
import uuid

import pytest

from app.services.risk_scoring import SEVERITY_WEIGHT, compute_asset_risk_score
from app.models.finding import Confidence, Finding, FindingClass, FindingStatus, Severity


def _finding(org_id, asset_id, severity, status=FindingStatus.OPEN):
    return Finding(
        organization_id=org_id,
        asset_id=asset_id,
        # Findings carry a stable identity; a random one keeps each fixture row
        # distinct without depending on the fingerprint logic under test here.
        fingerprint=uuid.uuid4().hex * 2,
        title=f"{severity.value} finding",
        description="",
        evidence="",
        finding_class=FindingClass.EXPOSURE,
        confidence=Confidence.CONFIRMED,
        severity=severity,
        status=status,
    )


def test_severity_weights_are_monotonic():
    assert (
        SEVERITY_WEIGHT[Severity.CRITICAL]
        > SEVERITY_WEIGHT[Severity.HIGH]
        > SEVERITY_WEIGHT[Severity.MEDIUM]
        > SEVERITY_WEIGHT[Severity.LOW]
        >= SEVERITY_WEIGHT[Severity.INFO]
    )


def test_no_findings_scores_zero(db, organization, asset):
    assert compute_asset_risk_score(db, asset.id) == 0.0


def test_score_sums_open_finding_weights(db, organization, asset):
    db.add(_finding(organization.id, asset.id, Severity.HIGH))
    db.add(_finding(organization.id, asset.id, Severity.MEDIUM))
    db.flush()

    expected = SEVERITY_WEIGHT[Severity.HIGH] + SEVERITY_WEIGHT[Severity.MEDIUM]
    assert compute_asset_risk_score(db, asset.id) == pytest.approx(expected)


def test_remediated_findings_do_not_contribute(db, organization, asset):
    db.add(_finding(organization.id, asset.id, Severity.CRITICAL, FindingStatus.REMEDIATED))
    db.flush()
    assert compute_asset_risk_score(db, asset.id) == 0.0


def test_score_is_capped_at_one_hundred(db, organization, asset):
    for _ in range(20):
        db.add(_finding(organization.id, asset.id, Severity.CRITICAL))
    db.flush()
    assert compute_asset_risk_score(db, asset.id) == 100.0


def test_score_is_deterministic(db, organization, asset):
    db.add(_finding(organization.id, asset.id, Severity.HIGH))
    db.flush()
    scores = {compute_asset_risk_score(db, asset.id) for _ in range(5)}
    assert len(scores) == 1
