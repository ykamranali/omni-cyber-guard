"""
The exposure engine.

The property that matters most is not any individual weight — those are meant
to be tuned. It is that the published breakdown always adds up to the published
score, that nothing is counted that cannot be evidenced, and that an unassessed
asset is never presented as a safe one.
"""
from datetime import date, datetime, timedelta, timezone

import pytest

from app.models.asset import Criticality, DataSensitivity
from app.models.asset_detail import AssetService
from app.models.finding import (
    Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.services.exposure_engine import (
    ExposureModel, assess_asset, band_for, recompute_organization_exposure,
)
from app.services.finding_ingest import FindingInput, ingest_findings

NOW = datetime.now(timezone.utc)


def _finding(db, organization, asset, **overrides):
    payload = dict(
        asset_id=asset.id,
        title="Test finding",
        finding_class=FindingClass.VULNERABILITY,
        confidence=Confidence.PROBABLE,
        severity=Severity.HIGH,
        source="test",
        identifier=overrides.pop("identifier", "test-check"),
    )
    extra = {key: overrides.pop(key) for key in list(overrides) if key in {
        "cve_id", "cvss_score", "location", "evidence",
    }}
    payload.update(extra)
    payload.update(overrides)
    ingest_findings(db, organization.id, [FindingInput(**payload)], None, NOW)
    db.flush()
    return db.query(Finding).filter(Finding.asset_id == asset.id).order_by(
        Finding.created_at.desc()
    ).first()


# --- the arithmetic must be honest ---------------------------------------

def test_contributors_always_sum_to_the_score(db, organization, asset):
    """A breakdown that does not add up is worse than no breakdown."""
    asset.is_internet_facing = True
    asset.criticality = Criticality.CRITICAL
    asset.data_sensitivity = DataSensitivity.RESTRICTED
    db.flush()
    _finding(db, organization, asset, severity=Severity.CRITICAL, cvss_score=9.8)

    assessment = assess_asset(db, asset)
    total = sum(contributor.points for contributor in assessment.contributors)
    assert round(total, 1) == assessment.score


def test_the_score_never_exceeds_one_hundred(db, organization, asset):
    asset.is_internet_facing = True
    asset.is_production = True
    asset.criticality = Criticality.CRITICAL
    asset.data_sensitivity = DataSensitivity.RESTRICTED
    db.flush()

    for index in range(20):
        _finding(
            db, organization, asset,
            severity=Severity.CRITICAL, cvss_score=10.0, identifier=f"check-{index}",
        )
    for finding in db.query(Finding).filter(Finding.asset_id == asset.id):
        finding.is_known_exploited = True
        finding.epss_score = 0.99
    db.flush()

    assessment = assess_asset(db, asset)
    assert assessment.score <= 100.0


@pytest.mark.parametrize("score,expected", [
    (95, "extreme"), (90, "extreme"), (89, "critical"), (70, "critical"),
    (69, "high"), (40, "high"), (39, "medium"), (20, "medium"),
    (19, "low"), (0.1, "low"), (0, "none"),
])
def test_bands(score, expected):
    assert band_for(score) == expected


# --- what counts, and what does not --------------------------------------

def test_a_clean_asset_with_no_context_is_unassessed_not_safe(db, organization, asset):
    """A zero here means 'nothing to score', and says so."""
    assessment = assess_asset(db, asset)
    assert assessment.score == 0.0
    assert assessment.assessed is False
    assert "not assessed" in assessment.note


def test_an_asset_with_business_context_is_assessed(db, organization, asset):
    asset.criticality = Criticality.HIGH
    db.flush()
    assessment = assess_asset(db, asset)
    assert assessment.assessed is True


def test_informational_findings_do_not_raise_exposure(db, organization, asset):
    """Recording a fact is not an exposure."""
    _finding(
        db, organization, asset,
        finding_class=FindingClass.INFORMATIONAL, severity=Severity.INFO,
    )
    assessment = assess_asset(db, asset)
    keys = {contributor.key for contributor in assessment.contributors}
    assert "vulnerability_severity" not in keys


def test_a_remediated_finding_stops_counting(db, organization, asset):
    """Otherwise remediation would never move the number."""
    finding = _finding(db, organization, asset, severity=Severity.CRITICAL)
    before = assess_asset(db, asset).score

    finding.status = FindingStatus.REMEDIATED
    db.flush()
    after = assess_asset(db, asset).score

    assert before > 0
    assert after < before


def test_an_accepted_risk_stops_counting(db, organization, asset):
    finding = _finding(db, organization, asset, severity=Severity.CRITICAL)
    finding.status = FindingStatus.ACCEPTED_RISK
    db.flush()
    keys = {c.key for c in assess_asset(db, asset).contributors}
    assert "vulnerability_severity" not in keys


# --- individual contributors --------------------------------------------

def test_known_exploited_is_a_named_contributor_with_the_cve(db, organization, asset):
    finding = _finding(db, organization, asset, cve_id="CVE-2021-44228")
    finding.is_known_exploited = True
    db.flush()

    assessment = assess_asset(db, asset)
    contributor = next(c for c in assessment.contributors if c.key == "known_exploited")
    assert "CVE-2021-44228" in contributor.evidence
    assert "KEV" in contributor.evidence


def test_epss_scales_with_probability(db, organization, asset):
    finding = _finding(db, organization, asset, cve_id="CVE-2021-44228")

    finding.epss_score = 0.05
    db.flush()
    low = next(
        (c.points for c in assess_asset(db, asset).contributors if c.key == "exploit_probability"),
        0,
    )

    finding.epss_score = 0.95
    db.flush()
    high = next(
        c.points for c in assess_asset(db, asset).contributors if c.key == "exploit_probability"
    )

    assert high > low


def test_internet_exposure_says_it_was_declared_not_inferred(db, organization, asset):
    asset.is_internet_facing = True
    db.flush()
    contributor = next(
        c for c in assess_asset(db, asset).contributors if c.key == "internet_exposure"
    )
    assert "declared" in contributor.evidence
    assert "never inferred" in contributor.evidence


def test_criticality_raises_exposure(db, organization, asset):
    _finding(db, organization, asset, severity=Severity.MEDIUM)

    asset.criticality = Criticality.UNASSIGNED
    db.flush()
    unassigned = assess_asset(db, asset).score

    asset.criticality = Criticality.CRITICAL
    db.flush()
    critical = assess_asset(db, asset).score

    assert critical > unassigned


def test_an_old_finding_scores_higher_than_a_fresh_one(db, organization, asset):
    finding = _finding(db, organization, asset, severity=Severity.HIGH)

    fresh = assess_asset(db, asset).score
    finding.first_seen = NOW - timedelta(days=120)
    db.flush()
    aged = assess_asset(db, asset).score

    assert aged > fresh
    contributor = next(
        c for c in assess_asset(db, asset).contributors if c.key == "exposure_duration"
    )
    assert "day(s)" in contributor.evidence


def test_exposed_high_value_services_contribute(db, organization, asset):
    for port in (22, 445, 3389):
        db.add(AssetService(
            organization_id=organization.id, asset_id=asset.id,
            port=port, protocol="tcp", state="open",
        ))
    db.flush()

    contributor = next(
        c for c in assess_asset(db, asset).contributors if c.key == "exposed_services"
    )
    assert "3" in contributor.evidence


def test_a_closed_service_does_not_contribute(db, organization, asset):
    db.add(AssetService(
        organization_id=organization.id, asset_id=asset.id,
        port=3389, protocol="tcp", state="closed",
    ))
    db.flush()
    keys = {c.key for c in assess_asset(db, asset).contributors}
    assert "exposed_services" not in keys


# --- honesty about what the model cannot do ------------------------------

def test_unavailable_factors_are_declared_not_silently_zero(db, organization, asset):
    """
    A score that omits attack-path position without saying so looks complete.
    The reader has to be able to see what is missing.
    """
    assessment = assess_asset(db, asset)
    keys = {factor.key for factor in assessment.unavailable}
    assert "attack_path_position" in keys
    assert "identity_privilege" in keys
    for factor in assessment.unavailable:
        assert factor.reason


def test_every_contributor_carries_its_evidence(db, organization, asset):
    asset.is_internet_facing = True
    asset.criticality = Criticality.HIGH
    db.flush()
    _finding(db, organization, asset, severity=Severity.CRITICAL)

    for contributor in assess_asset(db, asset).contributors:
        assert contributor.evidence, f"{contributor.key} has no evidence"
        assert contributor.label


# --- configurable weights ------------------------------------------------

def test_weights_are_configurable_per_organization(db, organization, asset):
    asset.is_internet_facing = True
    db.flush()

    default = assess_asset(db, asset, ExposureModel())
    weighted = assess_asset(db, asset, ExposureModel(internet_exposure=60.0))

    assert weighted.score > default.score


def test_a_zero_weight_removes_a_contributor(db, organization, asset):
    asset.is_internet_facing = True
    db.flush()
    assessment = assess_asset(db, asset, ExposureModel(internet_exposure=0.0))
    assert "internet_exposure" not in {c.key for c in assessment.contributors}


def test_organization_overrides_are_loaded(db, organization):
    organization.exposure_model = {"internet_exposure": 42.0}
    db.flush()
    model = ExposureModel.from_organization(organization)
    assert model.internet_exposure == 42.0
    # Unspecified factors keep the platform default.
    assert model.known_exploited == ExposureModel().known_exploited


def test_a_negative_override_is_ignored(db, organization):
    organization.exposure_model = {"internet_exposure": -5}
    db.flush()
    assert ExposureModel.from_organization(organization).internet_exposure == ExposureModel().internet_exposure


# --- organization level --------------------------------------------------

def test_unassessed_assets_do_not_dilute_the_organization_score(db, organization, asset):
    """Averaging in unscored assets would make an unscanned estate look safe."""
    from app.models.asset import Asset

    asset.is_internet_facing = True
    asset.criticality = Criticality.CRITICAL
    db.flush()
    _finding(db, organization, asset, severity=Severity.CRITICAL)

    for index in range(5):
        db.add(Asset(
            organization_id=organization.id,
            hostname=f"unscanned-{index}",
            ip_address=f"192.168.9.{index + 1}",
        ))
    db.flush()

    result = recompute_organization_exposure(db, organization.id)
    assert result["assets_total"] == 6
    assert result["assets_assessed"] == 1
    assert result["organization_exposure_score"] > 0


def test_an_estate_with_nothing_to_score_reports_null_not_zero(db, organization, asset):
    result = recompute_organization_exposure(db, organization.id)
    assert result["organization_exposure_score"] is None
    assert "not enough data" in result["note"] or "No asset" in result["note"]
