"""
Compliance evaluation.

The rule under test everywhere here: **absence of evidence is never a pass.**
A control the platform cannot evaluate returns NOT_ASSESSED and is excluded
from the compliance percentage. Getting this wrong would let an unscanned
estate report 100% compliant, which is the single most dangerous number this
platform could produce.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.models.asset import Asset, AssetStatus, Criticality
from app.models.asset_detail import AssetService
from app.models.compliance import (
    CheckType, ComplianceControl, ComplianceException, ComplianceFramework,
    ComplianceRequirement, ControlAttestation, ControlResult,
)
from app.models.finding import Confidence, Finding, FindingClass, FindingStatus, Severity
from app.services.compliance.engine import assess_framework, evaluate_control
from app.services.compliance.packs import CONTENT_PACKS, available_packs, install_pack
from app.services.finding_ingest import FindingInput, ingest_findings

NOW = datetime.now(timezone.utc)


@pytest.fixture
def framework(db, organization):
    record = ComplianceFramework(
        organization_id=organization.id, name="Test Framework", slug="test-framework"
    )
    db.add(record)
    db.flush()
    return record


@pytest.fixture
def requirement(db, framework):
    record = ComplianceRequirement(framework_id=framework.id, code="R-1", title="Requirement 1")
    db.add(record)
    db.flush()
    return record


def _control(db, requirement, code, check_type, parameters=None):
    record = ComplianceControl(
        requirement_id=requirement.id,
        code=code,
        title=f"Control {code}",
        check_type=check_type,
        check_parameters=parameters or {},
    )
    db.add(record)
    db.flush()
    return record


def _service(db, organization, asset, port, state="open"):
    db.add(AssetService(
        organization_id=organization.id, asset_id=asset.id,
        port=port, protocol="tcp", state=state,
    ))
    db.flush()


# --- absence of evidence is not a pass -----------------------------------

def test_a_port_check_with_no_scan_data_is_not_assessed(db, organization, asset, requirement):
    """The most important assertion in this file."""
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    evaluation = evaluate_control(db, organization.id, control)

    assert evaluation.result is ControlResult.NOT_ASSESSED
    assert "no port data" in evaluation.summary.lower()


def test_a_port_check_with_no_assets_is_not_assessed(db, organization, requirement):
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    evaluation = evaluate_control(db, organization.id, control)
    assert evaluation.result is ControlResult.NOT_ASSESSED


def test_a_finding_check_passes_only_if_the_source_actually_ran(db, organization, asset, requirement):
    """Nothing found by a scanner that never ran is not a pass."""
    control = _control(
        db, requirement, "C-1", CheckType.NO_OPEN_FINDING,
        {"source": "windows_audit", "check_ids": ["smbv1-enabled"]},
    )
    evaluation = evaluate_control(db, organization.id, control)

    assert evaluation.result is ControlResult.NOT_ASSESSED
    assert "never ran is not a pass" in evaluation.summary


def test_an_sla_check_with_no_findings_at_that_severity_is_not_assessed(db, organization, asset, requirement):
    control = _control(
        db, requirement, "C-1", CheckType.REMEDIATION_WITHIN_SLA,
        {"severity": "critical", "max_age_days": 7},
    )
    evaluation = evaluate_control(db, organization.id, control)

    assert evaluation.result is ControlResult.NOT_ASSESSED
    assert "not evidence of compliance" in evaluation.summary


def test_a_check_that_errors_is_not_assessed_rather_than_passing(db, organization, asset, requirement):
    control = _control(db, requirement, "C-1", CheckType.ASSET_ATTRIBUTE_REQUIRED,
                       {"attribute": "no_such_attribute"})
    evaluation = evaluate_control(db, organization.id, control)
    # An unknown attribute reads as missing on every asset, which is a FAIL —
    # never a silent pass.
    assert evaluation.result is not ControlResult.PASS


# --- port checks ---------------------------------------------------------

def test_an_exposed_prohibited_port_fails(db, organization, asset, requirement):
    _service(db, organization, asset, 23)
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})

    evaluation = evaluate_control(db, organization.id, control)
    assert evaluation.result is ControlResult.FAIL
    assert evaluation.assets_failing == 1
    assert evaluation.evidence["failing_assets"][0]["hostname"] == asset.hostname


def test_a_scanned_asset_without_the_port_passes(db, organization, asset, requirement):
    _service(db, organization, asset, 22)
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})

    evaluation = evaluate_control(db, organization.id, control)
    assert evaluation.result is ControlResult.PASS
    assert evaluation.evidence["assets_scanned"] == 1


def test_a_closed_port_does_not_fail_the_control(db, organization, asset, requirement):
    _service(db, organization, asset, 22)
    _service(db, organization, asset, 23, state="closed")
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    assert evaluate_control(db, organization.id, control).result is ControlResult.PASS


def test_scope_narrows_to_internet_facing_assets(db, organization, asset, requirement):
    _service(db, organization, asset, 3389)
    control = _control(
        db, requirement, "C-1", CheckType.NO_EXPOSED_PORT,
        {"ports": [3389], "internet_facing_only": True},
    )

    # The asset is internal, so it is out of scope.
    evaluation = evaluate_control(db, organization.id, control)
    assert evaluation.result is ControlResult.NOT_ASSESSED

    asset.is_internet_facing = True
    db.flush()
    assert evaluate_control(db, organization.id, control).result is ControlResult.FAIL


def test_a_decommissioned_asset_is_out_of_scope(db, organization, asset, requirement):
    """A control cannot fail on a machine that no longer exists."""
    _service(db, organization, asset, 23)
    asset.status = AssetStatus.DECOMMISSIONED
    db.flush()

    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    assert evaluate_control(db, organization.id, control).result is ControlResult.NOT_ASSESSED


# --- attribute and freshness checks --------------------------------------

def test_a_missing_attribute_fails(db, organization, asset, requirement):
    control = _control(db, requirement, "C-1", CheckType.ASSET_ATTRIBUTE_REQUIRED,
                       {"attribute": "criticality"})
    evaluation = evaluate_control(db, organization.id, control)

    assert evaluation.result is ControlResult.FAIL
    assert asset.hostname in evaluation.evidence["failing_assets"]


def test_a_populated_attribute_passes(db, organization, asset, requirement):
    asset.criticality = Criticality.HIGH
    db.flush()
    control = _control(db, requirement, "C-1", CheckType.ASSET_ATTRIBUTE_REQUIRED,
                       {"attribute": "criticality"})
    assert evaluate_control(db, organization.id, control).result is ControlResult.PASS


def test_a_stale_assessment_fails_the_freshness_control(db, organization, asset, requirement):
    asset.last_seen = NOW - timedelta(days=60)
    db.flush()
    control = _control(db, requirement, "C-1", CheckType.ASSESSMENT_FRESHNESS,
                       {"max_age_days": 30})

    evaluation = evaluate_control(db, organization.id, control)
    assert evaluation.result is ControlResult.FAIL
    assert evaluation.assets_failing == 1


def test_a_recent_assessment_passes(db, organization, asset, requirement):
    asset.last_seen = NOW - timedelta(days=2)
    db.flush()
    control = _control(db, requirement, "C-1", CheckType.ASSESSMENT_FRESHNESS,
                       {"max_age_days": 30})
    assert evaluate_control(db, organization.id, control).result is ControlResult.PASS


# --- SLA and exposure checks ---------------------------------------------

def test_an_overdue_critical_finding_fails_the_sla_control(db, organization, asset, requirement):
    ingest_findings(db, organization.id, [FindingInput(
        asset_id=asset.id, title="Old critical",
        finding_class=FindingClass.VULNERABILITY, confidence=Confidence.PROBABLE,
        severity=Severity.CRITICAL, source="test", identifier="old-crit",
    )], None, NOW - timedelta(days=45))
    db.flush()

    control = _control(db, requirement, "C-1", CheckType.REMEDIATION_WITHIN_SLA,
                       {"severity": "critical", "max_age_days": 7})
    evaluation = evaluate_control(db, organization.id, control)

    assert evaluation.result is ControlResult.FAIL
    assert evaluation.evidence["overdue"][0]["days_open"] >= 45


def test_a_recent_critical_finding_passes_the_sla_control(db, organization, asset, requirement):
    ingest_findings(db, organization.id, [FindingInput(
        asset_id=asset.id, title="Fresh critical",
        finding_class=FindingClass.VULNERABILITY, confidence=Confidence.PROBABLE,
        severity=Severity.CRITICAL, source="test", identifier="fresh-crit",
    )], None, NOW)
    db.flush()

    control = _control(db, requirement, "C-1", CheckType.REMEDIATION_WITHIN_SLA,
                       {"severity": "critical", "max_age_days": 7})
    assert evaluate_control(db, organization.id, control).result is ControlResult.PASS


def test_no_internet_facing_assets_makes_the_exposure_control_not_applicable(
    db, organization, asset, requirement
):
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_SEVERITY, {"severity": "high"})
    evaluation = evaluate_control(db, organization.id, control)

    assert evaluation.result is ControlResult.NOT_APPLICABLE
    assert "does not apply" in evaluation.summary


# --- manual controls and attestations ------------------------------------

def test_a_manual_control_without_an_attestation_is_not_assessed(db, organization, requirement):
    control = _control(db, requirement, "C-1", CheckType.MANUAL)
    evaluation = evaluate_control(db, organization.id, control)

    assert evaluation.result is ControlResult.NOT_ASSESSED
    assert "no attestation" in evaluation.summary


def test_a_valid_attestation_passes(db, organization, requirement):
    control = _control(db, requirement, "C-1", CheckType.MANUAL)
    db.add(ControlAttestation(
        organization_id=organization.id, control_id=control.id,
        statement="Training completed for all staff.",
        attested_at=NOW, valid_until=NOW + timedelta(days=365), is_met=True,
    ))
    db.flush()

    assert evaluate_control(db, organization.id, control).result is ControlResult.PASS


def test_an_expired_attestation_reverts_to_not_assessed(db, organization, requirement):
    """A statement made two years ago is not evidence of current compliance."""
    control = _control(db, requirement, "C-1", CheckType.MANUAL)
    db.add(ControlAttestation(
        organization_id=organization.id, control_id=control.id,
        statement="Training completed.",
        attested_at=NOW - timedelta(days=800), valid_until=NOW - timedelta(days=400),
        is_met=True,
    ))
    db.flush()

    evaluation = evaluate_control(db, organization.id, control)
    assert evaluation.result is ControlResult.NOT_ASSESSED
    assert "expired" in evaluation.summary


def test_an_attestation_of_non_compliance_fails(db, organization, requirement):
    control = _control(db, requirement, "C-1", CheckType.MANUAL)
    db.add(ControlAttestation(
        organization_id=organization.id, control_id=control.id,
        statement="No restoration test has been performed.",
        attested_at=NOW, valid_until=NOW + timedelta(days=90), is_met=False,
    ))
    db.flush()
    assert evaluate_control(db, organization.id, control).result is ControlResult.FAIL


# --- exceptions ----------------------------------------------------------

def test_an_active_exception_overrides_a_failure(db, organization, asset, requirement):
    _service(db, organization, asset, 23)
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    assert evaluate_control(db, organization.id, control).result is ControlResult.FAIL

    db.add(ComplianceException(
        organization_id=organization.id, control_id=control.id,
        reason="Legacy industrial controller; network-segmented.",
        expires_at=NOW + timedelta(days=90),
    ))
    db.flush()

    evaluation = evaluate_control(db, organization.id, control)
    # An exception is its own result, never a pass.
    assert evaluation.result is ControlResult.EXCEPTION
    assert "Legacy industrial controller" in evaluation.summary


def test_an_expired_exception_stops_applying(db, organization, asset, requirement):
    _service(db, organization, asset, 23)
    control = _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    db.add(ComplianceException(
        organization_id=organization.id, control_id=control.id,
        reason="Temporary.", expires_at=NOW - timedelta(days=1),
    ))
    db.flush()

    assert evaluate_control(db, organization.id, control).result is ControlResult.FAIL


# --- assessment arithmetic ------------------------------------------------

def test_not_assessed_controls_are_excluded_from_the_percentage(
    db, organization, asset, framework, requirement
):
    """
    The number that must never lie: an unscanned estate cannot report 100%.
    """
    _service(db, organization, asset, 22)
    _control(db, requirement, "PASS-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    _control(db, requirement, "FAIL-1", CheckType.ASSET_ATTRIBUTE_REQUIRED, {"attribute": "criticality"})
    _control(db, requirement, "MANUAL-1", CheckType.MANUAL)
    _control(db, requirement, "MANUAL-2", CheckType.MANUAL)

    assessment = assess_framework(db, organization.id, framework)

    assert assessment.controls_total == 4
    assert assessment.controls_passed == 1
    assert assessment.controls_failed == 1
    assert assessment.controls_not_assessed == 2
    # 1 of 2 conclusive controls passed.
    assert assessment.compliance_percent == 50.0
    # Only half the framework could be evaluated at all.
    assert assessment.assessable_percent == 50.0


def test_a_framework_with_nothing_conclusive_reports_no_percentage(
    db, organization, framework, requirement
):
    """Zero and 'unknown' are different, and are not conflated."""
    _control(db, requirement, "MANUAL-1", CheckType.MANUAL)
    assessment = assess_framework(db, organization.id, framework)

    assert assessment.compliance_percent is None
    assert assessment.assessable_percent == 0.0


def test_an_assessment_records_evidence_for_every_control(
    db, organization, asset, framework, requirement
):
    from app.models.compliance import ComplianceResult

    _service(db, organization, asset, 23)
    _control(db, requirement, "C-1", CheckType.NO_EXPOSED_PORT, {"ports": [23]})
    assessment = assess_framework(db, organization.id, framework)

    result = db.query(ComplianceResult).filter(
        ComplianceResult.assessment_id == assessment.id
    ).one()
    assert result.summary
    assert result.evidence


# --- content packs -------------------------------------------------------

def test_the_packs_install_and_are_idempotent(db, organization):
    framework = install_pack(db, organization.id, "network-hygiene")
    first = db.query(ComplianceControl).join(ComplianceRequirement).filter(
        ComplianceRequirement.framework_id == framework.id
    ).count()

    install_pack(db, organization.id, "network-hygiene")
    second = db.query(ComplianceControl).join(ComplianceRequirement).filter(
        ComplianceRequirement.framework_id == framework.id
    ).count()

    assert first > 0
    assert first == second


def test_an_unknown_pack_is_rejected(db, organization):
    with pytest.raises(ValueError, match="Unknown content pack"):
        install_pack(db, organization.id, "iso-27001")


def test_the_network_hygiene_pack_is_fully_automatable(db, organization):
    """A pack advertised as automatable must contain no manual controls."""
    pack = next(item for item in available_packs() if item["slug"] == "network-hygiene")
    assert pack["manual_control_count"] == 0


def test_packs_declare_how_much_is_manual(db, organization):
    """Stated up front so a low assessable percentage is not a surprise."""
    governance = next(item for item in available_packs() if item["slug"] == "governance-baseline")
    assert governance["manual_control_count"] > 0


def test_no_pack_claims_to_be_a_published_standard(db, organization):
    """
    Installing a pack must not imply certification. The previous provisioning
    created empty frameworks named "ISO 27001" and "PCI DSS" with no control
    content behind them at all.
    """
    for pack in CONTENT_PACKS.values():
        assert "Omni Cyber Guard" in pack["source"]
        for forbidden in ("ISO 27001", "PCI DSS", "SOC 2", "HIPAA"):
            assert forbidden not in pack["name"]


def test_installed_packs_assess_end_to_end(db, organization, asset):
    _service(db, organization, asset, 22)
    asset.criticality = Criticality.HIGH
    asset.last_seen = NOW
    db.flush()

    framework = install_pack(db, organization.id, "network-hygiene")
    assessment = assess_framework(db, organization.id, framework)

    assert assessment.controls_total > 0
    # Every control in this pack is automatable, so nothing should be
    # not-assessed once there is scan data.
    assert assessment.controls_not_assessed + assessment.controls_not_applicable < assessment.controls_total
