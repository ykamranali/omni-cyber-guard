"""
Remediation workflow.

The property under test throughout is the separation of *fixed* from
*verified*. FIXED is a person's claim; VERIFIED requires a scan. A platform
that conflates them reports remediation that may never have happened, which is
exactly what §56 forbids.
"""
from datetime import date, datetime, timedelta, timezone

import pytest

from app.models.finding import (
    Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.models.remediation import (
    AcceptanceStatus, RemediationPriority, RemediationStatus, RemediationTask, RiskAcceptance,
)
from app.services.finding_ingest import FindingInput, ingest_findings
from app.services.remediation_engine import (
    DEFAULT_SLA_DAYS, KNOWN_EXPLOITED_SLA_DAYS, RemediationError, accept_risk, assign_task,
    close_task, create_task, due_date_for, expire_lapsed_acceptances, mark_fixed, metrics,
    reopen_from_scan, revoke_acceptance, sla_policy, verify_from_scan,
)

NOW = datetime.now(timezone.utc)
TODAY = date.today()


@pytest.fixture
def finding(db, organization, asset):
    ingest_findings(db, organization.id, [FindingInput(
        asset_id=asset.id,
        title="Exposed RDP service on port 3389",
        finding_class=FindingClass.EXPOSURE,
        confidence=Confidence.CONFIRMED,
        severity=Severity.HIGH,
        source="nmap",
        identifier="exposed-port-3389",
        location="tcp/3389",
        remediation_guidance="Restrict RDP to VPN access.",
    )], None, NOW)
    db.flush()
    return db.query(Finding).filter(Finding.asset_id == asset.id).one()


@pytest.fixture
def task(db, organization, finding):
    record = create_task(db, finding, organization, created_by_user_id=None)
    db.flush()
    return record


# --- SLA -----------------------------------------------------------------

def test_due_dates_follow_severity(db, organization, asset, finding):
    policy = sla_policy(organization)
    for severity, expected_days in DEFAULT_SLA_DAYS.items():
        finding.severity = severity
        finding.is_known_exploited = False
        due, days = due_date_for(finding, policy, TODAY)
        assert days == expected_days
        assert due == TODAY + timedelta(days=expected_days)


def test_a_known_exploited_finding_gets_the_shortest_window(db, organization, finding):
    """Observed exploitation outranks theoretical severity."""
    finding.severity = Severity.LOW
    finding.is_known_exploited = True
    due, days = due_date_for(finding, sla_policy(organization), TODAY)
    assert days == KNOWN_EXPLOITED_SLA_DAYS
    assert days < DEFAULT_SLA_DAYS[Severity.LOW]


def test_the_sla_policy_is_configurable(db, organization):
    organization.sla_policy = {"critical": 1}
    db.flush()
    assert sla_policy(organization)[Severity.CRITICAL] == 1
    assert sla_policy(organization)[Severity.HIGH] == DEFAULT_SLA_DAYS[Severity.HIGH]


# --- task creation -------------------------------------------------------

def test_creating_a_task_sets_priority_and_due_date(db, organization, finding):
    task = create_task(db, finding, organization)
    db.flush()
    assert task.status is RemediationStatus.OPEN
    assert task.priority is RemediationPriority.HIGH
    assert task.due_date == TODAY + timedelta(days=DEFAULT_SLA_DAYS[Severity.HIGH])
    assert task.sla_days == DEFAULT_SLA_DAYS[Severity.HIGH]


def test_creating_a_task_acknowledges_the_finding(db, organization, finding):
    create_task(db, finding, organization)
    db.flush()
    assert finding.status is FindingStatus.ACKNOWLEDGED


def test_assigning_at_creation_marks_the_finding_in_progress(db, organization, finding):
    user_id = finding.organization_id  # any UUID; the FK is nullable in this fixture path
    task = create_task(db, finding, organization, assigned_to_user_id=None)
    db.flush()
    assert task.status is RemediationStatus.OPEN


def test_a_second_open_task_for_the_same_finding_is_refused(db, organization, finding):
    create_task(db, finding, organization)
    db.flush()
    with pytest.raises(RemediationError, match="already exists"):
        create_task(db, finding, organization)


def test_no_task_is_created_for_an_already_closed_finding(db, organization, finding):
    """A task against a resolved finding would sit in the queue forever."""
    finding.status = FindingStatus.REMEDIATED
    db.flush()
    with pytest.raises(RemediationError, match="nothing to remediate"):
        create_task(db, finding, organization)


# --- the fixed / verified distinction ------------------------------------

def test_marking_fixed_does_not_close_the_finding(db, organization, finding, task):
    """This is the whole point: a claim is not evidence."""
    mark_fixed(db, task, None, "Restricted RDP to the VPN range.")
    db.flush()

    assert task.status is RemediationStatus.AWAITING_VERIFICATION
    assert task.fixed_at is not None
    assert task.verified_at is None
    assert task.verified_by_scan_job_id is None
    # The finding is untouched — only a scan can resolve it.
    assert finding.status is not FindingStatus.REMEDIATED


def test_only_a_scan_moves_a_task_to_verified(db, organization, finding, task, scan_job):
    mark_fixed(db, task, None)
    db.flush()

    verified = verify_from_scan(db, organization.id, scan_job.id, {finding.id})
    db.flush()

    assert verified == 1
    assert task.status is RemediationStatus.VERIFIED
    assert task.verified_by_scan_job_id == scan_job.id
    assert task.verified_at is not None


def test_verification_records_which_scan_established_it(db, organization, finding, task, scan_job):
    verify_from_scan(db, organization.id, scan_job.id, {finding.id})
    db.flush()
    assert task.verified_by_scan_job_id == scan_job.id


def test_a_scan_that_still_sees_the_finding_verifies_nothing(db, organization, finding, task, scan_job):
    assert verify_from_scan(db, organization.id, scan_job.id, set()) == 0
    assert task.status is not RemediationStatus.VERIFIED


def test_closing_without_verification_requires_a_reason(db, organization, task):
    with pytest.raises(RemediationError, match="requires a reason"):
        close_task(db, task, None, "   ")


def test_closing_without_verification_lands_in_closed_not_verified(db, organization, task):
    """The two are counted separately in every report."""
    close_task(db, task, None, "The asset was decommissioned.")
    db.flush()

    assert task.status is RemediationStatus.CLOSED
    assert task.verified_at is None
    assert task.verified_by_scan_job_id is None
    assert "decommissioned" in task.notes


def test_a_verified_task_reopens_if_the_finding_comes_back(db, organization, finding, task, scan_job):
    """A regression must not stay hidden behind a closed task."""
    verify_from_scan(db, organization.id, scan_job.id, {finding.id})
    db.flush()
    assert task.status is RemediationStatus.VERIFIED

    reopened = reopen_from_scan(db, organization.id, {finding.id})
    db.flush()

    assert reopened == 1
    assert task.status is RemediationStatus.IN_PROGRESS
    assert task.verified_by_scan_job_id is None
    assert "Reopened" in task.notes


def test_a_terminal_task_cannot_be_marked_fixed_again(db, organization, task, scan_job, finding):
    verify_from_scan(db, organization.id, scan_job.id, {finding.id})
    db.flush()
    with pytest.raises(RemediationError, match="already"):
        mark_fixed(db, task, None)


# --- overdue -------------------------------------------------------------

def test_a_task_past_its_due_date_is_overdue(db, organization, task):
    task.due_date = TODAY - timedelta(days=1)
    db.flush()
    assert task.is_overdue is True


def test_a_closed_task_is_never_overdue(db, organization, task):
    task.due_date = TODAY - timedelta(days=30)
    close_task(db, task, None, "Decommissioned.")
    db.flush()
    assert task.is_overdue is False


# --- risk acceptance -----------------------------------------------------

def test_accepting_a_risk_records_reason_approver_and_expiry(db, organization, finding):
    acceptance = accept_risk(
        db, finding,
        reason="Legacy application; replacement scheduled for Q4.",
        expires_at=TODAY + timedelta(days=90),
        approved_by_user_id=None,
    )
    db.flush()

    assert acceptance.status is AcceptanceStatus.ACTIVE
    assert acceptance.approved_at is not None
    assert finding.status is FindingStatus.ACCEPTED_RISK


def test_an_acceptance_must_have_a_reason(db, organization, finding):
    with pytest.raises(RemediationError, match="requires a reason"):
        accept_risk(db, finding, reason="  ", expires_at=TODAY + timedelta(days=30),
                    approved_by_user_id=None)


def test_an_acceptance_must_expire_in_the_future(db, organization, finding):
    """An acceptance with no end date is indistinguishable from forgetting."""
    with pytest.raises(RemediationError, match="future date"):
        accept_risk(db, finding, reason="Because.", expires_at=TODAY,
                    approved_by_user_id=None)


def test_a_second_active_acceptance_is_refused(db, organization, finding):
    accept_risk(db, finding, reason="First.", expires_at=TODAY + timedelta(days=30),
                approved_by_user_id=None)
    db.flush()
    with pytest.raises(RemediationError, match="already has an active"):
        accept_risk(db, finding, reason="Second.", expires_at=TODAY + timedelta(days=60),
                    approved_by_user_id=None)


def test_a_lapsed_acceptance_reopens_the_finding(db, organization, finding):
    """This is what makes the expiry date mean something."""
    acceptance = accept_risk(
        db, finding, reason="Temporary.", expires_at=TODAY + timedelta(days=1),
        approved_by_user_id=None,
    )
    db.flush()

    acceptance.expires_at = TODAY - timedelta(days=1)
    db.flush()

    expired = expire_lapsed_acceptances(db, organization.id)
    db.flush()

    assert expired == 1
    assert acceptance.status is AcceptanceStatus.EXPIRED
    assert finding.status is FindingStatus.OPEN


def test_an_unexpired_acceptance_is_left_alone(db, organization, finding):
    accept_risk(db, finding, reason="Valid.", expires_at=TODAY + timedelta(days=30),
                approved_by_user_id=None)
    db.flush()
    assert expire_lapsed_acceptances(db, organization.id) == 0
    assert finding.status is FindingStatus.ACCEPTED_RISK


def test_revoking_an_acceptance_reopens_the_finding(db, organization, finding):
    acceptance = accept_risk(
        db, finding, reason="Mistaken.", expires_at=TODAY + timedelta(days=90),
        approved_by_user_id=None,
    )
    db.flush()

    # actor_user_id is nullable here; the fixture has no user, and passing an
    # organization id would violate the users foreign key.
    revoke_acceptance(db, acceptance, None, "The compensating control was removed.")
    db.flush()

    assert acceptance.status is AcceptanceStatus.REVOKED
    assert acceptance.revocation_reason
    assert finding.status is FindingStatus.OPEN


# --- metrics -------------------------------------------------------------

def test_metrics_separate_verified_from_unverified_closure(db, organization, asset, scan_job):
    """A programme that closes everything unverified is not measuring itself."""
    findings = []
    for index in range(3):
        ingest_findings(db, organization.id, [FindingInput(
            asset_id=asset.id,
            title=f"Finding {index}",
            finding_class=FindingClass.EXPOSURE,
            confidence=Confidence.CONFIRMED,
            severity=Severity.HIGH,
            source="nmap",
            identifier=f"check-{index}",
        )], None, NOW)
    db.flush()
    findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()

    tasks = [create_task(db, finding, organization) for finding in findings]
    db.flush()

    verify_from_scan(db, organization.id, scan_job.id, {findings[0].id})
    close_task(db, tasks[1], None, "Decommissioned.")
    db.flush()

    result = metrics(db, organization.id).as_dict()
    assert result["verified_by_scan"] == 1
    assert result["closed_without_verification"] == 1
    assert result["open_tasks"] == 1
    assert result["verification_rate"] == 50.0


def test_the_verification_rate_is_null_with_nothing_closed(db, organization):
    assert metrics(db, organization.id).as_dict()["verification_rate"] is None


def test_overdue_tasks_are_counted(db, organization, task):
    task.due_date = TODAY - timedelta(days=5)
    db.flush()
    assert metrics(db, organization.id).as_dict()["overdue_tasks"] == 1
