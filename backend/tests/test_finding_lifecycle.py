"""
Finding lifecycle: deduplication, reopening, and evidence-based resolution.

These are the properties that make finding counts and ageing trustworthy. If
a rescan duplicates findings, every metric in the platform inflates. If it
never closes anything, remediation is invisible. If it closes things it merely
did not look at, the platform reports work that was never done.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.models.finding import Confidence, Finding, FindingClass, FindingStatus, Severity
from app.services.finding_ingest import (
    FindingInput, close_unseen_findings, ingest_findings, upsert_finding,
)

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=3)


def _payload(asset, **overrides):
    base = dict(
        asset_id=asset.id,
        title="Exposed RDP service on port 3389",
        finding_class=FindingClass.EXPOSURE,
        confidence=Confidence.CONFIRMED,
        severity=Severity.HIGH,
        source="nmap",
        identifier="exposed-port-3389",
        location="tcp/3389",
        evidence="nmap: tcp/3389 open, service=ms-wbt-server",
    )
    base.update(overrides)
    return FindingInput(**base)


# --- deduplication -------------------------------------------------------

def test_first_observation_creates_a_finding(db, organization, asset, scan_job):
    finding, created, _ = upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    assert created
    assert finding.occurrence_count == 1
    assert finding.first_seen == NOW
    assert finding.last_seen == NOW
    assert finding.status == FindingStatus.OPEN


def test_second_observation_updates_rather_than_duplicates(db, organization, asset, scan_job):
    upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    finding, created, _ = upsert_finding(db, organization.id, _payload(asset), scan_job.id, LATER)
    db.flush()

    assert not created
    assert db.query(Finding).filter(Finding.asset_id == asset.id).count() == 1
    assert finding.occurrence_count == 2
    # first_seen is the answer to "how long has this been open" and must not move.
    assert finding.first_seen == NOW
    assert finding.last_seen == LATER


def test_rewording_a_finding_does_not_duplicate_it(db, organization, asset, scan_job):
    upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    upsert_finding(
        db, organization.id,
        _payload(asset, title="Remote Desktop exposed on 3389", severity=Severity.CRITICAL),
        scan_job.id, LATER,
    )
    db.flush()

    findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
    assert len(findings) == 1
    # The newest observation wins for mutable attributes.
    assert findings[0].title == "Remote Desktop exposed on 3389"
    assert findings[0].severity == Severity.CRITICAL


def test_same_check_on_two_ports_stays_two_findings(db, organization, asset, scan_job):
    ingest_findings(db, organization.id, [
        _payload(asset, location="tcp/3389", identifier="exposed-port-3389"),
        _payload(asset, location="tcp/3390", identifier="exposed-port-3390"),
    ], scan_job.id, NOW)
    db.flush()
    assert db.query(Finding).filter(Finding.asset_id == asset.id).count() == 2


def test_ingest_reports_created_versus_seen_again(db, organization, asset, scan_job):
    first = ingest_findings(db, organization.id, [_payload(asset)], scan_job.id, NOW)
    second = ingest_findings(db, organization.id, [_payload(asset)], scan_job.id, LATER)

    assert (first.created, first.updated) == (1, 0)
    assert (second.created, second.updated) == (0, 1)


# --- workflow preservation ----------------------------------------------

def test_rescan_does_not_overturn_a_human_decision(db, organization, asset, scan_job):
    """An operator's risk acceptance survives the finding being seen again."""
    finding, _, _ = upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    finding.status = FindingStatus.ACCEPTED_RISK
    db.flush()

    upsert_finding(db, organization.id, _payload(asset), scan_job.id, LATER)
    db.flush()
    assert finding.status == FindingStatus.ACCEPTED_RISK


def test_a_resolved_finding_that_reappears_is_reopened(db, organization, asset, scan_job):
    """A regression must not stay hidden behind a stale 'remediated' status."""
    finding, _, _ = upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    finding.status = FindingStatus.REMEDIATED
    finding.resolved_at = NOW
    finding.resolved_by_scan_job_id = scan_job.id
    db.flush()

    upsert_finding(db, organization.id, _payload(asset), scan_job.id, LATER)
    db.flush()

    assert finding.status == FindingStatus.OPEN
    assert finding.resolved_at is None
    assert finding.resolved_by_scan_job_id is None


# --- evidence-based resolution ------------------------------------------

def test_a_finding_the_rescan_no_longer_sees_is_resolved(db, organization, asset, scan_job):
    ingest = ingest_findings(db, organization.id, [_payload(asset)], scan_job.id, NOW)
    db.flush()

    # The next scan of the same asset by the same source finds nothing.
    closed = close_unseen_findings(
        db, organization.id, asset.id, "nmap", set(), scan_job.id, LATER
    )
    db.flush()

    assert len(closed) == 1
    finding = db.query(Finding).filter(Finding.asset_id == asset.id).one()
    assert finding.status == FindingStatus.REMEDIATED
    assert finding.resolved_at == LATER
    assert finding.resolved_by_scan_job_id == scan_job.id
    assert ingest.created == 1


def test_a_finding_the_rescan_still_sees_stays_open(db, organization, asset, scan_job):
    ingest = ingest_findings(db, organization.id, [_payload(asset)], scan_job.id, NOW)
    db.flush()

    closed = close_unseen_findings(
        db, organization.id, asset.id, "nmap", ingest.fingerprints, scan_job.id, LATER
    )
    db.flush()

    assert closed == set()
    assert db.query(Finding).one().status == FindingStatus.OPEN


def test_one_scanner_silence_does_not_close_another_scanners_findings(db, organization, asset, scan_job):
    """nmap not reporting something says nothing about what nuclei found."""
    ingest_findings(db, organization.id, [_payload(asset, source="nuclei")], scan_job.id, NOW)
    db.flush()

    closed = close_unseen_findings(
        db, organization.id, asset.id, "nmap", set(), scan_job.id, LATER
    )
    db.flush()

    assert closed == set()
    assert db.query(Finding).one().status == FindingStatus.OPEN


@pytest.mark.parametrize("status", [FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE])
def test_operator_closed_findings_are_left_alone(db, organization, asset, scan_job, status):
    finding, _, _ = upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    finding.status = status
    db.flush()

    closed = close_unseen_findings(
        db, organization.id, asset.id, "nmap", set(), scan_job.id, LATER
    )
    db.flush()

    assert closed == set()
    assert finding.status == status


# --- honesty of classification ------------------------------------------

def test_an_open_port_is_recorded_as_an_exposure_not_a_vulnerability(db, organization, asset, scan_job):
    finding, _, _ = upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    assert finding.finding_class == FindingClass.EXPOSURE


def test_evidence_is_stored_verbatim(db, organization, asset, scan_job):
    finding, _, _ = upsert_finding(db, organization.id, _payload(asset), scan_job.id, NOW)
    assert finding.evidence == "nmap: tcp/3389 open, service=ms-wbt-server"


def test_evidence_is_capped(db, organization, asset, scan_job):
    finding, _, _ = upsert_finding(
        db, organization.id, _payload(asset, evidence="x" * 50_000), scan_job.id, NOW
    )
    assert len(finding.evidence) == 8000
