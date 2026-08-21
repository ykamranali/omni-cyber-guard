"""
The single path by which a finding enters the database.

Every scanner, correlation job and manual entry goes through `upsert_finding`.
Centralising it is what makes these properties true everywhere rather than in
whichever code path last remembered them:

* A finding seen again is the *same* finding — `last_seen` and
  `occurrence_count` advance, `first_seen` does not move, and the row is not
  duplicated. "Open for 43 days" becomes a fact rather than an artefact of how
  often someone scanned.
* A finding that stops being observed is closed by evidence, not by assertion.
  `close_unseen_findings` marks rows a rescan no longer saw, recording which
  scan job established that.
* A finding never claims more than its evidence supports. `finding_class` and
  `confidence` are required arguments, so classifying a port-scan observation
  as a confirmed vulnerability has to be a deliberate act rather than a default.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import (
    CLOSED_STATUSES, Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.services.finding_identity import compute_fingerprint

MAX_EVIDENCE_CHARS = 8000


@dataclass
class FindingInput:
    """A normalized finding, ready to be persisted."""

    asset_id: uuid.UUID
    title: str
    finding_class: FindingClass
    confidence: Confidence
    severity: Severity
    source: str
    #: Stable identity for this check — a CVE ID, an nmap script ID, a nuclei
    #: template ID. Falls back to the title only when nothing better exists.
    identifier: str
    #: Where on the asset it was observed, e.g. "tcp/3389".
    location: str = ""
    description: str = ""
    evidence: str = ""
    remediation_guidance: str = ""
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_id: str | None = None
    affected_product: str | None = None
    affected_version: str | None = None
    asset_service_id: uuid.UUID | None = None


@dataclass
class IngestResult:
    created: int = 0
    updated: int = 0
    fingerprints: set[str] = field(default_factory=set)
    #: Findings that had been resolved and were observed again. A regression
    #: must reopen its remediation task rather than staying quietly closed.
    reopened_finding_ids: set[uuid.UUID] = field(default_factory=set)

    @property
    def total(self) -> int:
        return self.created + self.updated


def upsert_finding(
    db: Session,
    organization_id: uuid.UUID,
    payload: FindingInput,
    scan_job_id: uuid.UUID | None = None,
    observed_at: datetime | None = None,
) -> tuple[Finding, bool, bool]:
    """
    Create the finding, or update the existing one with the same identity.

    Returns (finding, created, reopened).
    """
    observed_at = observed_at or datetime.now(timezone.utc)

    fingerprint = compute_fingerprint(
        asset_id=payload.asset_id,
        finding_class=payload.finding_class,
        source=payload.source,
        identifier=payload.identifier or payload.title,
        location=payload.location,
    )

    existing = db.execute(
        select(Finding).where(
            Finding.asset_id == payload.asset_id,
            Finding.fingerprint == fingerprint,
        )
    ).scalar_one_or_none()

    evidence = (payload.evidence or "")[:MAX_EVIDENCE_CHARS]

    if existing is not None:
        # Observed again. Refresh what the current scan learned; leave the
        # human workflow fields (status, assignment, risk acceptance) alone —
        # a rescan is evidence, not a decision.
        existing.last_seen = observed_at
        existing.occurrence_count = (existing.occurrence_count or 1) + 1
        existing.scan_job_id = scan_job_id or existing.scan_job_id
        existing.evidence = evidence or existing.evidence
        existing.severity = payload.severity
        existing.confidence = payload.confidence
        existing.title = payload.title
        existing.description = payload.description or existing.description
        existing.remediation_guidance = payload.remediation_guidance or existing.remediation_guidance
        if payload.asset_service_id:
            existing.asset_service_id = payload.asset_service_id
        for attribute in (
            "cve_id", "cvss_score", "cvss_vector", "cwe_id",
            "affected_product", "affected_version",
        ):
            value = getattr(payload, attribute)
            if value is not None:
                setattr(existing, attribute, value)

        # A previously resolved finding that is observed again has reopened.
        # Silently leaving it closed would hide a regression.
        reopened = existing.status == FindingStatus.REMEDIATED
        if reopened:
            existing.status = FindingStatus.OPEN
            existing.resolved_at = None
            existing.resolved_by_scan_job_id = None

        db.add(existing)
        return existing, False, reopened

    finding = Finding(
        organization_id=organization_id,
        asset_id=payload.asset_id,
        asset_service_id=payload.asset_service_id,
        scan_job_id=scan_job_id,
        fingerprint=fingerprint,
        title=payload.title,
        description=payload.description,
        evidence=evidence,
        finding_class=payload.finding_class,
        confidence=payload.confidence,
        severity=payload.severity,
        status=FindingStatus.OPEN,
        remediation_guidance=payload.remediation_guidance,
        source=payload.source,
        cve_id=payload.cve_id,
        cvss_score=payload.cvss_score,
        cvss_vector=payload.cvss_vector,
        cwe_id=payload.cwe_id,
        affected_product=payload.affected_product,
        affected_version=payload.affected_version,
        first_seen=observed_at,
        last_seen=observed_at,
        occurrence_count=1,
    )
    db.add(finding)
    db.flush()
    return finding, True, False


def ingest_findings(
    db: Session,
    organization_id: uuid.UUID,
    payloads: list[FindingInput],
    scan_job_id: uuid.UUID | None = None,
    observed_at: datetime | None = None,
) -> IngestResult:
    """Persist a batch, reporting how many were new versus seen again."""
    result = IngestResult()
    for payload in payloads:
        finding, created, reopened = upsert_finding(
            db, organization_id, payload, scan_job_id, observed_at
        )
        result.fingerprints.add(finding.fingerprint)
        if created:
            result.created += 1
        else:
            result.updated += 1
        if reopened:
            result.reopened_finding_ids.add(finding.id)
    return result


def close_unseen_findings(
    db: Session,
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    source: str,
    seen_fingerprints: set[str],
    scan_job_id: uuid.UUID,
    observed_at: datetime | None = None,
) -> set[uuid.UUID]:
    """
    Mark findings this scan no longer observes as remediated.

    This is the only automatic path to REMEDIATED, and it is driven by
    evidence: the same source scanned the same asset and did not find it.

    Scope is limited to one source, because nmap not reporting something says
    nothing about what nuclei found. Findings an operator has judged — accepted
    risk, false positive — are left alone; a scanner's silence does not overturn
    a human decision.

    Returns the IDs of the findings closed, so the caller can verify the
    remediation tasks attached to them.
    """
    observed_at = observed_at or datetime.now(timezone.utc)

    candidates = db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.asset_id == asset_id,
            Finding.source == source,
            Finding.status.notin_(list(CLOSED_STATUSES)),
        )
    ).scalars().all()

    closed: set[uuid.UUID] = set()
    for finding in candidates:
        if finding.fingerprint in seen_fingerprints:
            continue
        finding.status = FindingStatus.REMEDIATED
        finding.resolved_at = observed_at
        finding.resolved_by_scan_job_id = scan_job_id
        db.add(finding)
        closed.add(finding.id)

    return closed
