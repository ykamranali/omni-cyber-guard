"""
Remediation workflow.

The load-bearing distinction in this module is between *fixed* and *verified*.

FIXED is a person saying they did the work. VERIFIED is a scan running again
and no longer observing the finding. Treating those as the same thing is how a
security programme ends up reporting remediation that never happened — and it
is the one behaviour your §56 calls out explicitly. Nothing here moves a task to
VERIFIED except a scan.

Risk acceptance is handled as a governance act rather than a status: a reason, a
named approver, and an expiry. When the expiry passes, the finding reopens.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.finding import CLOSED_STATUSES, Finding, FindingStatus, Severity
from app.models.remediation import (
    TERMINAL_STATUSES, AcceptanceStatus, RemediationPriority, RemediationStatus,
    RemediationTask, RiskAcceptance,
)
from app.services.audit import log_action

#: Default remediation windows in days, by severity. Deliberately close to the
#: shapes most policies use; overridable per organization.
DEFAULT_SLA_DAYS: dict[Severity, int] = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: 365,
}

#: Findings CISA lists as exploited get the shortest window regardless of CVSS —
#: "being attacked today" outranks "theoretically severe".
KNOWN_EXPLOITED_SLA_DAYS = 3

PRIORITY_BY_SEVERITY: dict[Severity, RemediationPriority] = {
    Severity.CRITICAL: RemediationPriority.URGENT,
    Severity.HIGH: RemediationPriority.HIGH,
    Severity.MEDIUM: RemediationPriority.MEDIUM,
    Severity.LOW: RemediationPriority.LOW,
    Severity.INFO: RemediationPriority.LOW,
}


class RemediationError(RuntimeError):
    """Raised when a workflow transition is not permitted."""


def sla_policy(organization) -> dict[Severity, int]:
    """Load an organization's SLA windows, falling back to the defaults."""
    overrides = (getattr(organization, "sla_policy", None) or {}) if organization else {}
    policy = dict(DEFAULT_SLA_DAYS)
    for severity in Severity:
        value = overrides.get(severity.value)
        if isinstance(value, int) and value > 0:
            policy[severity] = value
    return policy


def due_date_for(finding: Finding, policy: dict[Severity, int], opened_on: date | None = None) -> tuple[date, int]:
    """Return the due date and the SLA window it came from."""
    opened_on = opened_on or date.today()
    days = KNOWN_EXPLOITED_SLA_DAYS if finding.is_known_exploited else policy[finding.severity]
    return opened_on + timedelta(days=days), days


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------

def create_task(
    db: Session,
    finding: Finding,
    organization,
    created_by_user_id: uuid.UUID | None = None,
    assigned_to_user_id: uuid.UUID | None = None,
    due_date: date | None = None,
) -> RemediationTask:
    """
    Open a remediation task for a finding.

    Refuses to create work for a finding that is already closed — there is
    nothing to remediate, and a task against it would sit in the queue forever.
    """
    if finding.status in CLOSED_STATUSES:
        raise RemediationError(
            f"{finding.title} is already {finding.status.value.replace('_', ' ')}; "
            f"there is nothing to remediate."
        )

    existing = db.execute(
        select(RemediationTask).where(
            RemediationTask.finding_id == finding.id,
            RemediationTask.status.notin_(list(TERMINAL_STATUSES)),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise RemediationError(
            f"An open remediation task already exists for this finding "
            f"({existing.status.value.replace('_', ' ')})."
        )

    policy = sla_policy(organization)
    computed_due, sla_days = due_date_for(finding, policy)

    task = RemediationTask(
        organization_id=finding.organization_id,
        finding_id=finding.id,
        asset_id=finding.asset_id,
        title=finding.title[:500],
        description=finding.remediation_guidance or finding.description,
        status=RemediationStatus.ASSIGNED if assigned_to_user_id else RemediationStatus.OPEN,
        priority=PRIORITY_BY_SEVERITY[finding.severity],
        assigned_to_user_id=assigned_to_user_id,
        created_by_user_id=created_by_user_id,
        due_date=due_date or computed_due,
        sla_days=sla_days,
    )
    db.add(task)
    db.flush()

    # The finding reflects that work has started, so the two views agree.
    if finding.status == FindingStatus.OPEN:
        finding.status = (
            FindingStatus.IN_PROGRESS if assigned_to_user_id else FindingStatus.ACKNOWLEDGED
        )
        db.add(finding)

    log_action(
        db, "create", "remediation_task", finding.organization_id, created_by_user_id,
        str(task.id),
        metadata={"finding_id": str(finding.id), "due_date": task.due_date.isoformat()},
    )
    return task


def assign_task(
    db: Session, task: RemediationTask, user_id: uuid.UUID, actor_user_id: uuid.UUID | None = None
) -> RemediationTask:
    if task.status in TERMINAL_STATUSES:
        raise RemediationError(f"This task is {task.status.value} and cannot be reassigned.")

    task.assigned_to_user_id = user_id
    if task.status is RemediationStatus.OPEN:
        task.status = RemediationStatus.ASSIGNED
    db.add(task)

    log_action(
        db, "assign", "remediation_task", task.organization_id, actor_user_id, str(task.id),
        metadata={"assigned_to": str(user_id)},
    )
    return task


def mark_fixed(
    db: Session, task: RemediationTask, actor_user_id: uuid.UUID | None = None, note: str = ""
) -> RemediationTask:
    """
    Record that an engineer believes the work is done.

    This deliberately does **not** close the task or resolve the finding. The
    finding stays open until a scan stops seeing it. A platform that closes on
    an assertion reports remediation it has not observed.
    """
    if task.status in TERMINAL_STATUSES:
        raise RemediationError(f"This task is already {task.status.value}.")

    task.status = RemediationStatus.AWAITING_VERIFICATION
    task.fixed_at = datetime.now(timezone.utc)
    if note:
        task.notes = (task.notes + "\n" if task.notes else "") + note
    db.add(task)

    log_action(
        db, "mark_fixed", "remediation_task", task.organization_id, actor_user_id, str(task.id),
        metadata={"awaiting_verification": True},
    )
    return task


def verify_task(
    db: Session, task: RemediationTask, scan_job_id: uuid.UUID, verified_at: datetime | None = None
) -> RemediationTask:
    """
    Confirm remediation from scan evidence.

    Only called by the scan pipeline. There is no API route that reaches it,
    because "verified" has to mean a scan established it.
    """
    task.status = RemediationStatus.VERIFIED
    task.verified_at = verified_at or datetime.now(timezone.utc)
    task.verified_by_scan_job_id = scan_job_id
    task.closed_at = task.verified_at
    db.add(task)

    log_action(
        db, "verified", "remediation_task", task.organization_id, None, str(task.id),
        metadata={"verified_by_scan_job": str(scan_job_id)},
    )
    return task


def close_task(
    db: Session, task: RemediationTask, actor_user_id: uuid.UUID | None, reason: str
) -> RemediationTask:
    """
    Close a task without scan verification.

    Sometimes legitimate — the asset was decommissioned, the service was removed
    entirely — so it is permitted, but it requires a reason and is recorded as
    CLOSED rather than VERIFIED. The two are not interchangeable in any report.
    """
    if not reason.strip():
        raise RemediationError(
            "Closing a task without scan verification requires a reason. Use 'mark fixed' "
            "and let a rescan verify it where that is possible."
        )

    task.status = RemediationStatus.CLOSED
    task.closed_at = datetime.now(timezone.utc)
    task.notes = (task.notes + "\n" if task.notes else "") + f"Closed without verification: {reason}"
    db.add(task)

    log_action(
        db, "close_unverified", "remediation_task", task.organization_id, actor_user_id,
        str(task.id), metadata={"reason": reason},
    )
    return task


def reopen_task(db: Session, task: RemediationTask, reason: str) -> RemediationTask:
    """Reopen a task whose finding was observed again."""
    task.status = RemediationStatus.IN_PROGRESS
    task.verified_at = None
    task.verified_by_scan_job_id = None
    task.closed_at = None
    task.notes = (task.notes + "\n" if task.notes else "") + f"Reopened: {reason}"
    db.add(task)
    return task


def verify_from_scan(
    db: Session, organization_id: uuid.UUID, scan_job_id: uuid.UUID, resolved_finding_ids: set[uuid.UUID]
) -> int:
    """
    Close out tasks whose findings a scan no longer observes.

    Called by the scan pipeline after `close_unseen_findings`. This is the only
    path to VERIFIED.
    """
    if not resolved_finding_ids:
        return 0

    tasks = db.execute(
        select(RemediationTask).where(
            RemediationTask.organization_id == organization_id,
            RemediationTask.finding_id.in_(sorted(resolved_finding_ids)),
            RemediationTask.status.notin_(list(TERMINAL_STATUSES)),
        )
    ).scalars().all()

    now = datetime.now(timezone.utc)
    for task in tasks:
        verify_task(db, task, scan_job_id, now)
    return len(tasks)


def reopen_from_scan(
    db: Session, organization_id: uuid.UUID, reopened_finding_ids: set[uuid.UUID]
) -> int:
    """Reopen tasks whose findings came back. A regression must not stay hidden."""
    if not reopened_finding_ids:
        return 0

    tasks = db.execute(
        select(RemediationTask).where(
            RemediationTask.organization_id == organization_id,
            RemediationTask.finding_id.in_(sorted(reopened_finding_ids)),
            RemediationTask.status == RemediationStatus.VERIFIED,
        )
    ).scalars().all()

    for task in tasks:
        reopen_task(db, task, "The finding was observed again by a later scan.")
    return len(tasks)


# ---------------------------------------------------------------------------
# Risk acceptance
# ---------------------------------------------------------------------------

def accept_risk(
    db: Session,
    finding: Finding,
    reason: str,
    expires_at: date,
    approved_by_user_id: uuid.UUID,
    requested_by_user_id: uuid.UUID | None = None,
    compensating_controls: str = "",
) -> RiskAcceptance:
    """
    Record a decision to live with a finding until a stated date.

    An acceptance with no expiry is indistinguishable from having forgotten
    about it, so an expiry is required and must be in the future.
    """
    if not reason.strip():
        raise RemediationError("Accepting a risk requires a reason.")
    if expires_at <= date.today():
        raise RemediationError("A risk acceptance must expire on a future date.")

    existing = db.execute(
        select(RiskAcceptance).where(
            RiskAcceptance.finding_id == finding.id,
            RiskAcceptance.status == AcceptanceStatus.ACTIVE,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise RemediationError(
            f"This finding already has an active risk acceptance expiring "
            f"{existing.expires_at.isoformat()}."
        )

    acceptance = RiskAcceptance(
        organization_id=finding.organization_id,
        finding_id=finding.id,
        reason=reason,
        compensating_controls=compensating_controls,
        requested_by_user_id=requested_by_user_id,
        approved_by_user_id=approved_by_user_id,
        approved_at=datetime.now(timezone.utc),
        expires_at=expires_at,
    )
    db.add(acceptance)

    finding.status = FindingStatus.ACCEPTED_RISK
    db.add(finding)
    db.flush()

    log_action(
        db, "accept_risk", "finding", finding.organization_id, approved_by_user_id,
        str(finding.id),
        metadata={
            "acceptance_id": str(acceptance.id),
            "expires_at": expires_at.isoformat(),
            "reason": reason[:500],
        },
    )
    return acceptance


def revoke_acceptance(
    db: Session, acceptance: RiskAcceptance, actor_user_id: uuid.UUID, reason: str
) -> RiskAcceptance:
    """Withdraw an acceptance early. The finding returns to open."""
    acceptance.status = AcceptanceStatus.REVOKED
    acceptance.revoked_by_user_id = actor_user_id
    acceptance.revoked_at = datetime.now(timezone.utc)
    acceptance.revocation_reason = reason
    db.add(acceptance)

    finding = db.get(Finding, acceptance.finding_id)
    if finding is not None and finding.status == FindingStatus.ACCEPTED_RISK:
        finding.status = FindingStatus.OPEN
        db.add(finding)

    log_action(
        db, "revoke_risk_acceptance", "finding", acceptance.organization_id, actor_user_id,
        str(acceptance.finding_id), metadata={"reason": reason[:500]},
    )
    return acceptance


def expire_lapsed_acceptances(db: Session, organization_id: uuid.UUID | None = None) -> int:
    """
    Reopen findings whose acceptance has lapsed.

    This is what makes the expiry date mean something. Without it, "accepted
    until March" silently becomes "accepted forever".
    """
    query = select(RiskAcceptance).where(
        RiskAcceptance.status == AcceptanceStatus.ACTIVE,
        RiskAcceptance.expires_at < date.today(),
    )
    if organization_id:
        query = query.where(RiskAcceptance.organization_id == organization_id)

    lapsed = db.execute(query).scalars().all()

    for acceptance in lapsed:
        acceptance.status = AcceptanceStatus.EXPIRED
        db.add(acceptance)

        finding = db.get(Finding, acceptance.finding_id)
        if finding is not None and finding.status == FindingStatus.ACCEPTED_RISK:
            finding.status = FindingStatus.OPEN
            db.add(finding)

        log_action(
            db, "risk_acceptance_expired", "finding", acceptance.organization_id, None,
            str(acceptance.finding_id),
            metadata={"expired_on": acceptance.expires_at.isoformat()},
        )

    return len(lapsed)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

@dataclass
class RemediationMetrics:
    open_tasks: int = 0
    overdue_tasks: int = 0
    awaiting_verification: int = 0
    verified_by_scan: int = 0
    closed_without_verification: int = 0
    active_risk_acceptances: int = 0
    expiring_acceptances: int = 0

    def as_dict(self) -> dict:
        return {
            "open_tasks": self.open_tasks,
            "overdue_tasks": self.overdue_tasks,
            "awaiting_verification": self.awaiting_verification,
            "verified_by_scan": self.verified_by_scan,
            "closed_without_verification": self.closed_without_verification,
            "active_risk_acceptances": self.active_risk_acceptances,
            "expiring_acceptances": self.expiring_acceptances,
            # Reported separately, and deliberately: a programme where most
            # tasks close without verification is not measuring its own work.
            "verification_rate": (
                round(
                    self.verified_by_scan
                    / (self.verified_by_scan + self.closed_without_verification) * 100,
                    1,
                )
                if (self.verified_by_scan + self.closed_without_verification)
                else None
            ),
        }


def metrics(db: Session, organization_id: uuid.UUID) -> RemediationMetrics:
    result = RemediationMetrics()
    today = date.today()

    def count(*conditions) -> int:
        return db.execute(
            select(func.count(RemediationTask.id)).where(
                RemediationTask.organization_id == organization_id, *conditions
            )
        ).scalar_one()

    result.open_tasks = count(RemediationTask.status.notin_(list(TERMINAL_STATUSES)))
    result.overdue_tasks = count(
        RemediationTask.status.notin_(list(TERMINAL_STATUSES)),
        RemediationTask.due_date < today,
    )
    result.awaiting_verification = count(RemediationTask.status == RemediationStatus.AWAITING_VERIFICATION)
    result.verified_by_scan = count(RemediationTask.status == RemediationStatus.VERIFIED)
    result.closed_without_verification = count(RemediationTask.status == RemediationStatus.CLOSED)

    result.active_risk_acceptances = db.execute(
        select(func.count(RiskAcceptance.id)).where(
            RiskAcceptance.organization_id == organization_id,
            RiskAcceptance.status == AcceptanceStatus.ACTIVE,
        )
    ).scalar_one()
    result.expiring_acceptances = db.execute(
        select(func.count(RiskAcceptance.id)).where(
            RiskAcceptance.organization_id == organization_id,
            RiskAcceptance.status == AcceptanceStatus.ACTIVE,
            RiskAcceptance.expires_at <= today + timedelta(days=30),
        )
    ).scalar_one()

    return result
