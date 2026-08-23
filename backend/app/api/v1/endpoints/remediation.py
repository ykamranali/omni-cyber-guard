"""
Remediation API.

The route list is shaped by one rule: there is no endpoint that marks a task
verified. `mark-fixed` records that an engineer believes the work is done and
moves the task to AWAITING_VERIFICATION; only the scan pipeline can move it to
VERIFIED, and only by observing that the finding is gone.

Closing without verification is possible — an asset gets decommissioned, a
service is removed entirely — but it requires a reason, lands in CLOSED rather
than VERIFIED, and is counted separately in the metrics.
"""
from __future__ import annotations

import uuid
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.remediation import (
    TERMINAL_STATUSES, AcceptanceStatus, RemediationStatus, RemediationTask, RiskAcceptance,
)
from app.models.user import User
from app.schemas.remediation import (
    CloseTaskRequest, MarkFixedRequest, RemediationTaskCreate, RemediationTaskOut,
    RemediationTaskUpdate, RevokeAcceptanceRequest, RiskAcceptanceCreate, RiskAcceptanceOut,
    SlaPolicyUpdate,
)
from app.services.audit import log_action
from app.services.remediation_engine import (
    DEFAULT_SLA_DAYS, KNOWN_EXPLOITED_SLA_DAYS, RemediationError, accept_risk, assign_task,
    close_task, create_task, expire_lapsed_acceptances, mark_fixed, metrics, revoke_acceptance,
    sla_policy,
)

router = APIRouter(prefix="/remediation", tags=["Remediation"])


# ------------------------------------------------------------------- tasks

@router.get("/tasks", response_model=list[RemediationTaskOut])
def list_tasks(
    status: RemediationStatus | None = Query(default=None),
    assigned_to_me: bool = Query(default=False),
    overdue_only: bool = Query(default=False),
    open_only: bool = Query(default=True),
    search: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    query = select(RemediationTask).where(
        RemediationTask.organization_id == current_user.organization_id
    )
    if status:
        query = query.where(RemediationTask.status == status)
    elif open_only:
        query = query.where(RemediationTask.status.notin_(list(TERMINAL_STATUSES)))
    if assigned_to_me:
        query = query.where(RemediationTask.assigned_to_user_id == current_user.id)
    if overdue_only:
        query = query.where(
            RemediationTask.due_date < date.today(),
            RemediationTask.status.notin_(list(TERMINAL_STATUSES)),
        )
    if search:
        # Filtered server-side rather than in the browser, so the search box
        # narrows the whole queue and not just the page that happened to load.
        pattern = f"%{search.strip().lower()}%"
        query = query.where(
            func.lower(RemediationTask.title).like(pattern)
            | func.lower(RemediationTask.description).like(pattern)
        )

    tasks = db.execute(
        query.order_by(RemediationTask.due_date.asc().nullslast()).offset(offset).limit(limit)
    ).scalars().all()

    return [_serialize_task(db, task) for task in tasks]


@router.get("/metrics")
def remediation_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    """
    Remediation throughput.

    `verification_rate` is reported deliberately: a programme where most tasks
    close without a scan confirming them is not measuring its own work, and
    that should be visible rather than buried.
    """
    return metrics(db, current_user.organization_id).as_dict()


@router.post("/tasks", response_model=RemediationTaskOut, status_code=201)
def open_task(
    payload: RemediationTaskCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    finding = db.execute(
        select(Finding).where(
            Finding.id == payload.finding_id,
            Finding.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    organization = db.get(Organization, current_user.organization_id)

    try:
        task = create_task(
            db, finding, organization,
            created_by_user_id=current_user.id,
            assigned_to_user_id=payload.assigned_to_user_id,
            due_date=payload.due_date,
        )
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    db.commit()
    db.refresh(task)
    return _serialize_task(db, task)


@router.patch("/tasks/{task_id}", response_model=RemediationTaskOut)
def update_task(
    task_id: uuid.UUID,
    payload: RemediationTaskUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    task = _get_task(db, task_id, current_user)
    changes = payload.model_dump(exclude_unset=True)

    assignee = changes.pop("assigned_to_user_id", None)
    if assignee is not None:
        try:
            assign_task(db, task, assignee, current_user.id)
        except RemediationError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    for field, value in changes.items():
        setattr(task, field, value)

    db.commit()
    db.refresh(task)
    return _serialize_task(db, task)


@router.post("/tasks/{task_id}/mark-fixed", response_model=RemediationTaskOut)
def mark_task_fixed(
    task_id: uuid.UUID,
    payload: MarkFixedRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    """
    Record that the work is believed done.

    This does not close the finding. The task moves to AWAITING_VERIFICATION and
    stays there until a scan of the same asset by the same source no longer sees
    the finding. Closing on an assertion would mean the platform reports
    remediation it has not observed.
    """
    task = _get_task(db, task_id, current_user)
    try:
        mark_fixed(db, task, current_user.id, payload.note)
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    db.commit()
    db.refresh(task)
    return _serialize_task(db, task)


@router.post("/tasks/{task_id}/close", response_model=RemediationTaskOut)
def close_without_verification(
    task_id: uuid.UUID,
    payload: CloseTaskRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    """Close a task that a scan cannot verify — a decommissioned asset, say."""
    task = _get_task(db, task_id, current_user)
    try:
        close_task(db, task, current_user.id, payload.reason)
    except RemediationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    db.commit()
    db.refresh(task)
    return _serialize_task(db, task)


# -------------------------------------------------------- risk acceptance

@router.get("/risk-acceptances", response_model=list[RiskAcceptanceOut])
def list_acceptances(
    status: AcceptanceStatus | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    # Lapsed acceptances are expired on read as well as on a schedule, so a
    # stale one is never displayed as active.
    expire_lapsed_acceptances(db, current_user.organization_id)
    db.commit()

    query = select(RiskAcceptance).where(
        RiskAcceptance.organization_id == current_user.organization_id
    )
    if status:
        query = query.where(RiskAcceptance.status == status)

    acceptances = db.execute(
        query.order_by(RiskAcceptance.expires_at.asc())
    ).scalars().all()
    return [_serialize_acceptance(db, acceptance) for acceptance in acceptances]


@router.post("/risk-acceptances", response_model=RiskAcceptanceOut, status_code=201)
def create_acceptance(
    payload: RiskAcceptanceCreate,
    db: Session = Depends(get_db),
    # Accepting risk is a governance decision, so it needs the compliance
    # permission rather than the one that lets an analyst change a status.
    current_user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
):
    finding = db.execute(
        select(Finding).where(
            Finding.id == payload.finding_id,
            Finding.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        acceptance = accept_risk(
            db, finding,
            reason=payload.reason,
            expires_at=payload.expires_at,
            approved_by_user_id=current_user.id,
            requested_by_user_id=current_user.id,
            compensating_controls=payload.compensating_controls,
        )
    except RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    db.commit()
    db.refresh(acceptance)
    return _serialize_acceptance(db, acceptance)


@router.post("/risk-acceptances/{acceptance_id}/revoke", response_model=RiskAcceptanceOut)
def revoke(
    acceptance_id: uuid.UUID,
    payload: RevokeAcceptanceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
):
    acceptance = db.execute(
        select(RiskAcceptance).where(
            RiskAcceptance.id == acceptance_id,
            RiskAcceptance.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if acceptance is None:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    if acceptance.status is not AcceptanceStatus.ACTIVE:
        raise HTTPException(status_code=409, detail=f"This acceptance is already {acceptance.status.value}.")

    revoke_acceptance(db, acceptance, current_user.id, payload.reason)
    db.commit()
    db.refresh(acceptance)
    return _serialize_acceptance(db, acceptance)


# -------------------------------------------------------------- SLA policy

@router.get("/sla-policy")
def get_sla_policy(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    organization = db.get(Organization, current_user.organization_id)
    policy = sla_policy(organization)
    return {
        "windows_in_days": {severity.value: days for severity, days in policy.items()},
        "defaults": {severity.value: days for severity, days in DEFAULT_SLA_DAYS.items()},
        "using_defaults": not (organization.sla_policy if organization else {}),
        "known_exploited_override_days": KNOWN_EXPLOITED_SLA_DAYS,
        "note": (
            f"A finding listed in the CISA KEV catalogue is given {KNOWN_EXPLOITED_SLA_DAYS} days "
            f"regardless of its CVSS score — observed exploitation outranks theoretical severity."
        ),
    }


@router.put("/sla-policy")
def update_sla_policy(
    payload: SlaPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORG_SETTINGS)),
):
    organization = db.get(Organization, current_user.organization_id)
    windows = {key: value for key, value in payload.model_dump(exclude_none=True).items()}
    organization.sla_policy = windows
    db.commit()

    log_action(
        db, "update_sla_policy", "organization", current_user.organization_id,
        current_user.id, str(organization.id), metadata={"windows": windows},
    )
    # Existing due dates are intentionally left alone: retroactively changing
    # them would rewrite whether past work was on time.
    return {
        "windows_in_days": {
            severity.value: days for severity, days in sla_policy(organization).items()
        },
        "note": "Existing tasks keep the due dates they were created with.",
    }


# ---------------------------------------------------------------- helpers

def _get_task(db: Session, task_id: uuid.UUID, current_user: User) -> RemediationTask:
    task = db.execute(
        select(RemediationTask).where(
            RemediationTask.id == task_id,
            RemediationTask.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if task is None:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    return task


def _serialize_task(db: Session, task: RemediationTask) -> RemediationTaskOut:
    out = RemediationTaskOut.model_validate(task)
    out.is_overdue = task.is_overdue
    out.days_until_due = (task.due_date - date.today()).days if task.due_date else None

    finding = db.get(Finding, task.finding_id)
    if finding is not None:
        out.finding_severity = finding.severity
        out.finding_cve_id = finding.cve_id

    if task.asset_id:
        asset = db.get(Asset, task.asset_id)
        if asset is not None:
            out.asset_hostname = asset.hostname

    if task.assigned_to_user_id:
        user = db.get(User, task.assigned_to_user_id)
        if user is not None:
            out.assigned_to_name = user.full_name

    return out


def _serialize_acceptance(db: Session, acceptance: RiskAcceptance) -> RiskAcceptanceOut:
    out = RiskAcceptanceOut.model_validate(acceptance)
    out.days_until_expiry = (acceptance.expires_at - date.today()).days

    finding = db.get(Finding, acceptance.finding_id)
    if finding is not None:
        out.finding_title = finding.title

    if acceptance.approved_by_user_id:
        user = db.get(User, acceptance.approved_by_user_id)
        if user is not None:
            out.approved_by_name = user.full_name

    return out
