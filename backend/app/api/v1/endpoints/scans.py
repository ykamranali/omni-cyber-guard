"""
Network scan API. Scans only ever target private/loopback ranges you're
authorized to assess — enforced in app/services/network_scanner.py before
any packet is sent. This platform has no offensive capability: it performs
authorized host/service discovery only, and turns the real results into
asset inventory + finding records.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
import asyncio
from app.services.websocket import manager

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.credential import CredentialProfile
from app.models.scan_job import ScanJob, ScanStatus, ScanType
from app.models.user import User
from app.scanners.manager import ScannerManager
from app.schemas.scan import ScanJobCreate, ScanJobOut
from app.services.network_scanner import validate_authorized_target, ScanAuthorizationError
from app.services.scan_authorization import AuthorizationError, assert_target_authorized
from app.services.audit import log_action

router = APIRouter(prefix="/scans", tags=["Network Scans"])


@router.get("", response_model=list[ScanJobOut])
def list_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    return (
        db.query(ScanJob)
        .filter(ScanJob.organization_id == current_user.organization_id)
        .order_by(ScanJob.created_at.desc())
        .limit(50)
        .all()
    )




@router.get("/engines")
def list_engines(
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    """
    What each scan engine is and whether it can actually run right now.

    Each adapter probes for its own tool, so an engine whose binary is missing
    reports `available: false` with the command that installs it. The Scan
    Center uses this to disable an engine and explain why, instead of offering
    one that would fail — or appearing to run one that does nothing.
    """
    return {"engines": ScannerManager.configuration_report()}


@router.post("", response_model=ScanJobOut, status_code=202)
def create_scan(
    payload: ScanJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    scanner = ScannerManager.get_scanner(payload.engine)
    if scanner is None:
        raise HTTPException(status_code=400, detail=f"Unknown scan engine '{payload.engine}'.")

    validation = scanner.validate_target(payload.target_cidr)
    if not validation.valid:
        raise HTTPException(status_code=400, detail=validation.reason)

    # Authorized scope, enforced rather than displayed.
    #
    # The syntactic check above rejects public ranges and oversized CIDRs. It
    # does not establish that this organization has any business assessing the
    # private range being asked for. `Network.is_authorized_scope` is the
    # record of consent, and until now nothing consulted it at launch — the
    # authorization endpoint existed but was advisory only.
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail=(
                "Confirm that you are authorized to assess this target before "
                "the scan can start."
            ),
        )
    try:
        authorization = assert_target_authorized(
            db,
            organization_id=current_user.organization_id,
            target=validation.normalized_target or payload.target_cidr,
        )
    except AuthorizationError as exc:
        log_action(
            db, "scan_refused_unauthorized_scope", "scan_job",
            current_user.organization_id, current_user.id, None,
            metadata={"target_cidr": payload.target_cidr, "reason": str(exc)},
        )
        raise HTTPException(status_code=403, detail=str(exc))

    # Only once the request is authorized is it worth asking whether the tool
    # is installed. Authorization is a question about the operator's right to
    # assess the target; it does not depend on this deployment's tooling, and
    # answering "the engine is missing" to an unauthorized request would tell
    # the caller less than it should.
    configuration = scanner.validate_configuration()
    if not configuration.available:
        raise HTTPException(
            status_code=409,
            detail=f"{configuration.summary} {configuration.remediation}".strip(),
        )

    credential_id = payload.credential_profile_id
    if credential_id is not None:
        owned = (
            db.query(CredentialProfile)
            .filter(
                CredentialProfile.id == credential_id,
                CredentialProfile.organization_id == current_user.organization_id,
            )
            .first()
        )
        if owned is None:
            raise HTTPException(status_code=404, detail="Credential profile not found.")
    elif scanner.requires_credential:
        raise HTTPException(
            status_code=400,
            detail=(
                f"The '{payload.engine}' engine performs a credentialed assessment and "
                f"requires a credential profile."
            ),
        )

    job = ScanJob(
        organization_id=current_user.organization_id,
        initiated_by_user_id=current_user.id,
        credential_profile_id=credential_id,
        target_cidr=validation.normalized_target or payload.target_cidr,
        scan_type=ScanType.PORT_SERVICE_SCAN,
        engine=payload.engine,
        status=ScanStatus.QUEUED,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Import locally to avoid importing Celery at API startup if the broker is
    # unreachable.
    from app.tasks.scan_tasks import run_network_scan

    try:
        run_network_scan.delay(str(job.id))
    except Exception as exc:  # noqa: BLE001 — broker down, auth failure, anything
        # A job that could not be handed to a worker must not sit at QUEUED
        # forever looking like it is about to start. This was the single most
        # confusing failure in the product: the row was committed, the dispatch
        # raised, and the Scan Centre showed "queued" indefinitely with nothing
        # anywhere saying why.
        job.status = ScanStatus.FAILED
        job.error_message = (
            f"The scan could not be handed to a worker: {exc}. "
            f"Check that the Celery worker and Redis are running "
            f"(docker compose ps worker redis)."
        )
        db.commit()
        db.refresh(job)
        raise HTTPException(status_code=503, detail=job.error_message)

    log_action(
        db, "start_scan", "scan_job", current_user.organization_id, current_user.id, str(job.id),
        metadata={
            "target_cidr": job.target_cidr,
            "engine": job.engine,
            "credentialed": credential_id is not None,
            "authorized_by_network": authorization.matched_network,
            "authorization_confirmed_by": str(current_user.id),
        },
    )

    # Notify via WebSocket in background.
    #
    # The organization id is stringified here on purpose: connections are keyed
    # by the `org_id` claim from the JWT, which is a string. Passing the UUID
    # object meant every lookup in the connection map missed, so this
    # notification was never delivered to anyone while the request reported
    # success.
    organization_key = str(current_user.organization_id)
    target = job.target_cidr

    def send_ws_notification():
        asyncio.run(manager.broadcast_to_org(
            organization_key,
            {"type": "info", "message": f"Scan initiated for {target}"},
        ))

    background_tasks.add_task(send_ws_notification)

    return job


@router.get("/{scan_id}", response_model=ScanJobOut)
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.organization_id == current_user.organization_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.post("/{scan_id}/cancel", response_model=ScanJobOut)
def cancel_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    """
    Request cancellation of a running scan.

    This sets `cancel_requested`; the worker polls it, terminates the scanner
    subprocess, and records the terminal status as CANCELED. A queued job that
    has not started is cancelled immediately.

    Previously this endpoint simply wrote status=FAILED with the message
    "Scan manually canceled by user" while nmap carried on running to
    completion — the platform reported an outcome that had not happened.
    """
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.organization_id == current_user.organization_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if job.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=409,
            detail=f"Scan is already in a terminal state ({job.status.value}) and cannot be cancelled.",
        )

    job.cancel_requested = True

    if job.status == ScanStatus.QUEUED:
        # Nothing has started yet, so this is immediately true.
        job.status = ScanStatus.CANCELED
        job.error_message = "Cancelled before the scan started."

    db.commit()
    db.refresh(job)

    log_action(db, "cancel_scan", "scan_job", current_user.organization_id, current_user.id, str(job.id))
    return job


@router.delete("/bulk")
def delete_scans_bulk(
    scan_ids: list[uuid.UUID],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    """
    Delete several scans, and report what actually happened.

    This returned 204 and silently skipped anything it could not delete, so
    selecting ten rows and pressing delete could remove none of them while
    looking like it had worked. It now says which were removed and why the
    rest were not.
    """
    jobs = (
        db.query(ScanJob)
        .filter(
            ScanJob.id.in_(scan_ids),
            ScanJob.organization_id == current_user.organization_id,
        )
        .all()
    )

    deleted: list[str] = []
    skipped: list[dict] = []

    for job in jobs:
        if job.status is ScanStatus.RUNNING:
            skipped.append({
                "id": str(job.id),
                "reason": "The scan is still running. Cancel it before deleting.",
            })
            continue
        # A queued job never started, so there is nothing to interrupt and no
        # reason to make the operator cancel it first.
        deleted.append(str(job.id))
        log_action(
            db, "delete_scan", "scan_job", current_user.organization_id,
            current_user.id, str(job.id), metadata={"status": job.status.value},
        )
        db.delete(job)

    db.commit()

    missing = sorted(
        {str(identifier) for identifier in scan_ids}
        - {str(job.id) for job in jobs}
    )
    for identifier in missing:
        skipped.append({"id": identifier, "reason": "No such scan in this organization."})

    return {"deleted": deleted, "skipped": skipped}

@router.delete("/{scan_id}", status_code=204)
def delete_scan(

    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.organization_id == current_user.organization_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    # A running scan has a live subprocess behind it, so it must be cancelled
    # first. A queued one never started — refusing to delete it forced a
    # pointless cancel step, and while jobs were stranded at QUEUED by an
    # absent worker it made them undeletable entirely.
    if job.status is ScanStatus.RUNNING:
        raise HTTPException(
            status_code=409,
            detail=(
                "This scan is still running. Cancel it first — the worker will "
                "stop the scanner process — then delete it."
            ),
        )

    log_action(
        db, "delete_scan", "scan_job", current_user.organization_id,
        current_user.id, str(job.id), metadata={"status": job.status.value},
    )
    db.delete(job)
    db.commit()

