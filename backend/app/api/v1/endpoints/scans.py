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

    # Reject at the edge rather than queueing work that is certain to fail.
    configuration = scanner.validate_configuration()
    if not configuration.available:
        raise HTTPException(
            status_code=409,
            detail=f"{configuration.summary} {configuration.remediation}".strip(),
        )

    validation = scanner.validate_target(payload.target_cidr)
    if not validation.valid:
        raise HTTPException(status_code=400, detail=validation.reason)

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

    # Import locally to avoid importing Celery at API startup if the broker is unreachable
    from app.tasks.scan_tasks import run_network_scan
    run_network_scan.delay(str(job.id))

    log_action(
        db, "start_scan", "scan_job", current_user.organization_id, current_user.id, str(job.id),
        metadata={
            "target_cidr": job.target_cidr,
            "engine": job.engine,
            "credentialed": credential_id is not None,
        },
    )

    # Notify via WebSocket in background
    def send_ws_notification():
        asyncio.run(manager.broadcast_to_org(
            current_user.organization_id, 
            {"type": "info", "message": f"Scan initiated for {payload.target_cidr}"}
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


@router.delete("/bulk", status_code=204)
def delete_scans_bulk(
    scan_ids: list[uuid.UUID],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    jobs = (
        db.query(ScanJob)
        .filter(ScanJob.id.in_(scan_ids), ScanJob.organization_id == current_user.organization_id)
        .all()
    )
    for job in jobs:
        if job.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            db.delete(job)
            log_action(db, "delete_scan", "scan_job", current_user.organization_id, current_user.id, str(job.id))
    db.commit()

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

    if job.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Cannot delete a scan that is currently running or queued. Cancel it first.")

    db.delete(job)
    db.commit()
    log_action(db, "delete_scan", "scan_job", current_user.organization_id, current_user.id, str(job.id))

