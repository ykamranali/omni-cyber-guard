"""
Network scan API. Scans only ever target private/loopback ranges you're
authorized to assess — enforced in app/services/network_scanner.py before
any packet is sent. This platform has no offensive capability: it performs
authorized host/service discovery only, and turns the real results into
asset inventory + finding records.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.scan_job import ScanJob, ScanStatus, ScanType
from app.models.user import User
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


@router.post("", response_model=ScanJobOut, status_code=202)
def create_scan(
    payload: ScanJobCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    try:
        validate_authorized_target(payload.target_cidr)
    except ScanAuthorizationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    job = ScanJob(
        organization_id=current_user.organization_id,
        initiated_by_user_id=current_user.id,
        target_cidr=payload.target_cidr,
        scan_type=ScanType.PORT_SERVICE_SCAN,
        status=ScanStatus.QUEUED,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Import locally to avoid importing Celery at API startup if the broker is unreachable
    from app.tasks.scan_tasks import run_network_scan
    run_network_scan.delay(str(job.id))

    log_action(db, "start_scan", "scan_job", current_user.organization_id, current_user.id, str(job.id),
               metadata={"target_cidr": payload.target_cidr})
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
    job = (
        db.query(ScanJob)
        .filter(ScanJob.id == scan_id, ScanJob.organization_id == current_user.organization_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if job.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        job.status = ScanStatus.FAILED
        job.error_message = "Scan manually canceled by user."
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

