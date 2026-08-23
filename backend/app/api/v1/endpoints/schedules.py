import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from croniter import croniter

from app.db.session import get_db
from app.core.deps import require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.scan_schedule import ScanSchedule
from app.schemas.scan_schedule import ScanScheduleCreate, ScanScheduleUpdate, ScanScheduleResponse
from app.services.audit import log_action
from app.services.scan_authorization import AuthorizationError, assert_target_authorized

router = APIRouter()

@router.get("/", response_model=list[ScanScheduleResponse])
def list_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    """
    List all scan schedules for the current organization.
    """
    schedules = db.query(ScanSchedule).filter(
        ScanSchedule.organization_id == current_user.organization_id
    ).all()
    return schedules

@router.post("/", response_model=ScanScheduleResponse)
def create_schedule(
    schedule_in: ScanScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    """
    Create a recurring scan schedule.

    The target is validated against declared authorized scope here, not only
    when the schedule eventually fires. Previously the only validation was
    `croniter.is_valid` on the cron string — any CIDR whatsoever could be
    saved, and the range check happened much later inside the worker, so an
    unauthorized schedule could be created, displayed as active, and fail
    invisibly every night.
    """
    if not croniter.is_valid(schedule_in.cron_expression):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    try:
        authorization = assert_target_authorized(
            db,
            organization_id=current_user.organization_id,
            target=schedule_in.target_cidr,
        )
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    schedule = ScanSchedule(
        organization_id=current_user.organization_id,
        created_by_user_id=current_user.id,
        **schedule_in.model_dump()
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    log_action(
        db, "create", "scan_schedule", current_user.organization_id, current_user.id,
        str(schedule.id),
        metadata={
            "target_cidr": schedule.target_cidr,
            "cron": schedule.cron_expression,
            "authorized_by_network": authorization.matched_network,
        },
    )
    return schedule

@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(
    schedule_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    schedule = db.query(ScanSchedule).filter(
        ScanSchedule.id == schedule_id,
        ScanSchedule.organization_id == current_user.organization_id
    ).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
        
    db.delete(schedule)
    db.commit()
    log_action(
        db, "delete", "scan_schedule", current_user.organization_id, current_user.id,
        str(schedule_id),
    )
    return None

@router.patch("/{schedule_id}", response_model=ScanScheduleResponse)
def update_schedule(
    schedule_id: uuid.UUID,
    schedule_in: ScanScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
):
    schedule = db.query(ScanSchedule).filter(
        ScanSchedule.id == schedule_id,
        ScanSchedule.organization_id == current_user.organization_id
    ).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
        
    if schedule_in.cron_expression and not croniter.is_valid(schedule_in.cron_expression):
        raise HTTPException(status_code=400, detail="Invalid cron expression")
        
    update_data = schedule_in.model_dump(exclude_unset=True)

    # A change of target is a change of what will be scanned, so it is
    # re-authorized rather than inheriting the original approval.
    new_target = update_data.get("target_cidr")
    if new_target and new_target != schedule.target_cidr:
        try:
            assert_target_authorized(
                db, organization_id=current_user.organization_id, target=new_target
            )
        except AuthorizationError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

    for field, value in update_data.items():
        setattr(schedule, field, value)

    # Re-enabling clears the reason the dispatcher last stopped it.
    if update_data.get("is_active"):
        schedule.last_error = ""

    db.commit()
    db.refresh(schedule)
    return schedule
