import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from croniter import croniter

from app.api.dependencies import get_db, get_current_user
from app.models.user import User
from app.models.scan_schedule import ScanSchedule
from app.schemas.scan_schedule import ScanScheduleCreate, ScanScheduleUpdate, ScanScheduleResponse

router = APIRouter()

@router.get("/", response_model=list[ScanScheduleResponse])
def list_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
    current_user: User = Depends(get_current_user),
):
    """
    Create a new recurring scan schedule.
    """
    if not croniter.is_valid(schedule_in.cron_expression):
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    schedule = ScanSchedule(
        organization_id=current_user.organization_id,
        created_by_user_id=current_user.id,
        **schedule_in.model_dump()
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule

@router.delete("/{schedule_id}", status_code=204)
def delete_schedule(
    schedule_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    schedule = db.query(ScanSchedule).filter(
        ScanSchedule.id == schedule_id,
        ScanSchedule.organization_id == current_user.organization_id
    ).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
        
    db.delete(schedule)
    db.commit()
    return None

@router.patch("/{schedule_id}", response_model=ScanScheduleResponse)
def update_schedule(
    schedule_id: uuid.UUID,
    schedule_in: ScanScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
    for field, value in update_data.items():
        setattr(schedule, field, value)
        
    db.commit()
    db.refresh(schedule)
    return schedule
