import uuid
from datetime import datetime, timezone
from croniter import croniter

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.models.scan_schedule import ScanSchedule
from app.models.scan_job import ScanJob, ScanType, ScanStatus
from app.tasks.scan_tasks import run_network_scan


@celery_app.task(name="scheduler_tasks.check_schedules")
def check_schedules() -> None:
    """
    Runs every minute to check if any active ScanSchedules are due to run.
    """
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        
        # We check schedules that are active
        active_schedules = db.query(ScanSchedule).filter(ScanSchedule.is_active == True).all()
        
        for schedule in active_schedules:
            try:
                # croniter uses local time normally, but we can pass a timezone-aware datetime
                # to check if the current minute is a match for the cron expression
                cron = croniter(schedule.cron_expression, now)
                
                # Check if 'now' matches the cron pattern exactly
                # croniter check match down to the minute
                if croniter.match(schedule.cron_expression, now):
                    # It's time to run this schedule. Create a new ScanJob
                    new_job = ScanJob(
                        organization_id=schedule.organization_id,
                        initiated_by_user_id=schedule.created_by_user_id,
                        target_cidr=schedule.target_cidr,
                        scan_type=ScanType.PORT_SERVICE_SCAN,
                        status=ScanStatus.QUEUED
                    )
                    db.add(new_job)
                    db.flush() # flush to get the new_job.id
                    
                    # Enqueue the scan task
                    run_network_scan.delay(str(new_job.id))
            except Exception as e:
                # If a schedule has an invalid cron expression or fails, log and continue
                print(f"Error processing schedule {schedule.id}: {e}")
                
        db.commit()
    finally:
        db.close()
