"""
Scheduled scan dispatch.

Two things were wrong here, and both were invisible from the UI.

The task opened a session and queried `scan_schedules` **without setting a
tenant scope**. Under enforced row-level security the policy predicate is then
NULL for every row, so the query returned nothing — for every organization,
every minute. A schedule could be created, shown as active, and never once
fire. The API reported success at creation and nothing ever contradicted it.

Per-schedule failures were swallowed by `print()`, so a schedule with a bad
target produced no record anywhere an operator would look.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from croniter import croniter
from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant, set_tenant
from app.models.scan_job import ScanJob, ScanStatus, ScanType
from app.models.scan_schedule import ScanSchedule
from app.services.scan_authorization import AuthorizationError, assert_target_authorized
from app.tasks.scan_tasks import run_network_scan

logger = logging.getLogger(__name__)


@celery_app.task(name="scheduler_tasks.check_schedules")
def check_schedules() -> dict:
    """Dispatch any schedule whose cron expression matches this minute."""
    db = SessionLocal()
    # The dispatcher legitimately spans tenants: it is deciding, for every
    # organization, whether a schedule is due. Each dispatch then narrows to
    # the schedule's own organization before creating anything.
    bypass_tenant(db)

    dispatched = 0
    skipped: list[str] = []

    try:
        now = datetime.now(timezone.utc)
        schedules = db.execute(
            select(ScanSchedule).where(ScanSchedule.is_active.is_(True))
        ).scalars().all()

        for schedule in schedules:
            try:
                if not croniter.is_valid(schedule.cron_expression):
                    raise ValueError(
                        f"{schedule.cron_expression!r} is not a valid cron expression"
                    )
                if not croniter.match(schedule.cron_expression, now):
                    continue

                # Re-checked at dispatch, not only at creation: an operator may
                # have withdrawn the authorized scope since the schedule was
                # made, and a schedule must not outlive its authorization.
                assert_target_authorized(
                    db, organization_id=schedule.organization_id,
                    target=schedule.target_cidr,
                )

                set_tenant(db, schedule.organization_id)
                job = ScanJob(
                    organization_id=schedule.organization_id,
                    initiated_by_user_id=schedule.created_by_user_id,
                    target_cidr=schedule.target_cidr,
                    scan_type=ScanType.PORT_SERVICE_SCAN,
                    status=ScanStatus.QUEUED,
                )
                db.add(job)
                db.flush()
                job_id = str(job.id)
                db.commit()
                bypass_tenant(db)

                run_network_scan.delay(job_id)
                dispatched += 1

            except AuthorizationError as exc:
                db.rollback()
                bypass_tenant(db)
                skipped.append(str(schedule.id))
                # Deactivated rather than left to fail every minute: a schedule
                # whose scope is no longer authorized should stop, visibly.
                _deactivate(db, schedule, reason=str(exc))
                logger.warning(
                    "Schedule %s deactivated — target no longer authorized: %s",
                    schedule.id, exc,
                )
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                bypass_tenant(db)
                skipped.append(str(schedule.id))
                logger.exception("Schedule %s could not be dispatched: %s", schedule.id, exc)

        return {"dispatched": dispatched, "skipped": skipped}
    finally:
        db.close()


def _deactivate(db, schedule: ScanSchedule, reason: str) -> None:
    set_tenant(db, schedule.organization_id)
    schedule.is_active = False
    schedule.last_error = reason[:500]
    db.add(schedule)
    db.commit()
    bypass_tenant(db)
