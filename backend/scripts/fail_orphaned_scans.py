"""Mark scan jobs that were lost to a restart as failed.

This began life as ``backend/test_celery.py``. Two problems with that: pytest
collects any module named ``test_*``, and every statement here ran at import
time, so a plain ``pytest`` run silently rewrote scan history in whichever
database the environment pointed at. It is a maintenance tool, not a test.

Its purpose is narrower now than it was. A dispatch failure no longer strands a
job at QUEUED — ``app/tasks`` marks the job FAILED with the reason the broker
gave, and ``GET /system/workers`` reports when no worker is consuming the
queue. What this still handles is the case the application cannot observe: the
worker process was killed mid-run, so the job was accepted and then nothing
ever reported back.

    python -m scripts.fail_orphaned_scans --older-than-minutes 30 --confirm

Nothing is written without ``--confirm``; without it the script lists what it
would change and exits.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone

from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant
from app.models.scan_job import ScanJob, ScanStatus

REASON = (
    "Marked failed by an operator: the job was queued but no worker ever "
    "reported a result, which normally means the worker process was stopped "
    "or restarted while the scan was in flight. No scan output was produced."
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--older-than-minutes",
        type=int,
        default=30,
        help=(
            "Only touch jobs queued at least this long ago, so a scan that is "
            "legitimately waiting for a busy worker is left alone."
        ),
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Actually write the change. Without it, this only reports.",
    )
    args = parser.parse_args()

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=args.older_than_minutes)

    db = SessionLocal()
    try:
        bypass_tenant(db)
        stranded = (
            db.query(ScanJob)
            .filter(ScanJob.status == ScanStatus.QUEUED)
            .filter(ScanJob.created_at < cutoff)
            .all()
        )

        if not stranded:
            print(f"No scan jobs have been queued for more than {args.older_than_minutes} minutes.")
            return 0

        print(f"{len(stranded)} scan job(s) queued for more than {args.older_than_minutes} minutes:")
        for job in stranded:
            print(f"  {job.id}  engine={job.engine}  target={job.target_cidr}  queued={job.created_at}")

        if not args.confirm:
            print("\nNothing written. Re-run with --confirm to mark these failed.")
            return 0

        for job in stranded:
            job.status = ScanStatus.FAILED
            job.error_message = REASON
        db.commit()
        print(f"\nMarked {len(stranded)} job(s) failed.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
