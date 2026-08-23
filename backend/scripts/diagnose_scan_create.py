"""
Reproduce the create-scan failure inside the running backend container.

    docker compose exec -T backend python -m scripts.diagnose_scan_create

The endpoint dies at `db.refresh(job)` with "Could not refresh instance",
which SQLAlchemy raises when the SELECT it issues for that row comes back
empty. The row demonstrably exists — a superuser query lists it — so something
is filtering it, and row-level security is the only thing that filters by
identity here.

This walks the same sequence the request does and prints the tenant scope at
every step, so the exact point where the session stops being able to see its
own row is visible rather than inferred. It writes one scan job and rolls it
back; nothing is left behind.
"""
from __future__ import annotations

import traceback
import uuid

from sqlalchemy import text

from app.core.config import settings
from app.db.session import SessionLocal
from app.db.tenancy import (
    bypass_tenant, clear_tenant, current_scope, rls_effective, set_tenant,
)
from app.models.scan_job import ScanJob, ScanStatus, ScanType
from app.models.user import User


def rule(title: str) -> None:
    print()
    print("=" * 68)
    print(title)
    print("=" * 68)


def main() -> int:
    rule("1. Settings")
    print("ENABLE_ROW_LEVEL_SECURITY :", settings.ENABLE_ROW_LEVEL_SECURITY)
    print("DATABASE_URL role         :", settings.DATABASE_URL.split("://", 1)[-1].split(":", 1)[0])

    db = SessionLocal()
    try:
        rule("2. Is RLS actually in force?")
        effective, explanation = rls_effective(db)
        print("effective:", effective)
        print(explanation)

        rule("3. Policies on scan_jobs")
        rows = db.execute(text(
            "SELECT policyname, permissive, cmd, qual, with_check "
            "FROM pg_policies WHERE tablename = 'scan_jobs'"
        )).fetchall()
        if not rows:
            print("NO POLICIES ON scan_jobs.")
        for row in rows:
            print(f"- {row.policyname} ({row.permissive}, {row.cmd})")
            print(f"    USING      {row.qual}")
            print(f"    WITH CHECK {row.with_check}")

        forced = db.execute(text(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'scan_jobs'"
        )).first()
        print(f"row security enabled={forced.relrowsecurity} forced={forced.relforcerowsecurity}")

        rule("4. Walking the request sequence")
        # get_db opens in bypass.
        bypass_tenant(db)
        print("after bypass_tenant      :", current_scope(db))

        user = db.query(User).order_by(User.created_at).first()
        if user is None:
            print("No users exist; cannot continue.")
            return 1
        print(f"acting as               : {user.email} org={user.organization_id}")

        # get_current_user narrows to the tenant.
        set_tenant(db, user.organization_id)
        print("after set_tenant         :", current_scope(db))

        visible = db.query(ScanJob).count()
        print(f"scan jobs visible now    : {visible}")

        job = ScanJob(
            organization_id=user.organization_id,
            initiated_by_user_id=user.id,
            target_cidr="192.168.1.0/24",
            scan_type=ScanType.PORT_SERVICE_SCAN,
            engine="nmap",
            status=ScanStatus.QUEUED,
        )
        db.add(job)
        db.flush()
        job_id = job.id
        print(f"inserted (not committed) : {job_id}")
        print("scope after flush        :", current_scope(db))

        found = db.execute(
            text("SELECT count(*) FROM scan_jobs WHERE id = :i"), {"i": str(job_id)}
        ).scalar()
        print(f"visible before commit    : {found}")

        db.commit()
        print("scope after commit       :", current_scope(db))

        found = db.execute(
            text("SELECT count(*) FROM scan_jobs WHERE id = :i"), {"i": str(job_id)}
        ).scalar()
        print(f"visible after commit     : {found}   <-- 0 here means RLS is hiding it")

        as_superuser_would_see = db.execute(
            text("SELECT organization_id::text FROM scan_jobs WHERE id = :i"),
            {"i": str(job_id)},
        ).scalar()
        print(f"row's organization_id    : {as_superuser_would_see}")

        rule("5. The failing call")
        try:
            db.refresh(job)
            print("db.refresh(job) SUCCEEDED — the bug did not reproduce here.")
        except Exception:
            print("db.refresh(job) FAILED, same as the endpoint:")
            traceback.print_exc()

        rule("6. Cleaning up")
        bypass_tenant(db)
        db.execute(text("DELETE FROM scan_jobs WHERE id = :i"), {"i": str(job_id)})
        db.commit()
        print("test row removed.")
        return 0
    finally:
        try:
            clear_tenant(db)
            db.commit()
        except Exception:
            db.rollback()
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
