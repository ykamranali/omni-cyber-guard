"""
First-run bootstrap: creates exactly one platform organization and one
super administrator, from the credentials in your .env file
(FIRST_SUPERADMIN_EMAIL / FIRST_SUPERADMIN_PASSWORD) — and only if the
users table is completely empty. This is what lets a genuinely empty,
freshly-migrated database become loggable-into without any demo/seed data.
Runs once at API startup; safe to call on every restart (it's a no-op once
any user exists).
"""
import logging

from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.db.session import SessionLocal, engine
from app.models.organization import Organization
from app.models.user import User
from app.services.org_provisioning import provision_new_organization

logger = logging.getLogger("omni_cyber_guard.bootstrap")


def ensure_bootstrap_admin() -> None:
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        logger.warning(
            "Database migrations have not been applied yet (no 'users' table found). "
            "Skipping admin bootstrap — run `alembic upgrade head` first."
        )
        return

    db: Session = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return  # already bootstrapped, or seed data / real users already exist

        org = db.query(Organization).filter_by(slug="platform-admin").first()
        if not org:
            org = Organization(name="Platform Administration", slug="platform-admin")
            db.add(org)
            db.flush()
            role_objs = provision_new_organization(db, org)
        else:
            from app.models.role import Role
            role_objs = {r.name: r for r in db.query(Role).filter_by(organization_id=org.id).all()}
            if "super_administrator" not in role_objs:
                role_objs = provision_new_organization(db, org)

        admin = User(
            organization_id=org.id,
            email=settings.FIRST_SUPERADMIN_EMAIL,
            full_name="Platform Super Admin",
            hashed_password=hash_password(settings.FIRST_SUPERADMIN_PASSWORD),
            is_super_admin=True,
        )
        admin.roles = [role_objs["super_administrator"]]
        db.add(admin)
        db.commit()

        logger.info(f"Bootstrapped first super admin account: {settings.FIRST_SUPERADMIN_EMAIL}")
    except Exception:  # noqa: BLE001 - never crash app startup over bootstrap issues
        logger.exception("Admin bootstrap failed; you can still create the first user via app/scripts/seed.py")
        db.rollback()
    finally:
        db.close()
