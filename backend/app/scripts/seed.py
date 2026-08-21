"""
OPTIONAL development bootstrap for Omni Cyber Guard.

Creates one organization, the standard role set, and one user per role so you
can sign in and exercise permissions. It creates **no assets, no findings and
no scan results** — the platform only ever displays security data produced by a
real assessment.

This script is never run automatically by the application or by docker-compose.
Run it explicitly if you want role-based logins to test with:

    python -m app.scripts.seed

A freshly-migrated database is otherwise completely empty apart from the single
super-admin account created at startup from your .env credentials.
"""
from app.core.config import settings
from app.core.security import hash_password
from app.db.session import Base, SessionLocal, engine
from app.models.organization import Organization
from app.models.user import User
from app.services.org_provisioning import provision_new_organization

DEV_PASSWORD = "Demo!12345"

DEV_USERS = [
    ("orgadmin@acme.test", "Olivia Admin", "organization_administrator"),
    ("secmanager@acme.test", "Sam Manager", "security_manager"),
    ("analyst@acme.test", "Alex Analyst", "security_analyst"),
    ("itadmin@acme.test", "Ivy ITAdmin", "it_administrator"),
    ("compliance@acme.test", "Cameron Compliance", "compliance_officer"),
    ("auditor@acme.test", "Aria Auditor", "auditor"),
    ("helpdesk@acme.test", "Hank Helpdesk", "helpdesk_technician"),
    ("readonly@acme.test", "Riley ReadOnly", "read_only_user"),
]


def run() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        if db.query(Organization).count() > 0:
            print("Database already contains an organization. Skipping seed.")
            return

        org = Organization(
            name="Acme Corporation",
            slug="acme-corp",
            subscription_plan="enterprise",
            license_seats=250,
        )
        db.add(org)
        db.flush()

        roles = provision_new_organization(db, org)

        super_admin = User(
            organization_id=org.id,
            email=settings.FIRST_SUPERADMIN_EMAIL,
            full_name="Platform Super Admin",
            hashed_password=hash_password(settings.FIRST_SUPERADMIN_PASSWORD),
            is_super_admin=True,
        )
        super_admin.roles = [roles["super_administrator"]]
        db.add(super_admin)

        for email, name, role_key in DEV_USERS:
            user = User(
                organization_id=org.id,
                email=email,
                full_name=name,
                hashed_password=hash_password(DEV_PASSWORD),
            )
            user.roles = [roles[role_key]]
            db.add(user)

        db.commit()

        print("Seed complete — accounts only, no security data.")
        print(f"  Super admin: {settings.FIRST_SUPERADMIN_EMAIL}")
        print(f"  Role users (password {DEV_PASSWORD}): " + ", ".join(email for email, _, _ in DEV_USERS))
        print()
        print("The dashboard will show empty states until you run a real scan.")
    finally:
        db.close()


if __name__ == "__main__":
    run()
