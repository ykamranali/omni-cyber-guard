"""
Shared provisioning logic used both by the seed script and the real
Organizations API: creates the standard role set (with default permission
grants) and the standard compliance framework rows (at real 0% coverage,
never a fabricated starting number) for a brand-new organization.
"""
from sqlalchemy.orm import Session

from app.core.rbac import DEFAULT_ROLE_PERMISSIONS
from app.models.compliance import ComplianceFramework
from app.models.organization import Organization
from app.models.role import Role, Permission as PermissionModel

STANDARD_FRAMEWORKS = ["ISO 27001", "NIST CSF", "CIS Benchmarks", "PCI DSS", "HIPAA", "GDPR", "SOC 2"]


def ensure_permission_catalog(db: Session) -> dict[str, PermissionModel]:
    """Permissions are platform-wide (not per-org). Creates any missing rows and returns the full map."""
    from app.core.rbac import Permission as PermissionEnum

    existing = {p.code: p for p in db.query(PermissionModel).all()}
    for perm in PermissionEnum:
        if perm.value not in existing:
            p = PermissionModel(code=perm.value, description=perm.value.replace("_", " ").title())
            db.add(p)
            existing[perm.value] = p
    db.flush()
    return existing


def provision_new_organization(db: Session, org: Organization) -> dict[str, Role]:
    """Creates the standard roles (with permissions) and compliance framework rows for `org`."""
    perm_objs = ensure_permission_catalog(db)

    role_objs: dict[str, Role] = {}
    for role_name, perms in DEFAULT_ROLE_PERMISSIONS.items():
        role = Role(organization_id=org.id, name=role_name.value, is_system_role=True)
        role.permissions = [perm_objs[p.value] for p in perms]
        db.add(role)
        role_objs[role_name.value] = role
    db.flush()

    for name in STANDARD_FRAMEWORKS:
        db.add(ComplianceFramework(organization_id=org.id, name=name, coverage_percent=0.0))

    db.commit()
    return role_objs
