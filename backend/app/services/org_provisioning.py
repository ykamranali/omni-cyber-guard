"""
Shared provisioning logic used both by the seed script and the real
Organizations API: creates the standard role set (with default permission
grants) and the standard compliance framework rows (at real 0% coverage,
never a fabricated starting number) for a brand-new organization.
"""
from sqlalchemy.orm import Session

from app.core.rbac import DEFAULT_ROLE_PERMISSIONS
from app.models.compliance import ComplianceFramework  # noqa: F401  (kept for callers)
from app.models.organization import Organization
from app.models.role import Role, Permission as PermissionModel

# Content packs installed for a new organization.
#
# These are original control sets mapped to signals this platform can actually
# evaluate. The previous behaviour created empty frameworks named "ISO 27001",
# "PCI DSS" and so on — which implied the platform assesses those standards
# while holding no control content for any of them, and would have shown an
# organization a compliance figure against a framework nothing had been written
# for. Named standards belong here only when the control content behind them
# exists.
DEFAULT_CONTENT_PACKS = ["network-hygiene", "host-hardening", "governance-baseline"]


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

    db.commit()

    # Install the compliance content packs. Imported here rather than at module
    # scope to avoid a circular import through the compliance engine.
    from app.services.compliance.packs import install_pack

    for slug in DEFAULT_CONTENT_PACKS:
        install_pack(db, org.id, slug)

    return role_objs
