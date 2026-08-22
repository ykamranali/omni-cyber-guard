"""
Row-level security scoping.

Tenant isolation previously rested entirely on every developer remembering to
write `.filter(Model.organization_id == current_user.organization_id)`. One
omission in one endpoint is a cross-customer data leak, and nothing in the
codebase would catch it.

PostgreSQL row-level security gives a second, independent enforcement point.
Policies on every tenant-scoped table restrict visible rows to the organization
named by the `app.current_org_id` session setting, and the policies are FORCED
so they apply to the table owner too.

Two settings drive it:

    app.current_org_id   the tenant a session is acting as
    app.rls_bypass       'on' for contexts that legitimately span tenants

Bypass is used in exactly three places, each of which is unavoidable:

  * Authentication. Resolving the bearer token's subject is a primary-key
    lookup on `users` that necessarily happens before the tenant is known.
  * Super administrators. Managing organizations is their function.
  * Background workers and first-run bootstrap, which have no request context.
    A worker narrows to its job's tenant as soon as it has loaded the job.

Every API session sets its scope explicitly at the start of the request, so a
value left behind on a pooled connection can never be inherited.
"""
from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

# Tables carrying an organization_id, protected by an RLS policy.
TENANT_TABLES = (
    "assets",
    "asset_interfaces",
    "asset_services",
    "asset_software",
    "asset_tags",
    "findings",
    "scan_jobs",
    "scan_targets",
    "scan_schedules",
    "compliance_frameworks",
    "compliance_assessments",
    "compliance_results",
    "compliance_exceptions",
    "control_attestations",
    "credential_profiles",
    "remediation_tasks",
    "risk_acceptances",
    "blocked_ips",
    "incidents",
    "dashboard_snapshots",
    "exposure_snapshots",
    "sites",
    "networks",
    "audit_logs",
    "users",
    "roles",
    "agent_conversations",
    "agent_messages",
    "agent_action_proposals",
)


def set_tenant(db: Session, organization_id: uuid.UUID | str) -> None:
    """Scope this session to one organization. Bypass is turned off."""
    db.execute(
        text("SELECT set_config('app.current_org_id', :org, false), "
             "set_config('app.rls_bypass', 'off', false)"),
        {"org": str(organization_id)},
    )


def bypass_tenant(db: Session) -> None:
    """Allow this session to span tenants. Use only where documented above."""
    db.execute(
        text("SELECT set_config('app.current_org_id', '', false), "
             "set_config('app.rls_bypass', 'on', false)")
    )


def clear_tenant(db: Session) -> None:
    """
    Reset scoping to 'no tenant, no bypass'.

    This is the safe default for a connection returning to the pool: with
    neither setting present the policies match no rows at all, so a leaked
    connection cannot expose data.
    """
    db.execute(
        text("SELECT set_config('app.current_org_id', '', false), "
             "set_config('app.rls_bypass', 'off', false)")
    )


def current_scope(db: Session) -> dict[str, str]:
    """Read back the active scope. Used by tests and diagnostics."""
    row = db.execute(
        text("SELECT current_setting('app.current_org_id', true) AS org, "
             "current_setting('app.rls_bypass', true) AS bypass")
    ).first()
    return {"organization_id": row.org or "", "bypass": row.bypass or "off"}


def rls_effective(db: Session) -> tuple[bool, str]:
    """
    Report whether row-level security is actually in force for this connection.

    PostgreSQL exempts superusers and roles with BYPASSRLS from every policy —
    silently. A deployment that connects as a superuser gets policies that
    exist, appear in pg_policies, and do nothing at all. Because the failure is
    invisible, it has to be checked explicitly rather than assumed.

    Returns (effective, explanation).
    """
    row = db.execute(
        text(
            "SELECT current_user AS role_name, "
            "  (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser, "
            "  (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user) AS bypasses_rls"
        )
    ).first()

    if row is None:
        return False, "Could not determine the current database role."

    if row.is_superuser:
        return False, (
            f"The application connects to PostgreSQL as '{row.role_name}', which is a "
            f"superuser. Superusers bypass every row-level security policy, so tenant "
            f"isolation is enforced only by application query filters. Grant the "
            f"application a role with NOSUPERUSER NOBYPASSRLS that owns the tables."
        )

    if row.bypasses_rls:
        return False, (
            f"The database role '{row.role_name}' has the BYPASSRLS attribute, so "
            f"row-level security policies do not apply to it. Remove it with: "
            f"ALTER ROLE {row.role_name} NOBYPASSRLS;"
        )

    unforced = [
        record[0]
        for record in db.execute(
            text(
                "SELECT relname FROM pg_class "
                "WHERE relname = ANY(:tables) AND relrowsecurity AND NOT relforcerowsecurity"
            ),
            {"tables": list(TENANT_TABLES)},
        )
    ]
    if unforced:
        return False, (
            "Row-level security is enabled but not FORCED on: "
            + ", ".join(sorted(unforced))
            + ". The table owner therefore bypasses the policies."
        )

    return True, f"Row-level security is in force for role '{row.role_name}'."
