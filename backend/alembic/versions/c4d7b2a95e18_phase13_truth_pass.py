"""Phase 13: integration state, attack-path claim strength, discovery honesty, RLS repair.

Revision ID: c4d7b2a95e18
Revises: b8e5a2f71c93
Create Date: 2026-08-22

Five changes, each removing a way the schema let the application state more
than it knew.

1. `integration_states` gives a failed or unconfigured external integration
   somewhere honest to live. Without it, the cloud and identity discovery tasks
   recorded their own failure as a `CloudResource` named "Discovery Failed: ..."
   and an `IdentityProfile` with the address `admin_integration_failed@...`,
   both served by their endpoints as discovered inventory.

2. `attack_paths.is_verified` becomes `claim_strength`. A boolean cannot carry
   the POTENTIAL / OBSERVED / VERIFIED distinction the specification requires,
   and `false` reads as "not yet checked" rather than "theoretical". Existing
   rows are backfilled to POTENTIAL, which is what they all were.

3. `identity_profiles.mfa_enabled` becomes nullable. It defaulted to `false`,
   so an account whose directory listing does not report factor enrolment was
   recorded as having MFA disabled — a security claim the API response never
   supported. Existing `false` values are set to NULL because none of them came
   from a real directory read.

4. `attack_surface_domains` gains the authorization columns that make probing a
   domain legitimate, plus uniqueness so a domain is registered once.

5. The row-level security policies on the three discovery tables are replaced.
   They were written against `current_setting('app.current_tenant')`, a setting
   the application has never once set — `set_tenant`/`bypass_tenant` use
   `app.current_org_id` and `app.rls_bypass` — and they omitted FORCE ROW LEVEL
   SECURITY. Tenant isolation on those tables was non-functional in both
   directions: the policy matched nothing for legitimate access, and the table
   owner bypassed it entirely.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "c4d7b2a95e18"
down_revision = "b8e5a2f71c93"
branch_labels = None
depends_on = None

DISCOVERY_TABLES = ["attack_surface_domains", "cloud_resources", "identity_profiles"]
GRAPH_TABLES = ["graph_edges", "attack_paths"]
NEW_TENANT_TABLES = ["integration_states"]

TENANT_POLICY = """
    CREATE POLICY tenant_isolation ON {table}
    USING (
        current_setting('app.rls_bypass', true) = 'on'
        OR organization_id = nullif(current_setting('app.current_org_id', true), '')::uuid
    )
    WITH CHECK (
        current_setting('app.rls_bypass', true) = 'on'
        OR organization_id = nullif(current_setting('app.current_org_id', true), '')::uuid
    )
"""

ENUMS = {
    "integrationkind": ["CLOUD", "IDENTITY", "ATTACK_SURFACE"],
    "integrationstatus": ["NOT_CONFIGURED", "ERROR", "CONNECTED"],
    "claimstrength": ["POTENTIAL", "OBSERVED", "VERIFIED"],
}


def _create_enums() -> None:
    for type_name, values in ENUMS.items():
        labels = ", ".join(f"'{value}'" for value in values)
        op.execute(
            f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = '{type_name}') THEN
                    CREATE TYPE {type_name} AS ENUM ({labels});
                END IF;
            END
            $$
            """
        )


def _apply_tenant_policy(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(TENANT_POLICY.format(table=table))


def upgrade() -> None:
    _create_enums()
    integration_kind = postgresql.ENUM(name="integrationkind", create_type=False)
    integration_status = postgresql.ENUM(name="integrationstatus", create_type=False)
    claim_strength = postgresql.ENUM(name="claimstrength", create_type=False)

    # ---------------------------------------------------------------- 1
    op.create_table(
        "integration_states",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("kind", integration_kind, nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("status", integration_status, nullable=False,
                  server_default="NOT_CONFIGURED"),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("missing_configuration", sa.JSON(), nullable=True),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        # Only advanced by a run that actually succeeded.
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("records_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "kind", "provider",
                            name="uq_integration_state"),
    )

    # ---------------------------------------------------------------- 2
    op.add_column("attack_paths", sa.Column(
        "claim_strength", claim_strength, nullable=False, server_default="POTENTIAL"
    ))
    op.add_column("attack_paths", sa.Column("entry_point", sa.String(32),
                                            nullable=False, server_default="unknown"))
    op.add_column("attack_paths", sa.Column("risk_breakdown", postgresql.JSONB(),
                                            nullable=False, server_default="{}"))
    op.add_column("attack_paths", sa.Column("verified_by_scan_job_id", UUID(as_uuid=True),
                                            nullable=True))
    op.create_foreign_key(
        "fk_attack_paths_verified_scan_job", "attack_paths", "scan_jobs",
        ["verified_by_scan_job_id"], ["id"], ondelete="SET NULL",
    )
    op.add_column("attack_paths", sa.Column("verified_at", sa.DateTime(timezone=True),
                                            nullable=True))
    op.add_column("attack_paths", sa.Column("evidence_note", sa.Text(),
                                            nullable=False, server_default=""))
    op.add_column("attack_paths", sa.Column("last_computed_at", sa.DateTime(timezone=True),
                                            nullable=True))

    # Every existing row was computed by the old engine, which hardcoded
    # is_verified=False and had no verification path. They are all POTENTIAL.
    op.execute("UPDATE attack_paths SET claim_strength = 'POTENTIAL'")
    op.drop_column("attack_paths", "is_verified")

    op.create_index(
        "ix_attack_paths_org_strength", "attack_paths",
        ["organization_id", "claim_strength"],
    )

    # ---------------------------------------------------------------- 3
    op.alter_column("identity_profiles", "mfa_enabled",
                    existing_type=sa.Boolean(), nullable=True, server_default=None)
    # None of the stored `false` values came from a directory that reported
    # factor enrolment; they came from the column default.
    op.execute("UPDATE identity_profiles SET mfa_enabled = NULL")
    op.alter_column("identity_profiles", "privilege_level",
                    existing_type=sa.String(50), server_default="")
    op.execute("UPDATE identity_profiles SET privilege_level = '' WHERE privilege_level = 'USER'")

    # Rows the fabricating discovery tasks inserted. They are not inventory and
    # were never read from anything.
    op.execute(
        "DELETE FROM identity_profiles WHERE email LIKE 'admin_integration_failed@%'"
    )
    op.execute(
        "DELETE FROM cloud_resources WHERE resource_type = 'Integration::Status' "
        "OR resource_id LIKE 'cspm-status-%'"
    )
    op.execute(
        "UPDATE attack_surface_domains SET registrar = '' "
        "WHERE registrar = 'Enumerated (Live)'"
    )

    op.alter_column("cloud_resources", "status",
                    existing_type=sa.String(50), server_default="")

    # ---------------------------------------------------------------- 4
    op.add_column("attack_surface_domains", sa.Column(
        "authorized_by_user_id", UUID(as_uuid=True), nullable=True
    ))
    op.create_foreign_key(
        "fk_attack_surface_domains_authorized_by", "attack_surface_domains", "users",
        ["authorized_by_user_id"], ["id"], ondelete="SET NULL",
    )
    op.add_column("attack_surface_domains", sa.Column(
        "authorized_at", sa.DateTime(timezone=True), nullable=True
    ))
    op.add_column("attack_surface_domains", sa.Column(
        "last_checked_at", sa.DateTime(timezone=True), nullable=True
    ))
    # Existing rows predate the authorization requirement. Backfilled to their
    # creation time so they remain probe-able, rather than deleted.
    op.execute("UPDATE attack_surface_domains SET authorized_at = created_at "
               "WHERE authorized_at IS NULL")

    op.execute(
        """
        DELETE FROM attack_surface_domains a
        USING attack_surface_domains b
        WHERE a.ctid < b.ctid
          AND a.organization_id = b.organization_id
          AND a.domain_name = b.domain_name
        """
    )
    op.create_unique_constraint(
        "uq_attack_surface_domain", "attack_surface_domains",
        ["organization_id", "domain_name"],
    )

    op.execute(
        """
        DELETE FROM cloud_resources a
        USING cloud_resources b
        WHERE a.ctid < b.ctid
          AND a.organization_id = b.organization_id
          AND a.provider = b.provider
          AND a.resource_id = b.resource_id
        """
    )
    op.create_unique_constraint(
        "uq_cloud_resource", "cloud_resources",
        ["organization_id", "provider", "resource_id"],
    )

    op.execute(
        """
        DELETE FROM identity_profiles a
        USING identity_profiles b
        WHERE a.ctid < b.ctid
          AND a.organization_id = b.organization_id
          AND a.provider = b.provider
          AND a.email = b.email
        """
    )
    op.create_unique_constraint(
        "uq_identity_profile", "identity_profiles",
        ["organization_id", "provider", "email"],
    )

    # ---------------------------------------------------------------- 5
    for table in DISCOVERY_TABLES:
        op.execute(
            f"DROP POLICY IF EXISTS {table}_tenant_isolation_policy ON {table}"
        )
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        _apply_tenant_policy(table)

    for table in NEW_TENANT_TABLES:
        _apply_tenant_policy(table)

    # ---------------------------------------------------------------- 6
    op.add_column("scan_schedules", sa.Column("last_error", sa.Text(),
                                              nullable=False, server_default=""))
    op.add_column("scan_schedules", sa.Column("last_dispatched_at",
                                              sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_schedules", "last_dispatched_at")
    op.drop_column("scan_schedules", "last_error")

    for table in NEW_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")

    for table in DISCOVERY_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_tenant_isolation_policy ON {table}
            USING (organization_id = current_setting('app.current_tenant', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.current_tenant', true)::uuid)
            """
        )

    op.drop_constraint("uq_identity_profile", "identity_profiles", type_="unique")
    op.drop_constraint("uq_cloud_resource", "cloud_resources", type_="unique")
    op.drop_constraint("uq_attack_surface_domain", "attack_surface_domains", type_="unique")

    op.drop_column("attack_surface_domains", "last_checked_at")
    op.drop_column("attack_surface_domains", "authorized_at")
    op.drop_constraint(
        "fk_attack_surface_domains_authorized_by", "attack_surface_domains",
        type_="foreignkey",
    )
    op.drop_column("attack_surface_domains", "authorized_by_user_id")

    op.alter_column("cloud_resources", "status",
                    existing_type=sa.String(50), server_default="ACTIVE")
    op.alter_column("identity_profiles", "privilege_level",
                    existing_type=sa.String(50), server_default="USER")
    op.execute("UPDATE identity_profiles SET mfa_enabled = false WHERE mfa_enabled IS NULL")
    op.alter_column("identity_profiles", "mfa_enabled",
                    existing_type=sa.Boolean(), nullable=False, server_default="false")

    op.drop_index("ix_attack_paths_org_strength", table_name="attack_paths")
    op.add_column("attack_paths", sa.Column(
        "is_verified", sa.Boolean(), nullable=False, server_default="false"
    ))
    op.execute("UPDATE attack_paths SET is_verified = (claim_strength = 'VERIFIED')")
    op.drop_column("attack_paths", "last_computed_at")
    op.drop_column("attack_paths", "evidence_note")
    op.drop_column("attack_paths", "verified_at")
    op.drop_constraint(
        "fk_attack_paths_verified_scan_job", "attack_paths", type_="foreignkey"
    )
    op.drop_column("attack_paths", "verified_by_scan_job_id")
    op.drop_column("attack_paths", "risk_breakdown")
    op.drop_column("attack_paths", "entry_point")
    op.drop_column("attack_paths", "claim_strength")

    op.drop_table("integration_states")

    for type_name in ("claimstrength", "integrationstatus", "integrationkind"):
        op.execute(f"DROP TYPE IF EXISTS {type_name}")
