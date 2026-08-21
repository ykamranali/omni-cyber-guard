"""Phase 6: remediation tasks, risk acceptances, and per-organization SLA policy.

Revision ID: f2c9d51e8a34
Revises: e6f1c48a2d70
Create Date: 2026-08-21

The distinction the schema is built around is FIXED versus VERIFIED. FIXED is a
person saying they did the work; VERIFIED requires `verified_by_scan_job_id`,
which only the scan pipeline sets. A task closed without scan evidence lands in
CLOSED, not VERIFIED, and the two are counted separately in every report — a
programme where most work closes unverified is not measuring itself.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "f2c9d51e8a34"
down_revision = "e6f1c48a2d70"
branch_labels = None
depends_on = None

TENANT_TABLES = ["remediation_tasks", "risk_acceptances"]


def upgrade() -> None:
    enums = {
        "remediationstatus": [
            "OPEN", "ASSIGNED", "IN_PROGRESS", "FIXED", "AWAITING_VERIFICATION",
            "VERIFIED", "CLOSED", "CANCELLED",
        ],
        "remediationpriority": ["URGENT", "HIGH", "MEDIUM", "LOW"],
        "acceptancestatus": ["ACTIVE", "EXPIRED", "REVOKED"],
    }
    for type_name, values in enums.items():
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

    remediation_status = postgresql.ENUM(name="remediationstatus", create_type=False)
    remediation_priority = postgresql.ENUM(name="remediationpriority", create_type=False)
    acceptance_status = postgresql.ENUM(name="acceptancestatus", create_type=False)

    op.add_column("organizations", sa.Column("sla_policy", sa.JSON(), nullable=True))
    op.execute("UPDATE organizations SET sla_policy = '{}'::json WHERE sla_policy IS NULL")

    op.create_table(
        "remediation_tasks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("finding_id", UUID(as_uuid=True),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("asset_id", UUID(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", remediation_status, nullable=False, server_default="OPEN"),
        sa.Column("priority", remediation_priority, nullable=False, server_default="MEDIUM"),
        sa.Column("assigned_to_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("created_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("sla_days", sa.Integer(), nullable=True),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        # Only the scan pipeline writes this. It is what makes "verified" mean
        # something other than a word someone typed.
        sa.Column("verified_by_scan_job_id", UUID(as_uuid=True),
                  sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("external_ticket_ref", sa.String(128), nullable=True),
        sa.Column("external_ticket_url", sa.String(512), nullable=True),
        sa.Column("external_system", sa.String(64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_remediation_org_status", "remediation_tasks", ["organization_id", "status"])
    op.create_index("ix_remediation_due", "remediation_tasks", ["organization_id", "due_date"])

    op.create_table(
        "risk_acceptances",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("finding_id", UUID(as_uuid=True),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("compensating_controls", sa.Text(), nullable=False, server_default=""),
        sa.Column("requested_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        # Required, not nullable: an acceptance with no end date is
        # indistinguishable from having forgotten about it.
        sa.Column("expires_at", sa.Date(), nullable=False),
        sa.Column("status", acceptance_status, nullable=False, server_default="ACTIVE"),
        sa.Column("revoked_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_risk_acceptance_org_status", "risk_acceptances", ["organization_id", "status"])

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
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
        )


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
    op.drop_index("ix_risk_acceptance_org_status", table_name="risk_acceptances")
    op.drop_table("risk_acceptances")
    op.drop_index("ix_remediation_due", table_name="remediation_tasks")
    op.drop_index("ix_remediation_org_status", table_name="remediation_tasks")
    op.drop_table("remediation_tasks")
    op.drop_column("organizations", "sla_policy")
    for type_name in ("acceptancestatus", "remediationpriority", "remediationstatus"):
        op.execute(f"DROP TYPE IF EXISTS {type_name}")
