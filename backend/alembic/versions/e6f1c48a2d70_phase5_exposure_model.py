"""Phase 5: per-organization exposure model weights, and exposure snapshots.

Revision ID: e6f1c48a2d70
Revises: d4a8e2c61b93
Create Date: 2026-08-21

`organizations.exposure_model` holds weight overrides for the exposure engine.
Empty means the platform defaults apply.

`exposure_snapshots` records a daily point per organization so the trend line is
real recorded history rather than an interpolation drawn between two current
values.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "e6f1c48a2d70"
down_revision = "d4a8e2c61b93"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("organizations", sa.Column("exposure_model", sa.JSON(), nullable=True))
    op.execute("UPDATE organizations SET exposure_model = '{}'::json WHERE exposure_model IS NULL")

    op.create_table(
        "exposure_snapshots",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("snapshot_date", sa.Date(), nullable=False),
        sa.Column("exposure_score", sa.Float(), nullable=True),
        sa.Column("assets_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_assessed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("known_exploited_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("internet_exposed_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "snapshot_date", name="uq_exposure_snapshot_per_day"),
    )

    # Tenant-scoped, so it gets the same isolation policy as every other
    # organization-owned table.
    op.execute("ALTER TABLE exposure_snapshots ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE exposure_snapshots FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON exposure_snapshots
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
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON exposure_snapshots")
    op.drop_table("exposure_snapshots")
    op.drop_column("organizations", "exposure_model")
