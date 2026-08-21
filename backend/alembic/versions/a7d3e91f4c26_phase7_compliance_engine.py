"""Phase 7: evidence-based compliance model.

Revision ID: a7d3e91f4c26
Revises: f2c9d51e8a34
Create Date: 2026-08-21

Replaces the operator-typed `coverage_percent` with Framework → Requirement →
Control → Check → Result. Every result is derived from a query over assessment
data, and NOT_ASSESSED is excluded from the compliance percentage rather than
counted as compliant.

Existing frameworks and controls are preserved. Each pre-existing framework gets
a synthetic "Migrated controls" requirement so its controls keep their notes and
their place in the hierarchy; they arrive as MANUAL because the old model
recorded no way to evaluate them.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "a7d3e91f4c26"
down_revision = "f2c9d51e8a34"
branch_labels = None
depends_on = None

TENANT_TABLES = [
    "compliance_assessments", "compliance_results", "compliance_exceptions",
    "control_attestations",
]


def upgrade() -> None:
    enums = {
        "controlresult": ["PASS", "FAIL", "NOT_ASSESSED", "NOT_APPLICABLE", "EXCEPTION"],
        "checktype": [
            "NO_EXPOSED_PORT", "NO_OPEN_FINDING", "REMEDIATION_WITHIN_SLA",
            "ASSET_ATTRIBUTE_REQUIRED", "ASSESSMENT_FRESHNESS", "NO_EXPOSED_SEVERITY",
            "MANUAL",
        ],
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

    control_result = postgresql.ENUM(name="controlresult", create_type=False)
    check_type = postgresql.ENUM(name="checktype", create_type=False)

    # --- framework gains identity and provenance -------------------------
    op.add_column("compliance_frameworks", sa.Column("slug", sa.String(100), nullable=True))
    op.add_column("compliance_frameworks", sa.Column("version", sa.String(32), nullable=False, server_default=""))
    op.add_column("compliance_frameworks", sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.add_column("compliance_frameworks", sa.Column("source", sa.String(255), nullable=False, server_default=""))
    op.add_column("compliance_frameworks", sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column("compliance_frameworks", sa.Column("last_assessed_at", sa.DateTime(timezone=True), nullable=True))

    # Derive a slug from the existing name so pre-existing frameworks remain
    # addressable, then make it required.
    op.execute(
        """
        UPDATE compliance_frameworks
        SET slug = lower(regexp_replace(name, '[^a-zA-Z0-9]+', '-', 'g'))
        WHERE slug IS NULL
        """
    )
    op.alter_column("compliance_frameworks", "slug", nullable=False)
    op.create_unique_constraint(
        "uq_framework_slug_per_org", "compliance_frameworks", ["organization_id", "slug"]
    )

    # --- requirements ----------------------------------------------------
    op.create_table(
        "compliance_requirements",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("framework_id", UUID(as_uuid=True),
                  sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("code", sa.String(50), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("display_order", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("framework_id", "code", name="uq_requirement_code_per_framework"),
    )

    # --- controls move under requirements --------------------------------
    op.add_column("compliance_controls", sa.Column("requirement_id", UUID(as_uuid=True), nullable=True))
    op.add_column("compliance_controls", sa.Column("code", sa.String(50), nullable=True))
    op.add_column("compliance_controls", sa.Column("description", sa.Text(), nullable=False, server_default=""))
    op.add_column("compliance_controls", sa.Column("guidance", sa.Text(), nullable=False, server_default=""))
    op.add_column("compliance_controls", sa.Column("check_type", check_type, nullable=False, server_default="MANUAL"))
    op.add_column("compliance_controls", sa.Column("check_parameters", sa.JSON(), nullable=True))
    op.execute("UPDATE compliance_controls SET check_parameters = '{}'::json WHERE check_parameters IS NULL")

    # Give every existing framework a container requirement so its controls
    # keep their notes rather than being discarded.
    op.execute(
        """
        INSERT INTO compliance_requirements (id, framework_id, code, title, description, display_order)
        SELECT gen_random_uuid(), f.id, 'MIGRATED', 'Migrated controls',
               'Controls carried over from the previous compliance model. They have no '
               'automated check defined, so they are recorded as manual and require an '
               'attestation before they can pass.',
               0
        FROM compliance_frameworks f
        WHERE EXISTS (SELECT 1 FROM compliance_controls c WHERE c.framework_id = f.id)
        """
    )
    op.execute(
        """
        UPDATE compliance_controls c
        SET requirement_id = r.id,
            code = COALESCE(NULLIF(c.control_code, ''), 'MIGRATED-' || left(c.id::text, 8))
        FROM compliance_requirements r
        WHERE r.framework_id = c.framework_id AND r.code = 'MIGRATED'
        """
    )
    # Anything still unattached has no framework to belong to.
    op.execute("DELETE FROM compliance_controls WHERE requirement_id IS NULL")

    op.alter_column("compliance_controls", "requirement_id", nullable=False)
    op.alter_column("compliance_controls", "code", nullable=False)
    op.create_foreign_key(
        "fk_control_requirement", "compliance_controls", "compliance_requirements",
        ["requirement_id"], ["id"], ondelete="CASCADE",
    )
    op.create_index("ix_compliance_controls_requirement_id", "compliance_controls", ["requirement_id"])
    op.create_unique_constraint(
        "uq_control_code_per_requirement", "compliance_controls", ["requirement_id", "code"]
    )
    op.drop_constraint("compliance_controls_framework_id_fkey", "compliance_controls", type_="foreignkey")
    op.drop_column("compliance_controls", "framework_id")
    op.drop_column("compliance_controls", "control_code")
    op.drop_column("compliance_controls", "status")

    # --- assessments, results, exceptions, attestations ------------------
    op.create_table(
        "compliance_assessments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("framework_id", UUID(as_uuid=True),
                  sa.ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("controls_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_not_assessed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_not_applicable", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("controls_exception", sa.Integer(), nullable=False, server_default="0"),
        # Nullable: with no conclusive results there is no percentage to state,
        # and reporting 0% or 100% would both be wrong.
        sa.Column("compliance_percent", sa.Float(), nullable=True),
        sa.Column("assessable_percent", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "compliance_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("assessment_id", UUID(as_uuid=True),
                  sa.ForeignKey("compliance_assessments.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("control_id", UUID(as_uuid=True),
                  sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("result", control_result, nullable=False, server_default="NOT_ASSESSED"),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("assets_in_scope", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_failing", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("assessment_id", "control_id", name="uq_result_per_control_per_assessment"),
    )
    op.create_index("ix_compliance_results_assessment", "compliance_results", ["assessment_id", "result"])

    op.create_table(
        "compliance_exceptions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("control_id", UUID(as_uuid=True),
                  sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("compensating_controls", sa.Text(), nullable=False, server_default=""),
        sa.Column("approved_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "control_attestations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("control_id", UUID(as_uuid=True),
                  sa.ForeignKey("compliance_controls.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("evidence_reference", sa.Text(), nullable=False, server_default=""),
        sa.Column("attested_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False),
        # Required: a statement made two years ago about something nobody has
        # looked at since is not evidence of current compliance.
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_met", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

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
    op.drop_table("control_attestations")
    op.drop_table("compliance_exceptions")
    op.drop_index("ix_compliance_results_assessment", table_name="compliance_results")
    op.drop_table("compliance_results")
    op.drop_table("compliance_assessments")

    op.add_column("compliance_controls", sa.Column("framework_id", UUID(as_uuid=True), nullable=True))
    op.add_column("compliance_controls", sa.Column("control_code", sa.String(50), nullable=True))
    op.add_column("compliance_controls", sa.Column("status", sa.String(50), nullable=True))
    op.execute(
        """
        UPDATE compliance_controls c
        SET framework_id = r.framework_id, control_code = c.code, status = 'not_started'
        FROM compliance_requirements r
        WHERE r.id = c.requirement_id
        """
    )
    op.execute("DELETE FROM compliance_controls WHERE framework_id IS NULL")
    op.alter_column("compliance_controls", "framework_id", nullable=False)
    op.alter_column("compliance_controls", "control_code", nullable=False)
    op.create_foreign_key(
        "compliance_controls_framework_id_fkey", "compliance_controls",
        "compliance_frameworks", ["framework_id"], ["id"], ondelete="CASCADE",
    )
    op.drop_constraint("uq_control_code_per_requirement", "compliance_controls", type_="unique")
    op.drop_index("ix_compliance_controls_requirement_id", table_name="compliance_controls")
    op.drop_constraint("fk_control_requirement", "compliance_controls", type_="foreignkey")
    for column in ("check_parameters", "check_type", "guidance", "description", "code", "requirement_id"):
        op.drop_column("compliance_controls", column)

    op.drop_table("compliance_requirements")

    op.drop_constraint("uq_framework_slug_per_org", "compliance_frameworks", type_="unique")
    for column in ("last_assessed_at", "is_enabled", "source", "description", "version", "slug"):
        op.drop_column("compliance_frameworks", column)

    for type_name in ("checktype", "controlresult"):
        op.execute(f"DROP TYPE IF EXISTS {type_name}")
