"""Phase 12: grounded AI security engineer — transcripts, evidence, action gate.

Revision ID: b8e5a2f71c93
Revises: 42e91f847792
Create Date: 2026-08-22

The assistant previously left no record: a question went to a language model
with a context string, and the completion was returned. Nothing persisted, so
nothing could be reviewed, and there was no place to record that an answer had
been checked against the database at all.

These three tables make the assistant auditable. `agent_messages` stores which
retrievals ran and what the grounding check concluded, keeping a rejected draft
in `withheld_draft` — separate from `content`, so a fabricated answer can be
investigated without ever being served as one. `agent_action_proposals` is the
gate between the model wanting something done and it being done: a proposal is
inert until a human holding the named permission confirms it.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "b8e5a2f71c93"
down_revision = "42e91f847792"
branch_labels = None
depends_on = None

TENANT_TABLES = ["agent_conversations", "agent_messages", "agent_action_proposals"]

ENUMS = {
    "messagerole": ["USER", "ASSISTANT", "TOOL", "SYSTEM"],
    "groundingstatus": [
        "GROUNDED", "REJECTED", "NO_EVIDENCE", "UNAVAILABLE", "NOT_APPLICABLE",
    ],
    "proposalstatus": [
        "PROPOSED", "CONFIRMED", "REJECTED", "EXECUTED", "FAILED", "EXPIRED",
    ],
}


def upgrade() -> None:
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

    message_role = postgresql.ENUM(name="messagerole", create_type=False)
    grounding_status = postgresql.ENUM(name="groundingstatus", create_type=False)
    proposal_status = postgresql.ENUM(name="proposalstatus", create_type=False)

    op.create_table(
        "agent_conversations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_agent_conversations_org_user", "agent_conversations",
        ["organization_id", "user_id"],
    )

    op.create_table(
        "agent_messages",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("conversation_id", UUID(as_uuid=True),
                  sa.ForeignKey("agent_conversations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("role", message_role, nullable=False),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("tool_name", sa.String(100), nullable=True),
        sa.Column("tool_arguments", sa.JSON(), nullable=True),
        sa.Column("tool_row_count", sa.Integer(), nullable=True),
        sa.Column("evidence_refs", sa.JSON(), nullable=True),
        sa.Column("grounding_status", grounding_status, nullable=False,
                  server_default="NOT_APPLICABLE"),
        sa.Column("unsupported_refs", sa.JSON(), nullable=True),
        # Kept apart from `content` on purpose: a draft that failed grounding is
        # evidence about the model, not analysis, and must never be rendered as
        # an answer.
        sa.Column("withheld_draft", sa.Text(), nullable=False, server_default=""),
        sa.Column("provider", sa.String(64), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_agent_messages_conversation", "agent_messages",
        ["conversation_id", "created_at"],
    )

    op.create_table(
        "agent_action_proposals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("conversation_id", UUID(as_uuid=True),
                  sa.ForeignKey("agent_conversations.id", ondelete="CASCADE"),
                  nullable=True, index=True),
        sa.Column("message_id", UUID(as_uuid=True),
                  sa.ForeignKey("agent_messages.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        # Written by the action definition, never by the model, so what the
        # operator confirms is what the executor will do.
        sa.Column("effect_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("required_permission", sa.String(64), nullable=False),
        sa.Column("status", proposal_status, nullable=False, server_default="PROPOSED"),
        sa.Column("proposed_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by_user_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=False, server_default=""),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_agent_proposals_org_status", "agent_action_proposals",
        ["organization_id", "status"],
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
    op.drop_index("ix_agent_proposals_org_status", table_name="agent_action_proposals")
    op.drop_table("agent_action_proposals")
    op.drop_index("ix_agent_messages_conversation", table_name="agent_messages")
    op.drop_table("agent_messages")
    op.drop_index("ix_agent_conversations_org_user", table_name="agent_conversations")
    op.drop_table("agent_conversations")
    for type_name in ("proposalstatus", "groundingstatus", "messagerole"):
        op.execute(f"DROP TYPE IF EXISTS {type_name}")
