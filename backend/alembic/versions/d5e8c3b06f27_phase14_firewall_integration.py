"""Phase 14: firewall integration and bounded automatic blocking.

Revision ID: d5e8c3b06f27
Revises: c4d7b2a95e18
Create Date: 2026-08-22

The platform records block decisions and does not interrupt traffic itself — an
earlier version tried to, by forging TCP RST packets with a spoofed source
address, and that was removed. This table is the honest version of the same
capability: a firewall the operator connects, with credentials they supply,
becomes the thing that enforces.

Three of these columns exist specifically to bound automatic blocking, and they
are in the schema rather than in application logic because a platform that can
cut off network access on its own judgement should not have those limits be
editable by a code change alone:

    auto_block_enabled            off unless an operator turns it on
    auto_block_min_severity       only events at or above this qualify
    never_block                   addresses that are never blocked, whatever
                                  happens
    auto_block_duration_minutes   every automatic block expires by itself

The secret is stored as Fernet ciphertext under the same vault key as scan
credentials, and no API response schema returns it in any form.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID

revision = "d5e8c3b06f27"
down_revision = "c4d7b2a95e18"
branch_labels = None
depends_on = None

ENUMS = {
    "firewallvendor": ["OPNSENSE", "PFSENSE", "FORTIGATE"],
    "firewallstatus": ["NOT_CONFIGURED", "ERROR", "CONNECTED"],
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

    vendor = postgresql.ENUM(name="firewallvendor", create_type=False)
    fw_status = postgresql.ENUM(name="firewallstatus", create_type=False)

    op.create_table(
        "firewall_integrations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", UUID(as_uuid=True),
                  sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("vendor", vendor, nullable=False),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("api_identity", sa.String(255), nullable=False, server_default=""),
        # Fernet ciphertext. Never returned by any response schema.
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("blocklist_object", sa.String(120), nullable=False, server_default=""),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default="true"),
        # Only a successful round trip to the firewall sets CONNECTED.
        sa.Column("status", fw_status, nullable=False, server_default="NOT_CONFIGURED"),
        sa.Column("status_message", sa.Text(), nullable=False, server_default=""),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("auto_block_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("auto_block_min_severity", sa.String(16), nullable=False,
                  server_default="critical"),
        sa.Column("never_block", sa.JSON(), nullable=True),
        sa.Column("auto_block_duration_minutes", sa.Integer(), nullable=False,
                  server_default="60"),
        sa.Column("enforced_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "name", name="uq_firewall_integration_name"),
    )

    op.execute("ALTER TABLE firewall_integrations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE firewall_integrations FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON firewall_integrations
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
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON firewall_integrations")
    op.drop_table("firewall_integrations")
    for type_name in ("firewallstatus", "firewallvendor"):
        op.execute(f"DROP TYPE IF EXISTS {type_name}")
