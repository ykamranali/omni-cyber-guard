"""Phase 1 (Truth & Foundation): add finding evidence, purge fabricated
findings from the removed openvas/zap engines, add blocked_ips table.

Revision ID: a1f0c3d29b74
Revises: c13705bb69fc
Create Date: 2026-08-21

Context
-------
The `openvas` and `zap` scanner modules contained no real integration. They
emitted hardcoded findings (invented CVE IDs, invented evidence strings, and
claims of successful SQL injection) which were persisted as ordinary Finding
rows and counted on the dashboard. Those modules were removed; this migration
removes the data they produced so that no fabricated security result survives
in the database.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "a1f0c3d29b74"
down_revision = "c13705bb69fc"
branch_labels = None
depends_on = None

FABRICATED_SOURCES = ("openvas", "zap")


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. Findings gain a first-class evidence column.
    #
    # Evidence was previously concatenated into the free-text description,
    # which made it impossible to distinguish an observation from a
    # narrative. app/agents/security_engineer.py already read
    # `finding.evidence` and crashed with AttributeError because the column
    # did not exist.
    # ------------------------------------------------------------------
    op.add_column(
        "findings",
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
    )

    conn = op.get_bind()

    # ------------------------------------------------------------------
    # 2. Purge fabricated findings.
    # ------------------------------------------------------------------
    conn.execute(
        sa.text("DELETE FROM findings WHERE source IN :sources").bindparams(
            sa.bindparam("sources", value=FABRICATED_SOURCES, expanding=True)
        )
    )

    # ------------------------------------------------------------------
    # 3. Remove the placeholder assets those fake scans created.
    #
    # The fake-scanner code path invented an Asset whose ip_address was the
    # literal scan target string. Only assets that (a) belong to an
    # openvas/zap scan job and (b) have no findings left are removed — a
    # real host discovered by nmap and later re-touched by a fake scan keeps
    # its record.
    # ------------------------------------------------------------------
    conn.execute(
        sa.text(
            """
            DELETE FROM assets a
            USING scan_jobs sj
            WHERE a.scan_job_id = sj.id
              AND sj.engine IN :sources
              AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id)
            """
        ).bindparams(sa.bindparam("sources", value=FABRICATED_SOURCES, expanding=True))
    )

    # Detach anything real that still points at a fabricated scan job.
    for table in ("assets", "findings"):
        conn.execute(
            sa.text(
                f"""
                UPDATE {table} SET scan_job_id = NULL
                WHERE scan_job_id IN (
                    SELECT id FROM scan_jobs WHERE engine IN :sources
                )
                """
            ).bindparams(sa.bindparam("sources", value=FABRICATED_SOURCES, expanding=True))
        )

    conn.execute(
        sa.text("DELETE FROM scan_jobs WHERE engine IN :sources").bindparams(
            sa.bindparam("sources", value=FABRICATED_SOURCES, expanding=True)
        )
    )

    # ------------------------------------------------------------------
    # 4. Blocked IPs move from an in-process Python set to the database.
    #
    # Previously both the blocklist and its metadata lived in module-level
    # globals, which meant the list was lost on restart and was never
    # visible to the worker process that actually inspected traffic — the
    # feature could not work in a multi-container deployment.
    #
    # These rows are recommendations for an operator (or a future firewall
    # integration) to act on. Omni Cyber Guard does not itself interrupt
    # traffic; the packet-forging "active defense" it previously used was
    # removed in the same cleanup.
    # ------------------------------------------------------------------
    op.create_table(
        "blocked_ips",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "organization_id",
            UUID(as_uuid=True),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "created_by_user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("ip_address", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="recommended"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "ip_address", name="uq_blocked_ip_per_org"),
    )

    # ------------------------------------------------------------------
    # 5. Real scan cancellation.
    #
    # `POST /scans/{id}/cancel` previously just wrote status=FAILED with the
    # message "Scan manually canceled by user" while the nmap subprocess kept
    # running to completion. The worker now polls `cancel_requested` and
    # terminates the child process, so the recorded outcome matches reality.
    # ------------------------------------------------------------------
    op.add_column(
        "scan_jobs",
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    # CANCELED is a distinct terminal state: a cancelled scan is not a failure.
    # ALTER TYPE ... ADD VALUE cannot be used in the same transaction that
    # later references the new label, hence the autocommit block.
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'CANCELED'")

    # ------------------------------------------------------------------
    # 6. Brute-force resistance on login.
    #
    # The login endpoint had no rate limit and no lockout, so credential
    # stuffing against it was unbounded. RATE_LIMIT_PER_MINUTE was defined in
    # config and never referenced anywhere in the codebase.
    # ------------------------------------------------------------------
    op.add_column(
        "users",
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "users",
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_attempts")
    op.drop_column("scan_jobs", "cancel_requested")
    # Postgres cannot remove a value from an enum type; CANCELED is left in
    # place. Any rows holding it are moved to FAILED so the older code path
    # can still read them.
    op.execute("UPDATE scan_jobs SET status = 'FAILED' WHERE status = 'CANCELED'")
    op.drop_table("blocked_ips")
    op.drop_column("findings", "evidence")
    # Deleted fabricated findings are intentionally not restored.
