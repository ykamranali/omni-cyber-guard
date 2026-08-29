"""Record a heartbeat on a running scan.

A scan is cancelled cooperatively: the endpoint sets cancel_requested and the
worker, which is polling, terminates the scanner process. That is the right
design while a worker is alive, and it has no answer at all when one is not.

Restart the worker mid-scan — a deploy, a crash, `docker compose restart` — and
the nmap subprocess dies with it while the row stays at RUNNING. Nothing owns
that job any more. The scan budget is enforced inside the task, so nothing
enforces it. Pressing Stop writes cancel_requested and returns success, and the
row never moves, because the process that was meant to read the flag no longer
exists. The operator sees a scan running for hours and a Stop button that does
nothing.

heartbeat_at is what makes that observable: the worker touches it while the
scan is alive, so a stale heartbeat on a RUNNING row means the job was orphaned
rather than that it is slow.

Revision ID: a3f7c81d94e2
Revises: f0a91d3c7b62
"""
from alembic import op
import sqlalchemy as sa

revision = "a3f7c81d94e2"
down_revision = "f0a91d3c7b62"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_jobs",
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Partial index: the reaper only ever asks about running jobs, and scan
    # history grows without bound.
    op.execute(
        "CREATE INDEX ix_scan_jobs_running_heartbeat ON scan_jobs (heartbeat_at) "
        "WHERE status = 'RUNNING'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scan_jobs_running_heartbeat")
    op.drop_column("scan_jobs", "heartbeat_at")
