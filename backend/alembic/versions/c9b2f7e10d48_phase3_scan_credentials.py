"""Phase 3: link a scan job to the credential profile it authenticates with.

Revision ID: c9b2f7e10d48
Revises: b7e4d1a90c35
Create Date: 2026-08-21

Only the reference is stored. The secret stays in credential_profiles as
ciphertext and is decrypted once, at scan time, by
app/services/credential_access.py — which writes an audit record naming the
scan and the target.
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "c9b2f7e10d48"
down_revision = "b7e4d1a90c35"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("credential_profile_id", UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        "fk_scan_jobs_credential_profile",
        "scan_jobs", "credential_profiles",
        ["credential_profile_id"], ["id"],
        # Deleting a credential must not delete the record of scans that used
        # it — the audit trail is the point.
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_scan_jobs_credential_profile", "scan_jobs", type_="foreignkey")
    op.drop_column("scan_jobs", "credential_profile_id")
