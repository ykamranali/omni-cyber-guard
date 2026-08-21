import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class TargetStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScanTarget(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One target within a scan job.

    A scan job previously held a single `target_cidr` string, so a job covering
    several ranges could only report one aggregate outcome — a partial failure
    was indistinguishable from a clean run. Each target now carries its own
    status and error, so "3 of 4 ranges scanned, 1 unreachable" is expressible.
    """
    __tablename__ = "scan_targets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[TargetStatus] = mapped_column(Enum(TargetStatus), default=TargetStatus.PENDING)

    hosts_discovered: Mapped[int] = mapped_column(Integer, default=0)
    findings_generated: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
