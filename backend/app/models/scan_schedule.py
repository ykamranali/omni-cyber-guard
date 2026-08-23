import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class ScanSchedule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Recurring schedule for authorized network scans.
    """
    __tablename__ = "scan_schedules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "0 2 * * *"
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Why the dispatcher last refused to run this schedule. A schedule that
    # cannot fire has to say so somewhere the operator can see; it previously
    # failed silently every minute with the reason going to stdout.
    last_error: Mapped[str] = mapped_column(Text, default="", server_default="")
    last_dispatched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
