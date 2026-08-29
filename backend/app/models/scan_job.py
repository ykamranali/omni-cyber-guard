import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import DateTime, String, ForeignKey, Enum, Text, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class ScanStatus(str, PyEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


class ScanType(str, PyEnum):
    NETWORK_DISCOVERY = "network_discovery"  # host discovery (ping sweep)
    PORT_SERVICE_SCAN = "port_service_scan"  # host + open ports + service/version


class ScanJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A single authorized network scan job. Scans are restricted to private
    (RFC1918) address ranges and loopback only — this platform never scans
    arbitrary public targets, in line with its defensive-only design.
    """
    __tablename__ = "scan_jobs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    initiated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Credential used for an authenticated assessment, if any. Only the
    # reference is stored here; the secret stays in the vault and is decrypted
    # once, at scan time, with an audit record naming this job.
    credential_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("credential_profiles.id", ondelete="SET NULL"), nullable=True
    )

    target_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), default=ScanType.PORT_SERVICE_SCAN)
    engine: Mapped[str] = mapped_column(String(32), default="nmap", server_default="nmap")
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.QUEUED)

    # Set by the cancel endpoint; polled by the worker, which terminates the
    # running scanner subprocess. A cancelled scan reports CANCELED, never
    # COMPLETED and never FAILED.
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    #: Touched by the worker while the scan is actually running.
    #:
    #: Cancellation is cooperative — the worker polls cancel_requested — so a
    #: job whose worker died has nobody to act on it and would sit at RUNNING
    #: forever with a Stop button that does nothing. A stale heartbeat is how
    #: the platform tells "still working" apart from "nobody is holding this".
    heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    hosts_discovered: Mapped[int] = mapped_column(Integer, default=0)
    findings_generated: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_summary: Mapped[str] = mapped_column(Text, default="")
