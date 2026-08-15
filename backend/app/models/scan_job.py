import uuid
from enum import Enum as PyEnum
from sqlalchemy import String, ForeignKey, Enum, Text, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class ScanStatus(str, PyEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


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

    target_cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_type: Mapped[ScanType] = mapped_column(Enum(ScanType), default=ScanType.PORT_SERVICE_SCAN)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.QUEUED)

    hosts_discovered: Mapped[int] = mapped_column(Integer, default=0)
    findings_generated: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_summary: Mapped[str] = mapped_column(Text, default="")
