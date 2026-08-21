import uuid
from datetime import date, datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, Date, DateTime, Enum, ForeignKey, Index, Integer, String, Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class RemediationStatus(str, PyEnum):
    """
    The remediation workflow.

    The distinction between FIXED and VERIFIED is the whole point of this
    module. FIXED is a person saying they did the work. VERIFIED is a scan
    confirming the finding is no longer observable. A platform that treats
    those as the same thing reports work that may never have happened.
    """

    OPEN = "open"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    #: The engineer says the work is done. Not yet confirmed.
    FIXED = "fixed"
    #: A rescan has been requested and has not yet reported.
    AWAITING_VERIFICATION = "awaiting_verification"
    #: A scan ran and no longer observes the finding.
    VERIFIED = "verified"
    CLOSED = "closed"
    CANCELLED = "cancelled"


#: Statuses that mean the task is no longer active work.
TERMINAL_STATUSES = frozenset({
    RemediationStatus.VERIFIED,
    RemediationStatus.CLOSED,
    RemediationStatus.CANCELLED,
})


class RemediationPriority(str, PyEnum):
    URGENT = "urgent"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationTask(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A unit of remediation work against one finding.

    Tasks reference the finding rather than copying it, so severity or
    intelligence changing on the finding is reflected here without a sync step.
    """

    __tablename__ = "remediation_tasks"
    __table_args__ = (
        Index("ix_remediation_org_status", "organization_id", "status"),
        Index("ix_remediation_due", "organization_id", "due_date"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")

    status: Mapped[RemediationStatus] = mapped_column(
        Enum(RemediationStatus), default=RemediationStatus.OPEN, server_default="OPEN"
    )
    priority: Mapped[RemediationPriority] = mapped_column(
        Enum(RemediationPriority), default=RemediationPriority.MEDIUM, server_default="MEDIUM"
    )

    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    #: Derived from severity and the organization's SLA policy at creation time.
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    sla_days: Mapped[int | None] = mapped_column(Integer, nullable=True)

    #: When the engineer marked it fixed, and when a scan confirmed it.
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: The scan that established the finding was gone. Without this, "verified"
    #: is just another word someone typed.
    verified_by_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Reference to an external tracker, when an integration created one.
    external_ticket_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    external_ticket_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_system: Mapped[str | None] = mapped_column(String(64), nullable=True)

    notes: Mapped[str] = mapped_column(Text, default="", server_default="")

    finding: Mapped["Finding"] = relationship("Finding")

    @property
    def is_overdue(self) -> bool:
        if self.due_date is None or self.status in TERMINAL_STATUSES:
            return False
        return self.due_date < date.today()


class AcceptanceStatus(str, PyEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RiskAcceptance(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A recorded decision to live with a finding.

    Risk acceptance is a governance act, not a status change. It therefore
    carries a reason, a named approver, and an expiry — an acceptance with no
    end date is indistinguishable from having forgotten about it. When it
    expires the finding returns to open, which is the behaviour that makes the
    expiry mean anything.
    """

    __tablename__ = "risk_acceptances"
    __table_args__ = (
        Index("ix_risk_acceptance_org_status", "organization_id", "status"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    reason: Mapped[str] = mapped_column(Text, nullable=False)
    #: Business justification distinct from the technical reason, e.g. a change
    #: freeze or a compensating control already in place.
    compensating_controls: Mapped[str] = mapped_column(Text, default="", server_default="")

    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    #: Who signed it off. Recorded separately from the requester so the
    #: separation of duties is visible in the audit trail.
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    expires_at: Mapped[date] = mapped_column(Date, nullable=False)

    status: Mapped[AcceptanceStatus] = mapped_column(
        Enum(AcceptanceStatus), default=AcceptanceStatus.ACTIVE, server_default="ACTIVE"
    )
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str] = mapped_column(Text, default="", server_default="")

    finding: Mapped["Finding"] = relationship("Finding")

    @property
    def is_expired(self) -> bool:
        return self.status is AcceptanceStatus.ACTIVE and self.expires_at < date.today()
