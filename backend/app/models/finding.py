import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, PyEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    MITIGATED = "mitigated"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


# Statuses that mean "this is no longer an open item".
CLOSED_STATUSES = frozenset({
    FindingStatus.REMEDIATED,
    FindingStatus.FALSE_POSITIVE,
    FindingStatus.ACCEPTED_RISK,
})


class FindingClass(str, PyEnum):
    """
    What kind of claim this finding makes.

    This distinction is not cosmetic. "Port 3389 is open" and "this host is
    vulnerable to CVE-2019-0708" are different assertions with different
    evidentiary weight, and presenting them as the same kind of row overstates
    what a port scan proves. The class travels with the finding into scoring,
    reporting and the UI.
    """
    # Backed by a CVE or a vendor advisory matched to identified software.
    VULNERABILITY = "vulnerability"
    # An observed exposure: a service reachable where it should not be.
    EXPOSURE = "exposure"
    # A configuration that deviates from a hardening standard.
    MISCONFIGURATION = "misconfiguration"
    # A failed control check within a compliance framework.
    COMPLIANCE = "compliance"
    # Information recorded for context; not itself a defect.
    INFORMATIONAL = "informational"


class Confidence(str, PyEnum):
    """
    How firmly the evidence supports the finding.

    CONFIRMED is reserved for a direct observation of the defect itself. A
    version banner suggesting a vulnerable release is PROBABLE, not CONFIRMED —
    the banner may be patched-but-unbumped, or deliberately altered.
    """
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"


class Finding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A security finding correlated to an asset.

    Populated by authorized scanner integrations or by manual entry — never by
    exploit code, and never invented.

    Deduplication
    -------------
    `fingerprint` is a stable identity derived from (asset, class, source,
    vulnerability reference, service location). Re-running a scan updates
    `last_seen` and `occurrence_count` on the existing row rather than
    inserting a duplicate, which is what makes "open for 43 days" and
    "resolved since last scan" meaningful.
    """
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("asset_id", "fingerprint", name="uq_finding_fingerprint_per_asset"),
        Index("ix_findings_org_status_severity", "organization_id", "status", "severity"),
        Index("ix_findings_org_last_seen", "organization_id", "last_seen"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_service_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("asset_services.id", ondelete="SET NULL"), nullable=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # --- Identity -------------------------------------------------------
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    # Verbatim scanner output supporting the finding. Never paraphrased.
    evidence: Mapped[str] = mapped_column(Text, default="", server_default="")

    finding_class: Mapped[FindingClass] = mapped_column(
        Enum(FindingClass), default=FindingClass.INFORMATIONAL, server_default="INFORMATIONAL"
    )
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence), default=Confidence.POSSIBLE, server_default="POSSIBLE"
    )

    # --- Vulnerability references ---------------------------------------
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    # Correlated intelligence, copied at correlation time with its own
    # timestamp so a stale enrichment is visible rather than assumed current.
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_known_exploited: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    intelligence_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    affected_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # --- Workflow -------------------------------------------------------
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.MEDIUM)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.OPEN)
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    remediation_guidance: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(100), default="manual")

    # --- Lifecycle ------------------------------------------------------
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    # Set when a rescan no longer observes the finding. Distinct from a manual
    # status change: this is evidence of remediation, not an assertion of it.
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )

    asset: Mapped["Asset"] = relationship(back_populates="findings")
    scan_job: Mapped["ScanJob"] = relationship("ScanJob", foreign_keys=[scan_job_id])
