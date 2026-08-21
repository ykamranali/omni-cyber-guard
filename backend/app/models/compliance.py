"""
Compliance model: Framework → Requirement → Control → Check → Result.

The previous model was a `coverage_percent` float an operator typed in. That is
not a compliance posture; it is a number someone chose. This model derives every
result from assessment data the platform actually holds.

The rule that shapes the whole design: **absence of evidence is never a pass.**
A control the platform cannot evaluate is NOT_ASSESSED, and NOT_ASSESSED never
counts toward a compliance percentage. An auditor asking "how do you know?" must
get an answer that is not "we assumed".
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    JSON, Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ControlResult(str, PyEnum):
    """
    The outcome of evaluating one control.

    NOT_ASSESSED is the important one. It means the platform has no evidence
    either way — because the check needs data it does not have, or because no
    asset in scope has been scanned. It is deliberately distinct from PASS, and
    it is excluded from the compliance percentage rather than counted as
    compliant.
    """

    PASS = "pass"
    FAIL = "fail"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"
    #: An operator has accepted a deviation, with a justification and an expiry.
    EXCEPTION = "exception"


class CheckType(str, PyEnum):
    """
    How a control is evaluated.

    Each type maps to a query over data the platform already holds. A control
    whose type is MANUAL cannot be automated and requires an operator
    attestation with evidence — it is NOT_ASSESSED until one is recorded.
    """

    #: Fails if any in-scope asset exposes one of the listed ports.
    NO_EXPOSED_PORT = "no_exposed_port"
    #: Fails if any open finding matches the given source and check identifier.
    NO_OPEN_FINDING = "no_open_finding"
    #: Fails if open findings at or above a severity exceed an age in days.
    REMEDIATION_WITHIN_SLA = "remediation_within_sla"
    #: Fails if any in-scope asset lacks a required attribute.
    ASSET_ATTRIBUTE_REQUIRED = "asset_attribute_required"
    #: Fails if any asset has not been scanned within a number of days.
    ASSESSMENT_FRESHNESS = "assessment_freshness"
    #: Fails if any internet-facing asset has an open finding above a severity.
    NO_EXPOSED_SEVERITY = "no_exposed_severity"
    #: Requires a recorded operator attestation.
    MANUAL = "manual"


class ComplianceFramework(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "compliance_frameworks"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug", name="uq_framework_slug_per_org"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="", server_default="")
    description: Mapped[str] = mapped_column(Text, default="", server_default="")

    #: Where the control content came from, so an auditor can trace it.
    source: Mapped[str] = mapped_column(String(255), default="", server_default="")

    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")

    #: Retained from the previous model so historical values are not lost, but
    #: no longer written to. Coverage is computed from results.
    coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)

    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    requirements: Mapped[list["ComplianceRequirement"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )


class ComplianceRequirement(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A grouping within a framework — a CIS section, a NIST CSF function."""

    __tablename__ = "compliance_requirements"
    __table_args__ = (
        UniqueConstraint("framework_id", "code", name="uq_requirement_code_per_framework"),
    )

    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    code: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    display_order: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    framework: Mapped["ComplianceFramework"] = relationship(back_populates="requirements")
    controls: Mapped[list["ComplianceControl"]] = relationship(
        back_populates="requirement", cascade="all, delete-orphan"
    )


class ComplianceControl(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One testable control.

    `check_type` and `check_parameters` describe how it is evaluated. A control
    the platform cannot evaluate automatically is MANUAL and stays NOT_ASSESSED
    until an operator records an attestation — it never silently passes.
    """

    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint("requirement_id", "code", name="uq_control_code_per_requirement"),
    )

    requirement_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_requirements.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    code: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    guidance: Mapped[str] = mapped_column(Text, default="", server_default="")

    check_type: Mapped[CheckType] = mapped_column(
        Enum(CheckType), default=CheckType.MANUAL, server_default="MANUAL"
    )
    check_parameters: Mapped[dict] = mapped_column(JSON, default=dict)

    #: Legacy free-text status from the previous model, kept so existing notes
    #: survive the migration.
    evidence_notes: Mapped[str] = mapped_column(Text, default="")

    requirement: Mapped["ComplianceRequirement"] = relationship(back_populates="controls")


class ComplianceAssessment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One evaluation run of a framework, so results can be compared over time."""

    __tablename__ = "compliance_assessments"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    controls_total: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    controls_passed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    controls_failed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    controls_not_assessed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    controls_not_applicable: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    controls_exception: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    #: Passed / (passed + failed). Excludes NOT_ASSESSED entirely, so the figure
    #: never treats "we did not look" as "we are compliant".
    compliance_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    #: What share of the framework could be evaluated at all. A 100% compliance
    #: figure over 10% coverage is not the same as one over 90%, and both are
    #: shown.
    assessable_percent: Mapped[float] = mapped_column(Float, default=0.0, server_default="0")


class ComplianceResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    The outcome of one control in one assessment, with its evidence.

    `evidence` holds what the check actually found — the assets, the findings,
    the queries. A result without evidence is an opinion.
    """

    __tablename__ = "compliance_results"
    __table_args__ = (
        Index("ix_compliance_results_assessment", "assessment_id", "result"),
        UniqueConstraint("assessment_id", "control_id", name="uq_result_per_control_per_assessment"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_assessments.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    result: Mapped[ControlResult] = mapped_column(
        Enum(ControlResult), default=ControlResult.NOT_ASSESSED, server_default="NOT_ASSESSED"
    )

    #: One line an auditor can read.
    summary: Mapped[str] = mapped_column(Text, default="", server_default="")
    #: Structured detail: which assets, which findings, what the query returned.
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)

    assets_in_scope: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    assets_failing: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ComplianceException(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An accepted deviation from a control.

    Like a risk acceptance, an exception carries a reason, an approver and an
    expiry. Without an expiry it is indistinguishable from an unrecorded
    failure.
    """

    __tablename__ = "compliance_exceptions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    reason: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_controls: Mapped[str] = mapped_column(Text, default="", server_default="")
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")


class ControlAttestation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An operator's recorded statement that a manual control is met.

    Attestations expire. A statement made two years ago about a control nobody
    has looked at since is not evidence of current compliance, and the platform
    should not present it as such.
    """

    __tablename__ = "control_attestations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    #: What the operator asserts, and what they are basing it on.
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_reference: Mapped[str] = mapped_column(Text, default="", server_default="")

    attested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    attested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    is_met: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
