import uuid
from sqlalchemy import String, ForeignKey, Text, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class ComplianceFramework(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "compliance_frameworks"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)  # ISO 27001, NIST CSF, CIS, PCI DSS, HIPAA, GDPR, SOC 2
    coverage_percent: Mapped[float] = mapped_column(Float, default=0.0)

    controls: Mapped[list["ComplianceControl"]] = relationship(back_populates="framework", cascade="all, delete-orphan")


class ComplianceControl(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "compliance_controls"

    framework_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False
    )
    control_code: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="not_started")  # not_started, in_progress, implemented, verified
    evidence_notes: Mapped[str] = mapped_column(Text, default="")

    framework: Mapped["ComplianceFramework"] = relationship(back_populates="controls")
