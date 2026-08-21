"""
Per-asset detail tables.

These replace the `custom_fields["open_ports"]` JSON blob, which could not be
queried, indexed, joined or trended. Services and software are first-class rows
so the platform can answer "which assets run OpenSSH < 9.0" with SQL rather
than by scanning JSON in Python.

Every row carries first_seen/last_seen, which is what makes change detection
("new port appeared", "service disappeared") possible at all.
"""
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class AssetInterface(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One network interface on an asset. A firewall or server may have several."""
    __tablename__ = "asset_interfaces"
    __table_args__ = (
        UniqueConstraint("asset_id", "ip_address", name="uq_interface_ip_per_asset"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Resolved from the MAC OUI registry, when the MAC is known.
    mac_vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    interface_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="interfaces")


class AssetService(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A listening service observed on an asset."""
    __tablename__ = "asset_services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_service_port_per_asset"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp", server_default="tcp")
    service_name: Mapped[str] = mapped_column(String(128), default="", server_default="")
    product: Mapped[str] = mapped_column(String(255), default="", server_default="")
    version: Mapped[str] = mapped_column(String(128), default="", server_default="")

    # Verbatim banner text, kept for evidence rather than paraphrased.
    banner: Mapped[str] = mapped_column(Text, default="", server_default="")
    # CPE string when one can be derived; NULL when it cannot. A guessed CPE
    # would silently mis-correlate CVEs, so it is left empty instead.
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)

    is_tls: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    state: Mapped[str] = mapped_column(String(32), default="open", server_default="open")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="services")


class AssetSoftware(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A software component identified on an asset.

    This is the join point for CVE correlation: `cpe` here is matched against
    the CPE ranges on a CVE record. Rows without a CPE are still useful for
    inventory but are excluded from automated correlation, because matching on
    a free-text product name produces false positives.
    """
    __tablename__ = "asset_software"
    __table_args__ = (
        UniqueConstraint("asset_id", "name", "version", name="uq_software_version_per_asset"),
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

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    vendor: Mapped[str] = mapped_column(String(255), default="", server_default="")
    version: Mapped[str] = mapped_column(String(128), default="", server_default="")
    cpe: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)

    # How this was identified: service_banner, package_manager, agent, manual.
    detection_method: Mapped[str] = mapped_column(String(64), default="service_banner", server_default="service_banner")
    evidence: Mapped[str] = mapped_column(Text, default="", server_default="")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    asset: Mapped["Asset"] = relationship(back_populates="software")
