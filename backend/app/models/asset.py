import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.asset_tag import asset_tag_links
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class AssetType(str, PyEnum):
    """
    Device classification.

    Deliberately broader than the original four categories: an estate is not
    made of servers and workstations. A camera, a PLC or a VoIP handset
    misclassified as "other" is invisible to risk prioritisation.
    """
    SERVER = "server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    FIREWALL = "firewall"
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    PRINTER = "printer"
    CAMERA = "camera"
    NVR = "nvr"
    NAS = "nas"
    PBX = "pbx"
    VOIP = "voip"
    IOT_DEVICE = "iot_device"
    OT_DEVICE = "ot_device"
    MOBILE_DEVICE = "mobile_device"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    WEB_SERVER = "web_server"
    DATABASE = "database"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    HYPERVISOR = "hypervisor"
    OTHER = "other"


class AssetStatus(str, PyEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    QUARANTINED = "quarantined"


class Criticality(str, PyEnum):
    """Business importance, set by an operator. Never inferred."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNASSIGNED = "unassigned"


class DataSensitivity(str, PyEnum):
    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNASSIGNED = "unassigned"


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "assets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True
    )
    network_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("networks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # --- Identity -------------------------------------------------------
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType), default=AssetType.OTHER)
    status: Mapped[AssetStatus] = mapped_column(Enum(AssetStatus), default=AssetStatus.ACTIVE)

    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    serial_number: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # --- Fingerprinting -------------------------------------------------
    # How confident the classification is, 0-100, and the signals behind it.
    # A classification is never presented without the evidence that produced
    # it — "Network Switch, 94%, from SNMP sysObjectID + MAC OUI" is useful;
    # an unqualified "Network Switch" is a guess dressed as a fact.
    fingerprint_confidence: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    fingerprint_evidence: Mapped[list] = mapped_column(JSON, default=list)

    # --- Business context (operator-assigned) ---------------------------
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality), default=Criticality.UNASSIGNED, server_default="UNASSIGNED"
    )
    data_sensitivity: Mapped[DataSensitivity] = mapped_column(
        Enum(DataSensitivity), default=DataSensitivity.UNASSIGNED, server_default="UNASSIGNED"
    )
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    is_production: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Legacy free-text site label, retained so existing records keep their
    # value until they are linked to a Site row.
    site: Mapped[str | None] = mapped_column(String(255), nullable=True)

    latitude: Mapped[float | None] = mapped_column(nullable=True)
    longitude: Mapped[float | None] = mapped_column(nullable=True)

    # --- Lifecycle ------------------------------------------------------
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # --- Scoring --------------------------------------------------------
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    exposure_score: Mapped[float] = mapped_column(Float, default=0.0, server_default="0")
    # The contributor breakdown behind exposure_score. Populated by the
    # exposure engine so every score can explain itself.
    exposure_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)
    exposure_calculated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Free-text tags kept for backwards compatibility; structured tags live in
    # asset_tags / asset_tag_links.
    tags: Mapped[list] = mapped_column(JSON, default=list)
    custom_fields: Mapped[dict] = mapped_column(JSON, default=dict)

    # --- Relationships --------------------------------------------------
    organization: Mapped["Organization"] = relationship(back_populates="assets")
    scan_job: Mapped["ScanJob"] = relationship("ScanJob")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    interfaces: Mapped[list["AssetInterface"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    services: Mapped[list["AssetService"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    software: Mapped[list["AssetSoftware"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    tag_links: Mapped[list["AssetTag"]] = relationship(
        secondary=asset_tag_links, back_populates="assets"
    )
