import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.asset import AssetStatus, AssetType, Criticality, DataSensitivity


class AssetServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    port: int
    protocol: str
    service_name: str
    product: str
    version: str
    banner: str
    cpe: str | None
    is_tls: bool
    state: str
    first_seen: datetime
    last_seen: datetime


class AssetSoftwareOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    vendor: str
    version: str
    cpe: str | None
    detection_method: str
    evidence: str
    first_seen: datetime
    last_seen: datetime


class AssetInterfaceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str
    mac_address: str | None
    mac_vendor: str | None
    interface_name: str | None
    is_primary: bool
    first_seen: datetime
    last_seen: datetime


class AssetTagOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    color: str
    description: str


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    ip_address: str | None
    mac_address: str | None
    asset_type: AssetType
    status: AssetStatus
    operating_system: str | None
    vendor: str | None
    model: str | None
    serial_number: str | None

    # A classification is always published with how sure it is and why. A bare
    # device type that turns out to be a misread banner is worse than "unknown".
    fingerprint_confidence: int
    fingerprint_evidence: list

    criticality: Criticality
    data_sensitivity: DataSensitivity
    is_internet_facing: bool
    is_production: bool

    site_id: uuid.UUID | None
    network_id: uuid.UUID | None
    site: str | None
    department: str | None
    business_owner: str | None
    latitude: float | None
    longitude: float | None

    first_seen: datetime
    last_seen: datetime

    tags: list
    risk_score: float
    exposure_score: float
    exposure_breakdown: dict
    exposure_calculated_at: datetime | None
    scan_job_id: uuid.UUID | None


class AssetDetailOut(AssetOut):
    """Full asset view, including the inventory rows behind it."""

    interfaces: list[AssetInterfaceOut] = []
    services: list[AssetServiceOut] = []
    software: list[AssetSoftwareOut] = []
    tag_links: list[AssetTagOut] = []
    open_finding_count: int = 0
    critical_finding_count: int = 0


class AssetCreate(BaseModel):
    hostname: str
    ip_address: str | None = None
    mac_address: str | None = None
    asset_type: AssetType = AssetType.OTHER
    status: AssetStatus = AssetStatus.ACTIVE
    operating_system: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    criticality: Criticality = Criticality.UNASSIGNED
    data_sensitivity: DataSensitivity = DataSensitivity.UNASSIGNED
    is_internet_facing: bool = False
    is_production: bool = False
    site_id: uuid.UUID | None = None
    network_id: uuid.UUID | None = None
    site: str | None = None
    department: str | None = None
    business_owner: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    tags: list[str] = []
    scan_job_id: uuid.UUID | None = None


class AssetUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    asset_type: AssetType | None = None
    status: AssetStatus | None = None
    operating_system: str | None = None
    vendor: str | None = None
    model: str | None = None
    serial_number: str | None = None
    criticality: Criticality | None = None
    data_sensitivity: DataSensitivity | None = None
    is_internet_facing: bool | None = None
    is_production: bool | None = None
    site_id: uuid.UUID | None = None
    network_id: uuid.UUID | None = None
    site: str | None = None
    department: str | None = None
    business_owner: str | None = None
    tags: list[str] | None = None


class AssetTagCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    color: str = "#64748B"
    description: str = ""


class AssetTagAssignment(BaseModel):
    tag_ids: list[uuid.UUID]
