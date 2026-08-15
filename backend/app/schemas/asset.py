import uuid
from pydantic import BaseModel, ConfigDict
from app.models.asset import AssetType, AssetStatus


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
    serial_number: str | None
    site: str | None
    department: str | None
    business_owner: str | None
    latitude: float | None
    longitude: float | None
    tags: list
    risk_score: float


class AssetCreate(BaseModel):
    hostname: str
    ip_address: str | None = None
    mac_address: str | None = None
    asset_type: AssetType = AssetType.OTHER
    status: AssetStatus = AssetStatus.ACTIVE
    operating_system: str | None = None
    vendor: str | None = None
    serial_number: str | None = None
    site: str | None = None
    department: str | None = None
    business_owner: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    tags: list[str] = []


class AssetUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    asset_type: AssetType | None = None
    status: AssetStatus | None = None
    operating_system: str | None = None
    vendor: str | None = None
    serial_number: str | None = None
    site: str | None = None
    department: str | None = None
    business_owner: str | None = None
    tags: list[str] | None = None
