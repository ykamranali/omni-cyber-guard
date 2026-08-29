import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SiteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    location: str | None
    latitude: float | None
    longitude: float | None
    created_at: datetime
    network_count: int = 0
    asset_count: int = 0


class SiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    location: str | None = None
    # Coordinates are recorded only when an operator supplies them. They are
    # never derived from an IP address, which for a private range would be a
    # confident fabrication.
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)


class SiteUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    location: str | None = None
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)


class NetworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    site_id: uuid.UUID | None
    name: str
    cidr: str
    vlan_id: int | None
    description: str
    is_internet_facing: bool
    is_authorized_scope: bool
    authorization_note: str
    created_at: datetime
    asset_count: int = 0


class NetworkCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    cidr: str
    site_id: uuid.UUID | None = None
    vlan_id: int | None = Field(default=None, ge=0, le=4094)
    description: str = ""
    is_internet_facing: bool = False
    is_authorized_scope: bool = False
    authorization_note: str = ""

    @field_validator("cidr")
    @classmethod
    def valid_cidr(cls, value: str) -> str:
        import ipaddress

        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"'{value}' is not a valid CIDR range.") from exc


class NetworkUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    # Editing a range was impossible: this model had no cidr field, and Pydantic
    # discards unknown keys rather than complaining, so the edit form appeared
    # to save and the range never moved.
    cidr: str | None = None
    site_id: uuid.UUID | None = None
    vlan_id: int | None = Field(default=None, ge=0, le=4094)
    description: str | None = None
    is_internet_facing: bool | None = None
    is_authorized_scope: bool | None = None
    authorization_note: str | None = None

    @field_validator("cidr")
    @classmethod
    def valid_cidr(cls, value: str | None) -> str | None:
        if value is None:
            return None
        import ipaddress

        try:
            return str(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"'{value}' is not a valid CIDR range.") from exc
