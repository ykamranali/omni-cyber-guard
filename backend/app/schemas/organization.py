import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    logo_url: str | None
    # Present so the branding provider can set the tab icon; it was stored and
    # editable but never returned, so nothing could read it back.
    favicon_url: str | None = None
    primary_color: str
    secondary_color: str
    footer_text: str
    subscription_plan: str
    license_seats: int
    slack_webhook_url: str | None
    teams_webhook_url: str | None
    sso_provider: str
    sso_metadata_url: str | None
    created_at: datetime | None = None


class OrganizationUpdate(BaseModel):
    """Platform-level edits to any organization. Super administrators only."""
    name: str | None = Field(default=None, min_length=1, max_length=255)
    is_active: bool | None = None


class OrganizationLicenseUpdate(BaseModel):
    """
    Plan and seat count.

    Deliberately separate from OrganizationSettingsUpdate and restricted to
    super administrators: an organization administrator raising their own seat
    limit is not a setting, it is a billing decision.
    """
    subscription_plan: str | None = Field(default=None, min_length=1, max_length=50)
    license_seats: int | None = Field(default=None, ge=0, le=100000)


class OrganizationCreate(BaseModel):
    name: str
    slug: str
    subscription_plan: str = "trial"
    license_seats: int = 10
    admin_email: EmailStr
    admin_full_name: str
    admin_password: str

class OrganizationBrandingUpdate(BaseModel):
    logo_url: str | None = None
    favicon_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    footer_text: str | None = None

class OrganizationSettingsUpdate(BaseModel):
    slack_webhook_url: str | None = None
    teams_webhook_url: str | None = None
    sso_provider: str | None = None
    sso_metadata_url: str | None = None
