import uuid
from pydantic import BaseModel, ConfigDict, EmailStr


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    is_active: bool
    logo_url: str | None
    primary_color: str
    secondary_color: str
    footer_text: str
    subscription_plan: str
    license_seats: int


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
