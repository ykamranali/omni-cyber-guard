import uuid
from pydantic import BaseModel, EmailStr, ConfigDict


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    full_name: str
    is_active: bool
    is_super_admin: bool
    organization_id: uuid.UUID
    roles: list[str] = []


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role_names: list[str] = []


class UserUpdate(BaseModel):
    full_name: str | None = None
    is_active: bool | None = None
    role_names: list[str] | None = None
