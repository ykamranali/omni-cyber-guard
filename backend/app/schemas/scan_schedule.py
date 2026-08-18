import uuid
from datetime import datetime
from pydantic import BaseModel, Field

class ScanScheduleBase(BaseModel):
    name: str = Field(..., max_length=255)
    target_cidr: str = Field(..., max_length=64)
    cron_expression: str = Field(..., max_length=64)
    is_active: bool = True

class ScanScheduleCreate(ScanScheduleBase):
    pass

class ScanScheduleUpdate(BaseModel):
    name: str | None = Field(None, max_length=255)
    target_cidr: str | None = Field(None, max_length=64)
    cron_expression: str | None = Field(None, max_length=64)
    is_active: bool | None = None

class ScanScheduleResponse(ScanScheduleBase):
    id: uuid.UUID
    organization_id: uuid.UUID
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
