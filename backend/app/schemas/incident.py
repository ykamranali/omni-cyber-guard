from pydantic import BaseModel, ConfigDict
import uuid
from typing import Optional
from datetime import datetime
from app.models.incident import IncidentStatus, IncidentSeverity

class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM

class IncidentCreate(IncidentBase):
    asset_id: Optional[uuid.UUID] = None

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assigned_to: Optional[uuid.UUID] = None
    resolution_notes: Optional[str] = None

class IncidentOut(IncidentBase):
    id: uuid.UUID
    organization_id: str
    status: IncidentStatus
    asset_id: Optional[uuid.UUID] = None
    assigned_to: Optional[uuid.UUID] = None
    resolution_notes: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
