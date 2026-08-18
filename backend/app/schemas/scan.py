import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, field_validator

from app.models.scan_job import ScanStatus, ScanType


class ScanJobCreate(BaseModel):
    target_cidr: str
    engine: str = "nmap"

    @field_validator("target_cidr")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("target_cidr is required")
        return v.strip()


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_cidr: str
    scan_type: ScanType
    engine: str
    status: ScanStatus
    hosts_discovered: int
    findings_generated: int
    error_message: str | None
    raw_summary: str
    created_at: datetime
    updated_at: datetime
