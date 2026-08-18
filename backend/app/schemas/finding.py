import uuid
from pydantic import BaseModel, ConfigDict
from datetime import datetime
from app.models.finding import Severity, FindingStatus


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    description: str
    cve_id: str | None
    cvss_score: float | None
    severity: Severity
    status: FindingStatus
    remediation_guidance: str
    source: str
    scan_job_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class FindingCreate(BaseModel):
    asset_id: uuid.UUID
    title: str
    description: str = ""
    cve_id: str | None = None
    cvss_score: float | None = None
    severity: Severity = Severity.MEDIUM
    remediation_guidance: str = ""
    source: str = "manual"
    scan_job_id: uuid.UUID | None = None


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    is_false_positive: bool | None = None
    remediation_guidance: str | None = None
