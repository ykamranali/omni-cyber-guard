import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.finding import Severity
from app.models.remediation import AcceptanceStatus, RemediationPriority, RemediationStatus


class RemediationTaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    asset_id: uuid.UUID | None
    title: str
    description: str
    status: RemediationStatus
    priority: RemediationPriority
    assigned_to_user_id: uuid.UUID | None
    due_date: date | None
    sla_days: int | None
    fixed_at: datetime | None
    verified_at: datetime | None
    #: Present only when a scan established the fix. Its absence is meaningful.
    verified_by_scan_job_id: uuid.UUID | None
    closed_at: datetime | None
    external_ticket_ref: str | None
    external_ticket_url: str | None
    notes: str
    created_at: datetime

    # Enriched by the endpoint for display.
    is_overdue: bool = False
    days_until_due: int | None = None
    finding_severity: Severity | None = None
    finding_cve_id: str | None = None
    asset_hostname: str | None = None
    assigned_to_name: str | None = None


class RemediationTaskCreate(BaseModel):
    finding_id: uuid.UUID
    assigned_to_user_id: uuid.UUID | None = None
    #: Overrides the SLA-derived date. Recorded as an override in the audit log.
    due_date: date | None = None


class RemediationTaskUpdate(BaseModel):
    assigned_to_user_id: uuid.UUID | None = None
    priority: RemediationPriority | None = None
    due_date: date | None = None
    notes: str | None = None


class MarkFixedRequest(BaseModel):
    note: str = ""


class CloseTaskRequest(BaseModel):
    #: Required. Closing without scan verification is permitted but must be
    #: justified, and is reported separately from verified closure.
    reason: str = Field(min_length=1, max_length=2000)


class RiskAcceptanceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    reason: str
    compensating_controls: str
    requested_by_user_id: uuid.UUID | None
    approved_by_user_id: uuid.UUID | None
    approved_at: datetime | None
    expires_at: date
    status: AcceptanceStatus
    revoked_at: datetime | None
    revocation_reason: str
    created_at: datetime

    days_until_expiry: int | None = None
    finding_title: str | None = None
    approved_by_name: str | None = None


class RiskAcceptanceCreate(BaseModel):
    finding_id: uuid.UUID
    reason: str = Field(min_length=1, max_length=2000)
    compensating_controls: str = ""
    #: Mandatory. An acceptance with no end date is indistinguishable from
    #: having forgotten about it.
    expires_at: date

    @field_validator("expires_at")
    @classmethod
    def must_be_in_the_future(cls, value: date) -> date:
        if value <= date.today():
            raise ValueError("A risk acceptance must expire on a future date.")
        return value


class RevokeAcceptanceRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


class SlaPolicyUpdate(BaseModel):
    """Remediation windows in days, keyed by severity."""

    critical: int | None = Field(default=None, ge=1, le=3650)
    high: int | None = Field(default=None, ge=1, le=3650)
    medium: int | None = Field(default=None, ge=1, le=3650)
    low: int | None = Field(default=None, ge=1, le=3650)
    info: int | None = Field(default=None, ge=1, le=3650)
