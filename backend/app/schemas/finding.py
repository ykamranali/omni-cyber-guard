import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.finding import Confidence, FindingClass, FindingStatus, Severity


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    asset_service_id: uuid.UUID | None
    fingerprint: str

    title: str
    description: str
    #: Verbatim scanner output. What separates a claim from an assertion.
    evidence: str

    #: What kind of claim this is — an open port and a matched CVE are not the
    #: same assertion and are not presented as if they were.
    finding_class: FindingClass
    #: How firmly the evidence supports it.
    confidence: Confidence

    cve_id: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cwe_id: str | None
    epss_score: float | None
    is_known_exploited: bool
    exploit_available: bool
    intelligence_synced_at: datetime | None

    affected_product: str | None
    affected_version: str | None

    severity: Severity
    status: FindingStatus
    is_false_positive: bool
    remediation_guidance: str
    source: str

    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    resolved_at: datetime | None

    scan_job_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class FindingCreate(BaseModel):
    asset_id: uuid.UUID
    title: str
    description: str = ""
    evidence: str = ""
    finding_class: FindingClass = FindingClass.INFORMATIONAL
    confidence: Confidence = Confidence.POSSIBLE
    cve_id: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwe_id: str | None = None
    severity: Severity = Severity.MEDIUM
    remediation_guidance: str = ""
    source: str = "manual"
    scan_job_id: uuid.UUID | None = None


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    is_false_positive: bool | None = None
    remediation_guidance: str | None = None
    severity: Severity | None = None
