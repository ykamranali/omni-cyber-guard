"""
Compliance response shapes.

`ComplianceFrameworkOut` deliberately no longer carries `coverage_percent` as a
writable number. Coverage is computed from control results; the previous model
let an operator type a figure, which is a claim rather than a posture.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ComplianceFrameworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    version: str
    description: str
    source: str
    is_enabled: bool
    last_assessed_at: datetime | None


class FrameworkSummary(BaseModel):
    """A framework with the outcome of its most recent assessment."""

    id: uuid.UUID
    name: str
    control_count: int
    #: Null until at least one control has been conclusively evaluated. Zero
    #: and null mean different things and are not conflated.
    compliance_percent: float | None
    #: How much of the framework could be evaluated at all. Always published
    #: alongside compliance_percent so the latter is never read alone.
    assessable_percent: float
    last_assessed_at: datetime | None
