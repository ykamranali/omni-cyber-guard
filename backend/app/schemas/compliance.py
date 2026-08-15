import uuid
from pydantic import BaseModel, ConfigDict


class ComplianceFrameworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    coverage_percent: float


class ComplianceFrameworkUpdate(BaseModel):
    coverage_percent: float
