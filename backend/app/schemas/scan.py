import uuid
from datetime import datetime
from pydantic import BaseModel, ConfigDict, field_validator

from app.models.scan_job import ScanStatus, ScanType

def _registered_engines() -> tuple[str, ...]:
    """
    Engines the platform will accept, read from the live adapter registry.

    Derived rather than hardcoded so removing an adapter removes the engine and
    adding one makes it selectable, with no second list to keep in sync.
    """
    from app.scanners.manager import ScannerManager

    return tuple(sorted(ScannerManager.get_all_scanners()))


class ScanJobCreate(BaseModel):
    target_cidr: str
    engine: str = "nmap"
    #: Credential profile for an authenticated assessment. Required by engines
    #: that declare the CREDENTIALED capability.
    credential_profile_id: uuid.UUID | None = None

    @field_validator("target_cidr")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("target_cidr is required")
        return v.strip()

    @field_validator("engine")
    @classmethod
    def known_engine(cls, v: str) -> str:
        v = (v or "").strip().lower()
        engines = _registered_engines()
        if v not in engines:
            raise ValueError(
                f"Unknown scan engine '{v}'. Registered engines: {', '.join(engines) or 'none'}."
            )
        return v


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_cidr: str
    scan_type: ScanType
    engine: str
    status: ScanStatus
    credential_profile_id: uuid.UUID | None
    cancel_requested: bool
    hosts_discovered: int
    findings_generated: int
    error_message: str | None
    raw_summary: str
    created_at: datetime
    updated_at: datetime
