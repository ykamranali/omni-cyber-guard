import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Enum, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID

from app.db.session import Base
from app.models.mixins import TimestampMixin

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"

class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(String, ForeignKey("organizations.id"), nullable=False, index=True)
    
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False, index=True)
    severity = Column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False)
    
    # Optional relation to a specific asset or threat event
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=True)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    ai_playbook = Column(Text, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
