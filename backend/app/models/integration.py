import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import String, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class IntegrationProvider(str, Enum):
    JIRA = "jira"
    SERVICENOW = "servicenow"


class TicketIntegration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ticket_integrations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    
    # We store the ID of the CredentialProfile that holds the API token/password
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("credential_profiles.id", ondelete="SET NULL"), nullable=True
    )
    
    project_key: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    credential: Mapped["CredentialProfile"] = relationship()
