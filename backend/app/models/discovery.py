import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class AttackSurfaceDomain(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """External attack surface discovered domains and SSL cert info."""
    __tablename__ = "attack_surface_domains"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_addresses: Mapped[str] = mapped_column(String(512), default="", server_default="")
    registrar: Mapped[str] = mapped_column(String(255), default="", server_default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    
    # SSL Certificate info
    cert_issuer: Mapped[str] = mapped_column(String(255), default="", server_default="")
    cert_valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CloudResource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Cloud resources discovered from CSPM integrations."""
    __tablename__ = "cloud_resources"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True) # AWS, Azure, GCP
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False) # e.g. AWS::EC2::Instance
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False) # Cloud-specific ID
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    region: Mapped[str] = mapped_column(String(100), default="", server_default="")
    
    status: Mapped[str] = mapped_column(String(50), default="ACTIVE", server_default="ACTIVE")
    compliance_status: Mapped[str] = mapped_column(String(50), default="UNKNOWN", server_default="UNKNOWN")


class IdentityProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Corporate identities discovered from IdP (Entra, Okta)."""
    __tablename__ = "identity_profiles"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), default="", server_default="")
    provider: Mapped[str] = mapped_column(String(50), nullable=False) # e.g. Entra ID, Okta
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    privilege_level: Mapped[str] = mapped_column(String(50), default="USER", server_default="USER")
