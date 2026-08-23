import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class AttackSurfaceDomain(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A domain the operator has declared in scope, and what probing it observed.

    The row is the authorization. Resolving a name and opening a TLS connection
    to it is an active reach-out to a third party, so a domain has to be
    registered here — by a named user, at a recorded time — before any probe
    runs against it. Nothing in the platform discovers domains on its own.
    """
    __tablename__ = "attack_surface_domains"
    __table_args__ = (
        UniqueConstraint("organization_id", "domain_name", name="uq_attack_surface_domain"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain_name: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    ip_addresses: Mapped[str] = mapped_column(String(512), default="", server_default="")
    # Requires a WHOIS or RDAP lookup, which this platform does not perform.
    # Left empty rather than filled with a stand-in; the field previously read
    # "Enumerated (Live)", which is not a registrar.
    registrar: Mapped[str] = mapped_column(String(255), default="", server_default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")

    # Who put this domain in scope, and when. Without both, an active probe has
    # no authorization behind it.
    authorized_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    authorized_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Null means never probed. Distinct from "probed and found nothing".
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # SSL Certificate info
    cert_issuer: Mapped[str] = mapped_column(String(255), default="", server_default="")
    cert_valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cert_valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CloudResource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Cloud resources read from a configured provider integration."""
    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "provider", "resource_id", name="uq_cloud_resource"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)  # AWS, Azure
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. AWS::EC2::Instance
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)  # Cloud-specific ID
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    region: Mapped[str] = mapped_column(String(100), default="", server_default="")

    status: Mapped[str] = mapped_column(String(50), default="", server_default="")
    # Reading an inventory says nothing about whether a resource is compliant.
    # Posture assessment is a separate capability that does not exist yet, so
    # this stays UNKNOWN rather than defaulting to a verdict.
    compliance_status: Mapped[str] = mapped_column(String(50), default="UNKNOWN", server_default="UNKNOWN")


class IdentityProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Corporate identities read from a configured directory integration."""
    __tablename__ = "identity_profiles"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "provider", "email", name="uq_identity_profile"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), default="", server_default="")
    provider: Mapped[str] = mapped_column(String(50), nullable=False)  # e.g. Entra ID, Okta

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    # Nullable, and null means "the directory listing does not report it".
    # Recording False for an unknown would assert that MFA is off, which is a
    # security claim the API response does not support.
    mfa_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Empty means unknown. Defaulting to "USER" claimed a privilege level the
    # directory never reported.
    privilege_level: Mapped[str] = mapped_column(String(50), default="", server_default="")
