import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, ForeignKey, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class CredentialType(str, PyEnum):
    SSH_PASSWORD = "ssh_password"
    SSH_KEY = "ssh_key"
    WINDOWS = "windows"
    SNMP_V2C = "snmp_v2c"
    SNMP_V3 = "snmp_v3"
    LDAP = "ldap"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    API_TOKEN = "api_token"
    DATABASE = "database"


class CredentialProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A stored credential used for authenticated assessment.

    Design rules, enforced by the schema and by the API layer:

    * The secret is stored as Fernet ciphertext in `secret_encrypted`. There is
      no plaintext column and no plaintext default.
    * No API response schema exposes `secret_encrypted` or its plaintext. The
      only code path that decrypts is the scanner adapter that is about to use
      it.
    * Every decryption is written to the audit log with the actor and purpose,
      so credential access is reviewable.
    * `rotated_at` and `last_used_at` exist so a stale or over-used credential
      is visible rather than invisible.
    """
    __tablename__ = "credential_profiles"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_credential_name_per_org"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    credential_type: Mapped[CredentialType] = mapped_column(
        Enum(CredentialType), nullable=False
    )

    # Non-secret half of the credential. Safe to display.
    username: Mapped[str] = mapped_column(String(255), default="", server_default="")
    domain: Mapped[str] = mapped_column(String(255), default="", server_default="")

    # Secret half. Ciphertext only — never returned by any API response schema.
    secret_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Additional secret material (an SSH passphrase, an SNMPv3 privacy key,
    # a cloud secret access key), encrypted as a JSON document.
    extra_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
