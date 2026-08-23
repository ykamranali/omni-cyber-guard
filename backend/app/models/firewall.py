"""
Firewall integration.

The platform's position on blocking has been deliberate and unchanged: it
records a decision and does not interrupt traffic itself. An earlier version
did try to — by forging TCP RST packets with a spoofed source address, which is
indistinguishable from an attack and could be aimed at any host on the segment.
That was removed.

This is the honest version of the same capability. A firewall the operator
connects, with credentials they supply, becomes the thing that enforces. The
platform pushes a rule through the vendor's own API and records what the vendor
said. A block is only ever marked enforced when the vendor accepted it — never
because the platform decided one was warranted.

Automatic blocking is off by default and, when enabled, is bounded by an
explicit severity threshold and an allowlist that cannot be overridden. A
platform that can cut off network access on its own judgement needs those
limits to be in the schema, not in a comment.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Boolean, DateTime, Enum, ForeignKey, Integer, JSON, LargeBinary, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class FirewallVendor(str, PyEnum):
    OPNSENSE = "opnsense"
    PFSENSE = "pfsense"
    FORTIGATE = "fortigate"


class FirewallStatus(str, PyEnum):
    NOT_CONFIGURED = "not_configured"
    ERROR = "error"
    CONNECTED = "connected"


class FirewallIntegration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "firewall_integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_firewall_integration_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    vendor: Mapped[FirewallVendor] = mapped_column(Enum(FirewallVendor), nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)

    # The API key or username, which is not itself a secret.
    api_identity: Mapped[str] = mapped_column(String(255), default="", server_default="")
    # The secret, Fernet-encrypted with the same vault key as scan credentials.
    # Never returned by any API response; see app/services/credential_access.py
    # for the only path that decrypts one.
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # The named object the vendor's rules reference — an OPNsense/pfSense alias,
    # or a FortiGate address group. Blocking works by adding to this, so the
    # operator keeps control of what the rule referencing it actually does.
    blocklist_object: Mapped[str] = mapped_column(String(120), default="", server_default="")

    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")

    status: Mapped[FirewallStatus] = mapped_column(
        Enum(FirewallStatus), default=FirewallStatus.NOT_CONFIGURED,
        server_default="NOT_CONFIGURED",
    )
    status_message: Mapped[str] = mapped_column(Text, default="", server_default="")
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # --- Automatic blocking ------------------------------------------------
    # Off unless an operator turns it on. The platform will not start cutting
    # off network access because a default said it could.
    auto_block_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    # Only events at or above this severity may trigger one.
    auto_block_min_severity: Mapped[str] = mapped_column(
        String(16), default="critical", server_default="critical"
    )
    # Addresses that must never be blocked automatically, whatever happens —
    # the gateway, DNS resolvers, the operator's own management range. Enforced
    # in the service, and a block that would hit one is refused, not silently
    # skipped.
    never_block: Mapped[list] = mapped_column(JSON, default=list)
    # An automatic block expires by itself. A permanent one needs a human.
    auto_block_duration_minutes: Mapped[int] = mapped_column(
        Integer, default=60, server_default="60"
    )

    enforced_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
