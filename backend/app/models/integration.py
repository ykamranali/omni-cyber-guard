"""
Integration state.

When an external system the platform can pull from is not reachable — no
credentials, no SDK installed, an authentication failure — that fact has to be
recorded *as a fact about the integration*, not as a record in the inventory it
was supposed to populate.

That distinction is the whole reason this table exists. The previous cloud and
identity discovery tasks, finding no credentials, wrote a `CloudResource` named
"Discovery Failed: No active credentials found for AWS" and an
`IdentityProfile` with the email `admin_integration_failed@aws.local`. Both were
then served by their endpoints as discovered inventory, indistinguishable from
real records and counted in any total. An operator reading the cloud page saw a
resource. There was no resource.

Now a failed or unconfigured integration produces exactly one row here, the
inventory tables stay empty, and the UI can say "not configured" because the
API can tell it so.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class IntegrationKind(str, PyEnum):
    CLOUD = "cloud"
    IDENTITY = "identity"
    ATTACK_SURFACE = "attack_surface"


class IntegrationStatus(str, PyEnum):
    # No credentials or configuration supplied. The default, and not an error.
    NOT_CONFIGURED = "not_configured"
    # Configured, but the last attempt failed. `message` says how.
    ERROR = "error"
    # The last attempt succeeded. `records_discovered` is what it returned,
    # which may legitimately be zero.
    CONNECTED = "connected"


class IntegrationState(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "integration_states"
    __table_args__ = (
        UniqueConstraint("organization_id", "kind", "provider", name="uq_integration_state"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    kind: Mapped[IntegrationKind] = mapped_column(Enum(IntegrationKind), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[IntegrationStatus] = mapped_column(
        Enum(IntegrationStatus), default=IntegrationStatus.NOT_CONFIGURED,
        server_default="NOT_CONFIGURED",
    )
    message: Mapped[str] = mapped_column(Text, default="", server_default="")
    # Settings the operator must supply, so the UI can name them without
    # hard-coding a list that drifts from the adapter.
    missing_configuration: Mapped[list] = mapped_column(JSON, default=list)

    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Only advanced by a run that actually succeeded, so a broken integration
    # keeps showing when it last genuinely worked.
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    records_discovered: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
