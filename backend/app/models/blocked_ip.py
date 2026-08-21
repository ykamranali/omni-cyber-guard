import uuid
from sqlalchemy import String, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class BlockedIp(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An IP address an operator has flagged for blocking.

    Omni Cyber Guard records the decision and the justification; it does not
    itself interrupt network traffic. Enforcement belongs to the network
    boundary — a host firewall rule, an edge ACL, or (in a later phase) an
    authenticated integration with a firewall's management API.

    Statuses:
        recommended  — flagged in the platform, not yet enforced anywhere
        enforced     — an operator has confirmed the rule exists upstream
        expired      — no longer in force
    """
    __tablename__ = "blocked_ips"
    __table_args__ = (
        UniqueConstraint("organization_id", "ip_address", name="uq_blocked_ip_per_org"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), default="", server_default="")
    status: Mapped[str] = mapped_column(String(32), default="recommended", server_default="recommended")
