import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Network(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An authorized network range.

    `is_authorized_scope` is the record of consent: a scan may only target a
    range an operator has explicitly declared they are authorized to assess.
    Discovery and scanning both consult this table.
    """
    __tablename__ = "networks"
    __table_args__ = (UniqueConstraint("organization_id", "cidr", name="uq_network_cidr_per_org"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")

    # Declared by an operator, not guessed. Feeds the exposure score.
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    # Explicit authorization to assess this range.
    is_authorized_scope: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    authorized_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    authorization_note: Mapped[str] = mapped_column(Text, default="", server_default="")

    site: Mapped["Site"] = relationship(back_populates="networks")
