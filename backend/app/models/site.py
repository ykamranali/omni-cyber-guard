import uuid

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Site(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A physical or logical location within an organization.

    Organization -> Site -> Network -> Asset is the containment hierarchy the
    platform organises discovery around.
    """
    __tablename__ = "sites"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_site_name_per_org"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    location: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Recorded only when an operator supplies them. Never inferred from an IP
    # address: geolocating a private range produces a plausible-looking lie.
    latitude: Mapped[float | None] = mapped_column(nullable=True)
    longitude: Mapped[float | None] = mapped_column(nullable=True)

    networks: Mapped[list["Network"]] = relationship(
        back_populates="site", cascade="all, delete-orphan"
    )
