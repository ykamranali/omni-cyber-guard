import uuid

from sqlalchemy import Column, ForeignKey, String, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

asset_tag_links = Table(
    "asset_tag_links",
    Base.metadata,
    Column("asset_id", UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", UUID(as_uuid=True), ForeignKey("asset_tags.id", ondelete="CASCADE"), primary_key=True),
)


class AssetTag(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An organization-defined label applied to assets ("Production", "EMR",
    "Domain Controller", "PCI Scope").

    Tags replace the free-text JSON array previously held on the asset, which
    could not be renamed, counted or used to drive scoring consistently.
    """
    __tablename__ = "asset_tags"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_tag_name_per_org"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    color: Mapped[str] = mapped_column(String(20), default="#64748B", server_default="#64748B")
    description: Mapped[str] = mapped_column(String(500), default="", server_default="")

    assets: Mapped[list["Asset"]] = relationship(
        secondary=asset_tag_links, back_populates="tag_links"
    )
