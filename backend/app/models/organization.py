import uuid
from sqlalchemy import String, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A tenant. All org-scoped data references organization_id for isolation."""
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # White-label branding
    logo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    favicon_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    primary_color: Mapped[str] = mapped_column(String(20), default="#0EA5E9")
    secondary_color: Mapped[str] = mapped_column(String(20), default="#7C3AED")
    footer_text: Mapped[str] = mapped_column(String(255), default="Powered by Omni Digital Solution")

    # Licensing
    subscription_plan: Mapped[str] = mapped_column(String(50), default="trial")
    license_seats: Mapped[int] = mapped_column(default=10)

    # Enterprise Settings
    slack_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    teams_webhook_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sso_provider: Mapped[str] = mapped_column(String(50), default="none")
    sso_metadata_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    users: Mapped[list["User"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    assets: Mapped[list["Asset"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    roles: Mapped[list["Role"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
