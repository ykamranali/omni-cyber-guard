import uuid
from datetime import date

from sqlalchemy import Date, Float, ForeignKey, Integer, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ExposureSnapshot(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One day's recorded exposure posture for an organization.

    Recorded rather than derived: a trend line drawn between two current values
    is a drawing, not a history. If the platform was not running on a given day,
    that day is simply missing from the chart — which is the truth.
    """

    __tablename__ = "exposure_snapshots"
    __table_args__ = (
        UniqueConstraint("organization_id", "snapshot_date", name="uq_exposure_snapshot_per_day"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)

    #: NULL when nothing in the estate had enough data to be scored that day.
    exposure_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    assets_total: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    assets_assessed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    open_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    known_exploited_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    internet_exposed_assets: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
