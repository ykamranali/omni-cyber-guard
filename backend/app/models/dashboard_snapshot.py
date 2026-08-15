import uuid
import datetime
from sqlalchemy import ForeignKey, Float, Date
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import UUIDPrimaryKeyMixin, TimestampMixin


class DashboardSnapshot(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A recorded, real point-in-time snapshot of an organization's computed
    security posture. Written once per day (at most) so the dashboard's
    trend chart reflects actual historical values rather than fabricated
    data — the trend simply grows as the platform is used over time.
    """
    __tablename__ = "dashboard_snapshots"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    snapshot_date: Mapped[datetime.date] = mapped_column(Date, nullable=False, index=True)
    security_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    open_findings: Mapped[int] = mapped_column(default=0)
