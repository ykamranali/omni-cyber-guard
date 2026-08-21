import uuid
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class GraphEdge(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An explicit relationship between two nodes in the platform (e.g., Asset, Finding, Service).
    Used to traverse and compute attack paths.
    """
    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint("source_id", "target_id", "relationship", name="uq_graph_edge"),
        Index("ix_graph_edges_source", "source_id", "source_type"),
        Index("ix_graph_edges_target", "target_id", "target_type"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)

    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)

    relationship: Mapped[str] = mapped_column(String(50), nullable=False)
    
    properties: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")


class AttackPath(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A computed path demonstrating how an attacker could move from a source to a target.
    """
    __tablename__ = "attack_paths"
    __table_args__ = (
        UniqueConstraint("organization_id", "path_signature", name="uq_attack_path_signature"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    source_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_node_type: Mapped[str] = mapped_column(String(50), nullable=False)

    target_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_node_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # Ordered list of edge IDs that make up this path
    path_edges: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    
    # Ordered list of node objects along the path for easy frontend consumption
    path_nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]")

    # A deterministic hash of the nodes/edges to prevent duplicates
    path_signature: Mapped[str] = mapped_column(String(64), nullable=False)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
