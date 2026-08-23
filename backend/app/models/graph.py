import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Any

from sqlalchemy import (
    DateTime, Enum, Float, ForeignKey, Index, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class GraphEdge(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    An explicit relationship between two nodes in the platform (Asset, Finding,
    Service, Network). Attack paths are traversed over these edges rather than
    inferred from a flat join, so every hop in a path corresponds to a
    relationship that was actually recorded.
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


class ClaimStrength(str, PyEnum):
    """
    How strongly the evidence supports a path. This distinction is mandatory,
    and it is not presentational.

    POTENTIAL — the recorded relationships and findings mean this route could
    exist. Nothing has been attempted along it. Every path this platform
    computes today is POTENTIAL, because computing a route is not testing one.

    OBSERVED — activity consistent with this route was seen by the passive
    monitor or in ingested telemetry. Something happened; it was not
    necessarily an attack, and it was not necessarily successful.

    VERIFIED — an authorized exploitation test actually traversed this route
    and succeeded, and `verified_by_scan_job_id` names the run that did it.
    The platform has no exploit-verification capability, so nothing sets this
    today. The state exists so that if one is ever built there is somewhere
    truthful to record it — and so that a POTENTIAL path can never be
    displayed as though it were this one.
    """
    POTENTIAL = "potential"
    OBSERVED = "observed"
    VERIFIED = "verified"


class AttackPath(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A route through recorded relationships by which an attacker could plausibly
    move from an entry point to a target.

    The docstring previously read "a computed path demonstrating how an
    attacker could move". Nothing is demonstrated. The row states that the
    relationships composing the route exist in the inventory; whether the route
    works is a different question, and `claim_strength` is where the answer
    lives.
    """
    __tablename__ = "attack_paths"
    __table_args__ = (
        UniqueConstraint("organization_id", "path_signature", name="uq_attack_path_signature"),
        Index("ix_attack_paths_org_strength", "organization_id", "claim_strength"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    source_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_node_type: Mapped[str] = mapped_column(String(50), nullable=False)

    target_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_node_type: Mapped[str] = mapped_column(String(50), nullable=False)

    # How the attacker is assumed to reach the first node: "internet" for an
    # asset the operator declared internet-facing, "adjacent_network" for one
    # reachable only from inside. Recorded rather than implied, because the
    # previous implementation prepended a fictitious "Internet" node to every
    # path whether or not anything established reachability.
    entry_point: Mapped[str] = mapped_column(String(32), nullable=False, server_default="unknown")

    # Ordered list of graph_edge IDs actually traversed. Empty is not a valid
    # path: it would mean the route was asserted rather than walked.
    path_edges: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")

    # Ordered node objects along the path, for rendering.
    path_nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]")

    # A deterministic hash of the traversed edges, so recomputation updates
    # rather than duplicates.
    path_signature: Mapped[str] = mapped_column(String(64), nullable=False)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    # The contributors behind risk_score, so the number can be explained rather
    # than asserted. Mirrors the exposure engine's breakdown.
    risk_breakdown: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")

    claim_strength: Mapped[ClaimStrength] = mapped_column(
        Enum(ClaimStrength), default=ClaimStrength.POTENTIAL, server_default="POTENTIAL"
    )
    # Only set alongside VERIFIED, and only by an authorized verification run.
    verified_by_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # What was observed, for OBSERVED, or what the verification did, for
    # VERIFIED. Never a narrative for POTENTIAL.
    evidence_note: Mapped[str] = mapped_column(Text, default="", server_default="")

    last_computed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
