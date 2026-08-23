"""
Attack paths.

Every path this platform computes is POTENTIAL: the relationships composing the
route exist in the inventory, and nothing has been attempted along it. The
response says so explicitly, per route and once at the top level, because the
distinction between "could exist" and "was demonstrated" is the whole
difference between a prioritisation aid and a false claim of compromise.

The endpoint previously returned a bare `is_verified: false` boolean and
described its output as "identified attack paths". A boolean cannot express
"observed but not verified", and `false` reads as "not yet checked" rather than
"theoretical".
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.graph import AttackPath, ClaimStrength
from app.models.user import User

router = APIRouter()

CLAIM_MEANING: dict[ClaimStrength, str] = {
    ClaimStrength.POTENTIAL: (
        "The relationships composing this route exist in your inventory. "
        "Nothing has been attempted along it and it has not been shown to work."
    ),
    ClaimStrength.OBSERVED: (
        "Activity consistent with this route was seen in monitoring. That is "
        "not proof of an attack, and not proof that it succeeded."
    ),
    ClaimStrength.VERIFIED: (
        "An authorized verification run actually traversed this route. The scan "
        "job that did so is named in verified_by_scan_job_id."
    ),
}


def _serialise(path: AttackPath) -> dict[str, Any]:
    return {
        "id": str(path.id),
        "claim_strength": path.claim_strength.value,
        "claim_meaning": CLAIM_MEANING[path.claim_strength],
        "entry_point": path.entry_point,
        "source_node_id": str(path.source_node_id),
        "source_node_type": path.source_node_type,
        "target_node_id": str(path.target_node_id),
        "target_node_type": path.target_node_type,
        "risk_score": path.risk_score,
        # The contributors behind the score, so it can be argued with.
        "risk_breakdown": path.risk_breakdown or {},
        "path_nodes": path.path_nodes or [],
        "path_edges": path.path_edges or [],
        "hop_count": len(path.path_edges or []),
        "verified_by_scan_job_id": (
            str(path.verified_by_scan_job_id) if path.verified_by_scan_job_id else None
        ),
        "verified_at": path.verified_at.isoformat() if path.verified_at else None,
        "evidence_note": path.evidence_note,
        "last_computed_at": (
            path.last_computed_at.isoformat() if path.last_computed_at else None
        ),
        "created_at": path.created_at.isoformat() if path.created_at else None,
    }


@router.get("/")
def get_attack_paths(
    claim_strength: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> dict[str, Any]:
    """Potential attack paths for this organization, highest risk first."""
    statement = select(AttackPath).where(
        AttackPath.organization_id == current_user.organization_id
    )
    if claim_strength:
        try:
            statement = statement.where(
                AttackPath.claim_strength == ClaimStrength(claim_strength)
            )
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    "claim_strength must be one of: "
                    + ", ".join(member.value for member in ClaimStrength)
                ),
            )

    paths = db.execute(
        statement.order_by(AttackPath.risk_score.desc()).limit(limit)
    ).scalars().all()

    counts = {member.value: 0 for member in ClaimStrength}
    for path in paths:
        counts[path.claim_strength.value] += 1

    return {
        "paths": [_serialise(path) for path in paths],
        "counts_by_claim_strength": counts,
        "disclaimer": (
            "This platform runs no exploit verification. Unless a path is "
            "marked verified — and none is, because that capability does not "
            "exist — it describes a route that could exist, not one that has "
            "been shown to work."
        ),
        "empty_state_note": (
            "No paths have been computed. The graph is rebuilt after each "
            "completed scan and nightly; an empty result means nothing has been "
            "computed yet, not that no routes exist."
        ) if not paths else "",
    }


@router.get("/{path_id}")
def get_attack_path(
    path_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> dict[str, Any]:
    path = db.execute(
        select(AttackPath).where(
            AttackPath.id == path_id,
            AttackPath.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if path is None:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return _serialise(path)
