from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.models.graph import AttackPath
from app.models.user import User

router = APIRouter()


@router.get("/")
def get_attack_paths(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """
    Returns identified attack paths for the organization, sorted by risk.
    """
    
    paths_query = (
        select(AttackPath)
        .where(AttackPath.organization_id == current_user.organization_id)
        .order_by(AttackPath.risk_score.desc())
    )
    
    paths = db.execute(paths_query).scalars().all()
    
    return [
        {
            "id": str(p.id),
            "source_node_type": p.source_node_type,
            "target_node_type": p.target_node_type,
            "risk_score": p.risk_score,
            "is_verified": p.is_verified,
            "path_nodes": p.path_nodes,
            "created_at": p.created_at.isoformat()
        }
        for p in paths
    ]
