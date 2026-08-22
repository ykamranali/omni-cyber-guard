from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.graph import GraphEdge
from app.models.network import Network
from app.models.user import User

router = APIRouter()


@router.get("/")
def get_exposure_graph(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> dict[str, Any]:
    """
    Returns nodes and edges for the exposure graph visualization.
    """
    
    # 1. Fetch all edges for the organization
    edges_query = select(GraphEdge).where(GraphEdge.organization_id == current_user.organization_id)
    edges_records = db.execute(edges_query).scalars().all()
    
    edges = []
    node_ids = set()
    
    for e in edges_records:
        edges.append({
            "id": str(e.id),
            "source": str(e.source_id),
            "target": str(e.target_id),
            "relationship": e.relationship,
            "properties": e.properties
        })
        node_ids.add((str(e.source_id), e.source_type))
        node_ids.add((str(e.target_id), e.target_type))

    # 2. Build nodes list with labels
    nodes = []
    
    # Pre-fetch details for known types to avoid N+1 queries
    asset_ids = [n[0] for n in node_ids if n[1] == "Asset"]
    finding_ids = [n[0] for n in node_ids if n[1] == "Finding"]
    network_ids = [n[0] for n in node_ids if n[1] == "Network"]
    service_ids = [n[0] for n in node_ids if n[1] == "Service"]

    asset_map = {}
    if asset_ids:
        for a in db.query(Asset.id, Asset.hostname, Asset.ip_address).filter(Asset.id.in_(asset_ids)).all():
            asset_map[str(a.id)] = a.hostname or a.ip_address or "Unknown Asset"
            
    finding_map = {}
    if finding_ids:
        for f in db.query(Finding.id, Finding.title, Finding.severity).filter(Finding.id.in_(finding_ids)).all():
            finding_map[str(f.id)] = {"title": f.title, "severity": f.severity}
            
    network_map = {}
    if network_ids:
        for n in db.query(Network.id, Network.name).filter(Network.id.in_(network_ids)).all():
            network_map[str(n.id)] = n.name

    for node_id, node_type in node_ids:
        name = "Unknown"
        group = node_type
        properties = {}
        
        if node_type == "Asset":
            name = asset_map.get(node_id, "Asset")
        elif node_type == "Finding":
            f_data = finding_map.get(node_id, {"title": "Finding", "severity": "INFO"})
            name = f_data["title"]
            properties["severity"] = f_data["severity"]
        elif node_type == "Network":
            name = network_map.get(node_id, "Network")
        elif node_type == "Service":
            name = "Service"
            
        nodes.append({
            "id": node_id,
            "name": name,
            "group": group,
            "properties": properties
        })
        
    return {
        "nodes": nodes,
        "edges": edges
    }
