import uuid

from sqlalchemy import delete, insert
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_detail import AssetService
from app.models.finding import Finding
from app.models.graph import GraphEdge
from app.models.network import Network


def rebuild_organization_graph(db: Session, organization_id: uuid.UUID):
    """
    Rebuilds the graph edges for an entire organization. 
    In a high-scale system, this would be delta-based (updating only modified assets).
    For Phase 8, we simply clear and rebuild the edges for the tenant.
    """
    
    # 1. Clear existing edges for the organization
    db.execute(
        delete(GraphEdge).where(GraphEdge.organization_id == organization_id)
    )

    edges_to_insert = []

    # 2. Network -> CONTAINS -> Asset
    networks = db.query(Network.id, Asset.id).join(
        Asset, Asset.network_id == Network.id
    ).filter(Network.organization_id == organization_id).all()

    for net_id, asset_id in networks:
        edges_to_insert.append({
            "organization_id": organization_id,
            "source_id": net_id,
            "source_type": "Network",
            "target_id": asset_id,
            "target_type": "Asset",
            "relationship": "CONTAINS"
        })

    # 3. Asset -> RUNS -> AssetService
    services = db.query(AssetService.asset_id, AssetService.id, AssetService.port, AssetService.protocol).filter(
        AssetService.organization_id == organization_id
    ).all()

    for asset_id, service_id, port, protocol in services:
        edges_to_insert.append({
            "organization_id": organization_id,
            "source_id": asset_id,
            "source_type": "Asset",
            "target_id": service_id,
            "target_type": "Service",
            "relationship": "RUNS",
            "properties": {"port": port, "protocol": protocol}
        })

    # 4. Asset -> HAS_VULNERABILITY -> Finding
    findings = db.query(Finding.asset_id, Finding.id, Finding.severity).filter(
        Finding.organization_id == organization_id,
        Finding.status == "OPEN"
    ).all()

    for asset_id, finding_id, severity in findings:
        edges_to_insert.append({
            "organization_id": organization_id,
            "source_id": asset_id,
            "source_type": "Asset",
            "target_id": finding_id,
            "target_type": "Finding",
            "relationship": "HAS_VULNERABILITY",
            "properties": {"severity": severity}
        })

    if edges_to_insert:
        db.execute(insert(GraphEdge), edges_to_insert)
    
    db.commit()

