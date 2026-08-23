"""
Exposure graph.

Returns the nodes and edges the graph builder recorded, so the visualisation
draws relationships that exist rather than a shape assembled in the browser.

Two changes from the original. It is permission-guarded — it previously
authenticated the caller and then served the whole organization's asset and
finding inventory to anyone with a valid token, including roles that hold no
view permission at all. And a node whose backing record has since been deleted
is now labelled as missing: the endpoint used to substitute
`{"title": "Finding", "severity": "INFO"}`, which put a benign severity on the
page for a record nobody could look up.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset
from app.models.asset_detail import AssetService
from app.models.finding import Finding
from app.models.graph import GraphEdge
from app.models.network import Network
from app.models.user import User

router = APIRouter()

MISSING_NODE_NAME = "Record no longer in the database"


@router.get("/")
def get_exposure_graph(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> dict[str, Any]:
    """Nodes and edges for the exposure graph."""
    edge_records = db.execute(
        select(GraphEdge).where(
            GraphEdge.organization_id == current_user.organization_id
        )
    ).scalars().all()

    edges = []
    node_ids: set[tuple[str, str]] = set()
    for edge in edge_records:
        edges.append({
            "id": str(edge.id),
            "source": str(edge.source_id),
            "target": str(edge.target_id),
            "relationship": edge.relationship,
            "properties": edge.properties or {},
        })
        node_ids.add((str(edge.source_id), edge.source_type))
        node_ids.add((str(edge.target_id), edge.target_type))

    by_type: dict[str, list[str]] = {}
    for identifier, node_type in node_ids:
        by_type.setdefault(node_type, []).append(identifier)

    assets = {
        str(row.id): row
        for row in db.execute(
            select(Asset).where(
                Asset.organization_id == current_user.organization_id,
                Asset.id.in_(by_type.get("Asset", [])),
            )
        ).scalars().all()
    } if by_type.get("Asset") else {}

    findings = {
        str(row.id): row
        for row in db.execute(
            select(Finding).where(
                Finding.organization_id == current_user.organization_id,
                Finding.id.in_(by_type.get("Finding", [])),
            )
        ).scalars().all()
    } if by_type.get("Finding") else {}

    networks = {
        str(row.id): row
        for row in db.execute(
            select(Network).where(
                Network.organization_id == current_user.organization_id,
                Network.id.in_(by_type.get("Network", [])),
            )
        ).scalars().all()
    } if by_type.get("Network") else {}

    services = {
        str(row.id): row
        for row in db.execute(
            select(AssetService).where(
                AssetService.organization_id == current_user.organization_id,
                AssetService.id.in_(by_type.get("Service", [])),
            )
        ).scalars().all()
    } if by_type.get("Service") else {}

    nodes = []
    for identifier, node_type in sorted(node_ids):
        properties: dict[str, Any] = {}
        name = MISSING_NODE_NAME
        resolved = False

        if node_type == "Asset" and identifier in assets:
            asset = assets[identifier]
            name = asset.hostname or asset.ip_address or "Unnamed asset"
            properties = {
                "criticality": asset.criticality.value,
                "internet_facing": asset.is_internet_facing,
                "exposure_score": asset.exposure_score,
                "exposure_assessed": bool(asset.exposure_breakdown),
            }
            resolved = True
        elif node_type == "Finding" and identifier in findings:
            finding = findings[identifier]
            name = finding.title
            properties = {
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "finding_class": finding.finding_class.value,
                "cve_id": finding.cve_id,
            }
            resolved = True
        elif node_type == "Network" and identifier in networks:
            network = networks[identifier]
            name = network.name
            properties = {
                "cidr": network.cidr,
                "internet_facing": network.is_internet_facing,
            }
            resolved = True
        elif node_type == "Service" and identifier in services:
            service = services[identifier]
            name = (
                f"{service.port}/{service.protocol}"
                + (f" {service.service_name}" if service.service_name else "")
            )
            properties = {"port": service.port, "protocol": service.protocol}
            resolved = True

        nodes.append({
            "id": identifier,
            "name": name,
            "group": node_type,
            # An unresolved node is flagged rather than given a plausible
            # label and a benign severity. The UI greys it out.
            "resolved": resolved,
            "properties": properties,
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "note": (
            "Edges are rebuilt after every completed scan and nightly. An empty "
            "graph means no relationships have been recorded yet, not that the "
            "estate has none."
        ) if not edges else "",
    }
