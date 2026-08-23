"""
Exposure graph construction.

Turns the inventory into explicit relationship rows so attack paths can be
walked rather than inferred. Four relationships are recorded, and each one
corresponds to something the platform actually knows:

    Network  CONTAINS          Asset      the asset's IP falls in that network
    Asset    RUNS              Service    a scan observed the service
    Asset    HAS_VULNERABILITY Finding    a finding is open against the asset
    Service  EXPOSES           Finding    the finding is tied to that service

The last one is what makes a route longer than one hop: without it every path
is "asset → finding" and the graph adds nothing over a join.

The rebuild is destructive by design — edges are derived data with no
independent meaning, so recomputing them from scratch is cheaper and safer than
reconciling. Attack paths are *not* rebuilt this way; see attack_path_engine.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_detail import AssetService
from app.models.finding import CLOSED_STATUSES, Finding
from app.models.graph import GraphEdge
from app.models.network import Network


def rebuild_organization_graph(db: Session, organization_id: uuid.UUID) -> dict:
    """Rebuild every edge for one organization. Returns what was written."""
    db.execute(
        delete(GraphEdge).where(GraphEdge.organization_id == organization_id)
    )

    edges: list[dict] = []

    # Network CONTAINS Asset
    for network_id, asset_id in db.execute(
        select(Network.id, Asset.id)
        .join(Asset, Asset.network_id == Network.id)
        .where(Network.organization_id == organization_id)
    ).all():
        edges.append({
            "organization_id": organization_id,
            "source_id": network_id, "source_type": "Network",
            "target_id": asset_id, "target_type": "Asset",
            "relationship": "CONTAINS",
            "properties": {},
        })

    # Asset RUNS Service
    for service in db.execute(
        select(AssetService).where(AssetService.organization_id == organization_id)
    ).scalars().all():
        edges.append({
            "organization_id": organization_id,
            "source_id": service.asset_id, "source_type": "Asset",
            "target_id": service.id, "target_type": "Service",
            "relationship": "RUNS",
            "properties": {
                "port": service.port,
                "protocol": service.protocol,
                "label": f"{service.port}/{service.protocol}"
                         + (f" {service.service_name}" if service.service_name else ""),
            },
        })

    # Asset HAS_VULNERABILITY Finding, and Service EXPOSES Finding where the
    # finding was raised against a specific service.
    #
    # `status` is an enum column: the previous implementation compared it to
    # the string "OPEN", and only counted findings in that one state — an
    # acknowledged or in-progress finding is still an open exposure and was
    # silently dropped from the graph.
    for finding in db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
        )
    ).scalars().all():
        properties = {
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "label": finding.title[:120],
        }
        edges.append({
            "organization_id": organization_id,
            "source_id": finding.asset_id, "source_type": "Asset",
            "target_id": finding.id, "target_type": "Finding",
            "relationship": "HAS_VULNERABILITY",
            "properties": properties,
        })
        if finding.asset_service_id is not None:
            edges.append({
                "organization_id": organization_id,
                "source_id": finding.asset_service_id, "source_type": "Service",
                "target_id": finding.id, "target_type": "Finding",
                "relationship": "EXPOSES",
                "properties": properties,
            })

    if edges:
        db.execute(insert(GraphEdge), edges)
    db.flush()

    return {
        "edges": len(edges),
        "rebuilt_at": datetime.now(timezone.utc).isoformat(),
    }
