"""
Graph and attack-path recomputation.

These exist because the two services they call were previously never invoked
from anywhere — no task, no endpoint, no beat entry. `GET /graph/` and
`GET /attack-paths/` were therefore permanently empty while being presented as
a working exposure-graph and attack-path feature.

Recomputation is triggered from two places: after a scan finishes, because that
is when the inventory actually changed, and on a nightly schedule so that
intelligence correlation landing overnight is reflected without a rescan.
"""
from __future__ import annotations

import logging
import uuid

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant, set_tenant
from app.models.organization import Organization
from app.services.attack_path_engine import calculate_attack_paths
from app.services.graph_builder import rebuild_organization_graph

logger = logging.getLogger(__name__)


@celery_app.task(name="graph_tasks.rebuild_exposure_graph")
def rebuild_exposure_graph(organization_id: str) -> dict:
    """Rebuild one organization's graph, then recompute its potential paths."""
    org_uuid = uuid.UUID(organization_id)
    db = SessionLocal()
    set_tenant(db, org_uuid)
    try:
        graph = rebuild_organization_graph(db, org_uuid)
        paths = calculate_attack_paths(db, org_uuid)
        db.commit()
        logger.info(
            "Rebuilt exposure graph for %s: %s edges, %s potential paths",
            org_uuid, graph["edges"], paths["computed"],
        )
        return {"organization_id": str(org_uuid), "graph": graph, "attack_paths": paths}
    except Exception:
        db.rollback()
        logger.exception("Exposure graph rebuild failed for %s", org_uuid)
        raise
    finally:
        db.close()


@celery_app.task(name="graph_tasks.rebuild_all_graphs")
def rebuild_all_graphs() -> dict:
    """
    Nightly rebuild across every organization.

    Each tenant is dispatched as its own task so one organization's failure
    does not abandon the rest.
    """
    db = SessionLocal()
    bypass_tenant(db)
    try:
        organization_ids = [
            str(row) for row in db.execute(select(Organization.id)).scalars().all()
        ]
    finally:
        db.close()

    for organization_id in organization_ids:
        rebuild_exposure_graph.delay(organization_id)
    return {"dispatched": len(organization_ids)}
