"""
Attack path computation.

What this does, precisely: it walks the recorded relationship graph from assets
the operator has declared internet-facing, and records the routes that end at
an open finding. Every hop corresponds to a `graph_edges` row that exists.

What it does not do, equally precisely: it does not test any of these routes.
Nothing here attempts an exploit, and no path it produces is evidence that an
attacker could actually traverse it. Every path is written with
`claim_strength = POTENTIAL`, and there is no code path in this module that
writes any other value.

Why it was rewritten
--------------------
The previous implementation was a flat SQL join with several problems, each of
which made it assert more than it knew:

* It filtered on `exposure_breakdown->>'internet_exposed'`, a key nothing has
  ever written. The real column is `Asset.is_internet_facing`. The predicate
  matched zero rows, so the feature reported "no attack paths" for every
  organization — indistinguishable from a clean estate.
* It prepended a node `{"type": "External", "name": "Internet"}` to every path
  regardless of whether anything established reachability.
* `path_edges` was always `[]`, though the column is documented as the ordered
  list of edges making up the path. No edge was traversed; the "path" was two
  rows of a join.
* `risk_score` was `90.0` for CRITICAL and `70.0` for HIGH — invented constants
  — then silently overwritten by `cvss_score * 10`, which is a vulnerability
  severity, not a path risk.
* `source_node_id` was `uuid.UUID(int=0)` as a sentinel for "the internet",
  persisted as though it were a real node.
* Nothing ever called it.
"""
from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset, Criticality
from app.models.finding import CLOSED_STATUSES, Finding, Severity
from app.models.graph import AttackPath, ClaimStrength, GraphEdge

# How far the traversal will walk from an entry point. Three hops covers
# network → asset → service → finding; beyond that the routes stop being
# distinguishable from "everything is connected to everything".
MAX_PATH_LENGTH = 4

# The risk model. Every number an operator sees has to be traceable to one of
# these, which is why they are named constants and not literals at the call
# site.
SEVERITY_POINTS: dict[Severity, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 28.0,
    Severity.MEDIUM: 15.0,
    Severity.LOW: 6.0,
    Severity.INFO: 0.0,
}
CRITICALITY_POINTS: dict[Criticality, float] = {
    Criticality.CRITICAL: 25.0,
    Criticality.HIGH: 18.0,
    Criticality.MEDIUM: 10.0,
    Criticality.LOW: 4.0,
}
KNOWN_EXPLOITED_POINTS = 25.0
INTERNET_ENTRY_POINTS = 10.0
# A longer route needs more to go right for the attacker. Each hop beyond the
# first subtracts, floored so a long path is never worth nothing.
PER_HOP_PENALTY = 4.0
MAX_HOP_PENALTY = 12.0


@dataclass
class _Node:
    node_id: uuid.UUID
    node_type: str


@dataclass
class _Route:
    nodes: list[_Node]
    edges: list[GraphEdge] = field(default_factory=list)


def _severity_points(severity: Severity | None) -> float:
    if severity is None:
        return 0.0
    return SEVERITY_POINTS.get(severity, 0.0)


def score_path(
    *,
    finding: Finding,
    asset: Asset,
    entry_point: str,
    hop_count: int,
) -> tuple[float, dict]:
    """
    Score one route, and return the contributors alongside the number.

    The breakdown is not decoration. A risk figure an operator cannot take
    apart is a figure they cannot argue with, and the specification is explicit
    that no score may be unexplained.
    """
    contributors: list[dict] = []

    points = _severity_points(finding.severity)
    if points:
        contributors.append({
            "name": f"{finding.severity.value.title()} severity finding at the end of the route",
            "points": points,
            "detail": finding.title,
        })

    criticality_points = CRITICALITY_POINTS.get(asset.criticality, 0.0)
    if criticality_points:
        contributors.append({
            "name": f"Target asset is business-{asset.criticality.value}",
            "points": criticality_points,
            "detail": asset.hostname,
        })

    if finding.is_known_exploited:
        contributors.append({
            "name": "Vulnerability is on the CISA Known Exploited list",
            "points": KNOWN_EXPLOITED_POINTS,
            "detail": finding.cve_id or "",
        })

    if entry_point == "internet":
        contributors.append({
            "name": "Route begins at an asset declared internet-facing",
            "points": INTERNET_ENTRY_POINTS,
            "detail": "",
        })

    penalty = min(MAX_HOP_PENALTY, max(0, hop_count - 1) * PER_HOP_PENALTY)
    if penalty:
        contributors.append({
            "name": f"Route requires {hop_count} hops",
            "points": -penalty,
            "detail": "A longer route needs more to go right for an attacker.",
        })

    total = max(0.0, min(100.0, sum(item["points"] for item in contributors)))

    breakdown = {
        "score": round(total, 1),
        "contributors": contributors,
        "model": "attack_path_risk_v1",
        "unavailable_factors": [
            {
                "name": "exploitability_verified",
                "reason": (
                    "This platform runs no exploit verification, so whether the "
                    "route actually works has not been tested and contributes "
                    "nothing to this score."
                ),
            },
            {
                "name": "compensating_controls",
                "reason": (
                    "Firewall rules, segmentation and EDR coverage are not "
                    "inventoried, so their effect on this route is unknown."
                ),
            },
        ],
    }
    return round(total, 1), breakdown


def _adjacency(db: Session, organization_id: uuid.UUID) -> dict[uuid.UUID, list[GraphEdge]]:
    edges = db.execute(
        select(GraphEdge).where(GraphEdge.organization_id == organization_id)
    ).scalars().all()
    index: dict[uuid.UUID, list[GraphEdge]] = defaultdict(list)
    for edge in edges:
        index[edge.source_id].append(edge)
    return index


def _walk(
    adjacency: dict[uuid.UUID, list[GraphEdge]], start: _Node
) -> list[_Route]:
    """
    Breadth-first walk from one entry asset, collecting routes that terminate
    at a Finding. Cycles are cut by refusing to revisit a node within a route.
    """
    routes: list[_Route] = []
    queue: list[_Route] = [_Route(nodes=[start])]

    while queue:
        route = queue.pop(0)
        tail = route.nodes[-1]

        if tail.node_type == "Finding":
            routes.append(route)
            continue
        if len(route.nodes) >= MAX_PATH_LENGTH:
            continue

        visited = {node.node_id for node in route.nodes}
        for edge in adjacency.get(tail.node_id, ()):
            if edge.target_id in visited:
                continue
            queue.append(_Route(
                nodes=route.nodes + [_Node(edge.target_id, edge.target_type)],
                edges=route.edges + [edge],
            ))

    return routes


def _signature(route: _Route) -> str:
    return hashlib.sha256(
        "\x1f".join(str(edge.id) for edge in route.edges).encode("utf-8")
    ).hexdigest()


def calculate_attack_paths(db: Session, organization_id: uuid.UUID) -> dict:
    """
    Recompute this organization's potential attack paths.

    Paths whose claim strength has been raised above POTENTIAL are never
    deleted or downgraded here: an observation or a verification is a record of
    something that happened, and a later recomputation does not un-happen it.
    """
    assets = db.execute(
        select(Asset).where(Asset.organization_id == organization_id)
    ).scalars().all()
    assets_by_id = {asset.id: asset for asset in assets}

    findings = db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
        )
    ).scalars().all()
    findings_by_id = {finding.id: finding for finding in findings}

    adjacency = _adjacency(db, organization_id)

    existing = {
        path.path_signature: path
        for path in db.execute(
            select(AttackPath).where(AttackPath.organization_id == organization_id)
        ).scalars().all()
    }

    now = datetime.now(timezone.utc)
    seen_signatures: set[str] = set()
    written = 0

    for asset in assets:
        entry_point = "internet" if asset.is_internet_facing else "adjacent_network"
        for route in _walk(adjacency, _Node(asset.id, "Asset")):
            terminal = route.nodes[-1]
            finding = findings_by_id.get(terminal.node_id)
            if finding is None:
                # The edge points at a finding that is closed or gone. A route
                # ending nowhere is not a route.
                continue

            target_asset = assets_by_id.get(finding.asset_id, asset)
            hop_count = len(route.edges)
            score, breakdown = score_path(
                finding=finding, asset=target_asset,
                entry_point=entry_point, hop_count=hop_count,
            )

            signature = _signature(route)
            seen_signatures.add(signature)

            path_nodes = _describe_nodes(route, assets_by_id, findings_by_id)

            path = existing.get(signature)
            if path is None:
                path = AttackPath(
                    organization_id=organization_id,
                    path_signature=signature,
                    claim_strength=ClaimStrength.POTENTIAL,
                )
                db.add(path)
                existing[signature] = path

            path.source_node_id = asset.id
            path.source_node_type = "Asset"
            path.target_node_id = finding.id
            path.target_node_type = "Finding"
            path.entry_point = entry_point
            path.path_edges = [str(edge.id) for edge in route.edges]
            path.path_nodes = path_nodes
            path.risk_score = score
            path.risk_breakdown = breakdown
            path.last_computed_at = now
            written += 1

    # Retire POTENTIAL paths that no longer exist in the graph. Anything
    # OBSERVED or VERIFIED is left alone.
    removed = 0
    for signature, path in existing.items():
        if signature in seen_signatures:
            continue
        if path.claim_strength is not ClaimStrength.POTENTIAL:
            continue
        db.delete(path)
        removed += 1

    db.flush()
    return {"computed": written, "retired": removed, "computed_at": now.isoformat()}


def _describe_nodes(
    route: _Route,
    assets_by_id: dict[uuid.UUID, Asset],
    findings_by_id: dict[uuid.UUID, Finding],
) -> list[dict]:
    described: list[dict] = []
    for node in route.nodes:
        entry: dict = {"id": str(node.node_id), "type": node.node_type}
        if node.node_type == "Asset":
            asset = assets_by_id.get(node.node_id)
            entry["name"] = (
                asset.hostname or asset.ip_address or "Unnamed asset"
                if asset else "Asset no longer in inventory"
            )
            if asset is not None:
                entry["internet_facing"] = asset.is_internet_facing
                entry["criticality"] = asset.criticality.value
        elif node.node_type == "Finding":
            finding = findings_by_id.get(node.node_id)
            if finding is None:
                entry["name"] = "Finding no longer open"
            else:
                entry["name"] = finding.title
                entry["severity"] = finding.severity.value
                entry["confidence"] = finding.confidence.value
                entry["cve_id"] = finding.cve_id
        else:
            # Services and networks are labelled by the edge that reached them.
            # `graph_builder` writes a `label` property from the real record; if
            # it is absent the node is named as unlabelled rather than given an
            # invented name.
            label = ""
            for edge in route.edges:
                if edge.target_id == node.node_id:
                    label = str((edge.properties or {}).get("label") or "")
                    break
            entry["name"] = label or f"Unlabelled {node.node_type.lower()}"
        described.append(entry)
    return described
