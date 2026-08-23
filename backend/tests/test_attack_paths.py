"""
Exposure graph and attack paths.

Two concerns. First that the engine computes real routes over recorded
relationships — the previous implementation was a flat SQL join whose central
predicate referenced `exposure_breakdown->>'internet_exposed'`, a key nothing
has ever written, so it matched zero rows and reported "no attack paths" for
every organization. That is the worst possible failure for this feature: an
empty result reads as a clean estate.

Second, and more important, that nothing here ever claims more than it knows.
Every path is POTENTIAL. There is no verification capability in this platform,
so no code path may produce a VERIFIED one.
"""
from __future__ import annotations

import uuid

from tests.conftest import requires_db

from app.models.asset import Asset, AssetStatus, AssetType, Criticality
from app.models.asset_detail import AssetService
from app.models.finding import (
    Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.models.graph import AttackPath, ClaimStrength, GraphEdge
from app.services.attack_path_engine import calculate_attack_paths, score_path
from app.services.finding_identity import compute_fingerprint
from app.services.graph_builder import rebuild_organization_graph


def _asset(db, organization, hostname, **overrides) -> Asset:
    values = dict(
        organization_id=organization.id,
        hostname=hostname,
        ip_address=None,
        asset_type=AssetType.SERVER,
        status=AssetStatus.ACTIVE,
        criticality=Criticality.MEDIUM,
        is_internet_facing=False,
    )
    values.update(overrides)
    record = Asset(**values)
    db.add(record)
    db.flush()
    return record


def _service(db, organization, asset, port=22) -> AssetService:
    record = AssetService(
        organization_id=organization.id, asset_id=asset.id,
        port=port, protocol="tcp", service_name="ssh",
    )
    db.add(record)
    db.flush()
    return record


def _finding(db, organization, asset, service=None, **overrides) -> Finding:
    values = dict(
        organization_id=organization.id,
        asset_id=asset.id,
        asset_service_id=service.id if service else None,
        title="OpenSSH reports a vulnerable version",
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        finding_class=FindingClass.VULNERABILITY,
        confidence=Confidence.PROBABLE,
        source="nmap",
        cve_id="CVE-2024-6387",
    )
    values.update(overrides)
    values["fingerprint"] = compute_fingerprint(
        asset_id=asset.id, finding_class=values["finding_class"],
        source=values["source"], identifier=values.get("cve_id") or values["title"],
        location=f"{service.port}/tcp" if service else "",
    )
    record = Finding(**values)
    db.add(record)
    db.flush()
    return record


@requires_db
class TestGraphBuilder:
    def test_relationships_are_recorded_for_real_records(
        self, db, organization
    ):
        asset = _asset(db, organization, "web-01")
        service = _service(db, organization, asset)
        _finding(db, organization, asset, service)

        result = rebuild_organization_graph(db, organization.id)

        relationships = {
            edge.relationship
            for edge in db.query(GraphEdge).filter(
                GraphEdge.organization_id == organization.id
            ).all()
        }
        assert relationships == {"RUNS", "HAS_VULNERABILITY", "EXPOSES"}
        assert result["edges"] == 3

    def test_a_finding_that_is_acknowledged_still_counts_as_open(
        self, db, organization
    ):
        """
        The previous builder compared the status enum to the string "OPEN", so
        an acknowledged or in-progress finding — still an open exposure — was
        silently dropped from the graph.
        """
        asset = _asset(db, organization, "web-01")
        _finding(db, organization, asset, status=FindingStatus.ACKNOWLEDGED)

        rebuild_organization_graph(db, organization.id)

        assert db.query(GraphEdge).filter(
            GraphEdge.relationship == "HAS_VULNERABILITY"
        ).count() == 1

    def test_a_remediated_finding_is_not_in_the_graph(self, db, organization):
        asset = _asset(db, organization, "web-01")
        _finding(db, organization, asset, status=FindingStatus.REMEDIATED)

        rebuild_organization_graph(db, organization.id)

        assert db.query(GraphEdge).filter(
            GraphEdge.relationship == "HAS_VULNERABILITY"
        ).count() == 0

    def test_rebuilding_replaces_rather_than_accumulates(self, db, organization):
        asset = _asset(db, organization, "web-01")
        _finding(db, organization, asset)

        rebuild_organization_graph(db, organization.id)
        first = db.query(GraphEdge).count()
        rebuild_organization_graph(db, organization.id)

        assert db.query(GraphEdge).count() == first


@requires_db
class TestAttackPathEngine:
    def test_a_route_is_computed_from_a_real_internet_facing_asset(
        self, db, organization
    ):
        asset = _asset(db, organization, "edge-01", is_internet_facing=True)
        service = _service(db, organization, asset)
        finding = _finding(db, organization, asset, service)

        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        paths = db.query(AttackPath).filter(
            AttackPath.organization_id == organization.id
        ).all()
        assert paths, "an internet-facing asset with an open critical finding is a route"
        path = max(paths, key=lambda item: item.risk_score)
        assert path.entry_point == "internet"
        assert str(path.target_node_id) == str(finding.id)

    def test_internet_exposure_reads_the_column_that_actually_exists(
        self, db, organization
    ):
        """
        The old predicate was `exposure_breakdown->>'internet_exposed'`, a key
        nothing writes. The declared field is `Asset.is_internet_facing`.
        """
        internet = _asset(db, organization, "edge-01", is_internet_facing=True)
        internal = _asset(db, organization, "db-01", is_internet_facing=False)
        _finding(db, organization, internet)
        _finding(db, organization, internal, cve_id="CVE-2024-1111")

        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        entry_points = {
            path.entry_point
            for path in db.query(AttackPath).all()
        }
        assert "internet" in entry_points
        assert "adjacent_network" in entry_points

    def test_every_hop_corresponds_to_a_recorded_edge(self, db, organization):
        asset = _asset(db, organization, "edge-01", is_internet_facing=True)
        service = _service(db, organization, asset)
        _finding(db, organization, asset, service)

        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        edge_ids = {
            str(edge.id) for edge in db.query(GraphEdge).all()
        }
        for path in db.query(AttackPath).all():
            assert path.path_edges, "a path with no edges was asserted, not walked"
            assert set(path.path_edges).issubset(edge_ids)
            # nodes = edges + 1, for a walk.
            assert len(path.path_nodes) == len(path.path_edges) + 1

    def test_no_sentinel_node_is_persisted_as_a_source(self, db, organization):
        """The old engine stored uuid.UUID(int=0) to mean "the internet"."""
        asset = _asset(db, organization, "edge-01", is_internet_facing=True)
        _finding(db, organization, asset)

        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        for path in db.query(AttackPath).all():
            assert path.source_node_id != uuid.UUID(int=0)
            assert path.source_node_type == "Asset"

    def test_every_computed_path_is_potential_and_none_is_verified(
        self, db, organization
    ):
        asset = _asset(db, organization, "edge-01", is_internet_facing=True)
        _finding(db, organization, asset)

        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        strengths = {path.claim_strength for path in db.query(AttackPath).all()}
        assert strengths == {ClaimStrength.POTENTIAL}

    def test_the_engine_contains_no_path_to_a_verified_claim(self):
        """
        A structural guarantee rather than a behavioural one. This platform runs
        no exploit verification, so no line of the engine may write VERIFIED or
        OBSERVED — a later edit that starts doing so has to be deliberate.
        """
        import ast
        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[1]
            / "app" / "services" / "attack_path_engine.py"
        )
        tree = ast.parse(source.read_text(encoding="utf-8"))

        offenders = [
            f"line {node.lineno}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr in {"VERIFIED", "OBSERVED"}
        ]
        assert not offenders, (
            "The attack path engine may only produce POTENTIAL paths; this "
            f"platform verifies nothing. Found: {', '.join(offenders)}"
        )

    def test_a_closed_finding_retires_its_path(self, db, organization):
        asset = _asset(db, organization, "edge-01", is_internet_facing=True)
        finding = _finding(db, organization, asset)

        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)
        assert db.query(AttackPath).count() >= 1

        finding.status = FindingStatus.REMEDIATED
        db.add(finding)
        db.flush()
        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        assert db.query(AttackPath).count() == 0

    def test_a_verified_path_survives_recomputation(self, db, organization):
        """
        A verification is a record of something that happened. Recomputing the
        graph does not un-happen it, so retirement only touches POTENTIAL rows.
        """
        asset = _asset(db, organization, "edge-01", is_internet_facing=True)
        _finding(db, organization, asset)
        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        path = db.query(AttackPath).first()
        path.claim_strength = ClaimStrength.VERIFIED
        db.add(path)
        db.flush()

        db.query(GraphEdge).delete()
        db.flush()
        calculate_attack_paths(db, organization.id)

        assert db.query(AttackPath).filter(
            AttackPath.claim_strength == ClaimStrength.VERIFIED
        ).count() == 1

    def test_another_organizations_graph_is_not_traversed(
        self, db, organization, second_organization
    ):
        mine = _asset(db, organization, "mine-01", is_internet_facing=True)
        _finding(db, organization, mine)
        theirs = _asset(db, second_organization, "theirs-01", is_internet_facing=True)
        _finding(db, second_organization, theirs, cve_id="CVE-2024-2222")

        rebuild_organization_graph(db, organization.id)
        calculate_attack_paths(db, organization.id)

        for path in db.query(AttackPath).all():
            assert path.organization_id == organization.id


@requires_db
class TestRiskScoring:
    def test_the_score_is_explained_by_its_contributors(self, db, organization):
        asset = _asset(db, organization, "edge-01", criticality=Criticality.CRITICAL)
        finding = _finding(db, organization, asset)

        score, breakdown = score_path(
            finding=finding, asset=asset, entry_point="internet", hop_count=1
        )

        assert breakdown["score"] == score
        assert breakdown["contributors"]
        names = " ".join(item["name"] for item in breakdown["contributors"])
        assert "Critical severity" in names
        assert "business-critical" in names
        # Contributors have to add up to the score an operator is shown.
        assert round(sum(item["points"] for item in breakdown["contributors"]), 1) == score

    def test_unavailable_factors_are_declared_not_silently_omitted(
        self, db, organization
    ):
        asset = _asset(db, organization, "edge-01")
        finding = _finding(db, organization, asset)
        _, breakdown = score_path(
            finding=finding, asset=asset, entry_point="internet", hop_count=1
        )

        unavailable = {item["name"] for item in breakdown["unavailable_factors"]}
        assert "exploitability_verified" in unavailable
        assert "compensating_controls" in unavailable

    def test_a_known_exploited_vulnerability_scores_higher(self, db, organization):
        asset = _asset(db, organization, "edge-01")
        ordinary = _finding(db, organization, asset)
        exploited = _finding(
            db, organization, asset, cve_id="CVE-2024-3094", is_known_exploited=True
        )

        plain, _ = score_path(
            finding=ordinary, asset=asset, entry_point="internet", hop_count=1
        )
        raised, _ = score_path(
            finding=exploited, asset=asset, entry_point="internet", hop_count=1
        )
        assert raised > plain

    def test_a_longer_route_scores_lower_than_a_shorter_one(self, db, organization):
        asset = _asset(db, organization, "edge-01")
        finding = _finding(db, organization, asset)

        short, _ = score_path(
            finding=finding, asset=asset, entry_point="internet", hop_count=1
        )
        long, _ = score_path(
            finding=finding, asset=asset, entry_point="internet", hop_count=4
        )
        assert long < short

    def test_the_score_is_bounded(self, db, organization):
        asset = _asset(db, organization, "edge-01", criticality=Criticality.CRITICAL)
        finding = _finding(db, organization, asset, is_known_exploited=True)
        score, _ = score_path(
            finding=finding, asset=asset, entry_point="internet", hop_count=1
        )
        assert 0.0 <= score <= 100.0
