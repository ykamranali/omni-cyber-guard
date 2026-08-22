"""
The agent's retrieval layer.

Two things are being proven here. First, that the tools return what the
database actually holds — including returning nothing, clearly, when there is
nothing. Second, that they cannot be used to reach past the boundaries the rest
of the platform enforces: another organization's data, or data the calling
user's role does not permit.
"""
from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_db

from app.agents.tools import ToolContext, ToolError, run_tool, tools_for
from app.core.rbac import Permission, RoleName
from app.models.asset import Asset, AssetStatus, AssetType
from app.models.finding import (
    Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.core.security import hash_password
from app.models.user import User
from app.services.org_provisioning import provision_new_organization
from app.services.finding_identity import compute_fingerprint


_ROLE_CACHE: dict = {}


def _user(db, organization, role_name: RoleName, email: str | None = None) -> User:
    """A real user with a real role, provisioned the way the application does it."""
    key = (id(db), organization.id)
    if key not in _ROLE_CACHE:
        _ROLE_CACHE[key] = provision_new_organization(db, organization)
    roles = _ROLE_CACHE[key]

    user = User(
        organization_id=organization.id,
        email=email or f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Test User",
        hashed_password=hash_password("irrelevant"),
        is_active=True,
        is_super_admin=False,
    )
    user.roles = [roles[role_name.value]]
    db.add(user)
    db.flush()
    return user


def _finding(db, organization, asset, **overrides) -> Finding:
    values = dict(
        organization_id=organization.id,
        asset_id=asset.id,
        title="OpenSSH 8.9p1 reports a version with a known issue",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        finding_class=FindingClass.VULNERABILITY,
        confidence=Confidence.PROBABLE,
        source="nmap",
        cve_id="CVE-2024-6387",
        evidence="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    )
    values.update(overrides)
    values["fingerprint"] = compute_fingerprint(
        asset_id=asset.id,
        finding_class=values["finding_class"],
        source=values["source"],
        identifier=values.get("cve_id") or values["title"],
        location="22/tcp",
    )
    record = Finding(**values)
    db.add(record)
    db.flush()
    return record


@requires_db
class TestRetrieval:
    def test_counting_findings_reports_database_counts(self, db, organization, asset):
        _finding(db, organization, asset, severity=Severity.CRITICAL)
        _finding(db, organization, asset, severity=Severity.HIGH, cve_id="CVE-2024-1111")

        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        result = run_tool(ctx, "count_findings", {"group_by": "severity"})

        counts = {row["group"]: row["count"] for row in result.rows}
        assert counts == {"critical": 1, "high": 1}
        assert result.total_matching == 2

    def test_closed_findings_are_excluded_from_severity_counts(
        self, db, organization, asset
    ):
        _finding(db, organization, asset, severity=Severity.CRITICAL)
        _finding(
            db, organization, asset, severity=Severity.CRITICAL,
            cve_id="CVE-2024-2222", status=FindingStatus.REMEDIATED,
        )

        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        result = run_tool(ctx, "count_findings", {"group_by": "severity"})
        assert {row["group"]: row["count"] for row in result.rows} == {"critical": 1}

    def test_an_empty_result_says_so_rather_than_implying_safety(
        self, db, organization
    ):
        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        payload = run_tool(ctx, "search_findings", {}).as_payload()

        assert payload["row_count"] == 0
        assert "not that the environment is clean" in payload["note"]

    def test_search_returns_citable_references_for_every_row(
        self, db, organization, asset
    ):
        finding = _finding(db, organization, asset)
        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        result = run_tool(ctx, "search_findings", {})

        assert result.rows[0]["ref"] == f"finding:{finding.id}"
        assert f"finding:{finding.id}" in result.refs
        assert f"asset:{asset.id}" in result.refs
        assert "cve:CVE-2024-6387" in result.refs

    def test_truncation_is_declared_not_silent(self, db, organization, asset):
        for index in range(5):
            _finding(db, organization, asset, cve_id=f"CVE-2024-90{index:02d}")

        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        payload = run_tool(ctx, "search_findings", {"limit": 2}).as_payload()

        assert payload["row_count"] == 2
        assert payload["truncated"] is True
        assert payload["total_matching"] == 5
        assert "complete set" in payload["truncation_note"]

    def test_finding_detail_carries_verbatim_evidence(self, db, organization, asset):
        finding = _finding(db, organization, asset)
        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        row = run_tool(ctx, "get_finding", {"finding_id": str(finding.id)}).rows[0]

        assert row["evidence"] == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        assert row["confidence"] == "probable"

    def test_an_unassessed_exposure_score_is_reported_as_unassessed(
        self, db, organization, asset
    ):
        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        result = run_tool(ctx, "explain_asset_exposure", {"asset_id": str(asset.id)})

        assert result.rows == []
        assert "has not been computed" in result.note

    def test_an_assessed_exposure_score_returns_its_contributors(
        self, db, organization, asset
    ):
        asset.exposure_score = 62.5
        asset.exposure_breakdown = {
            "contributors": [{"name": "Known exploited vulnerability", "points": 30}],
            "unavailable_factors": [{"name": "attack_path_position"}],
        }
        db.add(asset)
        db.flush()

        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        row = run_tool(ctx, "explain_asset_exposure", {"asset_id": str(asset.id)}).rows[0]

        assert row["exposure_score"] == 62.5
        assert row["breakdown"]["contributors"][0]["points"] == 30

    def test_an_unsynchronised_cve_is_reported_as_unknown_not_described(
        self, db, organization
    ):
        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        result = run_tool(ctx, "get_cve_intelligence", {"cve_id": "CVE-2024-3094"})

        assert result.rows == []
        assert "has not been synchronised" in result.note
        assert "from memory" in result.note


@requires_db
class TestBoundaries:
    def test_another_organizations_findings_are_not_returned(
        self, db, organization, second_organization, asset
    ):
        _finding(db, organization, asset)

        other_asset = Asset(
            organization_id=second_organization.id,
            hostname="other-host", ip_address="10.9.9.9",
            asset_type=AssetType.SERVER, status=AssetStatus.ACTIVE,
        )
        db.add(other_asset)
        db.flush()
        _finding(db, second_organization, other_asset, title="Other org finding")

        ctx = ToolContext(
            db, organization.id, _user(db, organization, RoleName.ORG_ADMIN)
        )
        result = run_tool(ctx, "search_findings", {})

        titles = {row["title"] for row in result.rows}
        assert "Other org finding" not in titles
        assert len(result.rows) == 1

    def test_a_tool_the_role_cannot_use_is_refused(self, db, organization):
        helpdesk = _user(db, organization, RoleName.HELPDESK)
        ctx = ToolContext(db, organization.id, helpdesk)

        assert Permission.VIEW_COMPLIANCE.value not in ctx.permissions
        with pytest.raises(ToolError, match="view_compliance"):
            run_tool(ctx, "get_compliance_status", {})

    def test_a_tool_the_role_cannot_use_is_not_even_offered(self, db, organization):
        helpdesk = _user(db, organization, RoleName.HELPDESK)
        offered = {tool.name for tool in tools_for(ToolContext(db, organization.id, helpdesk))}

        assert "get_compliance_status" not in offered
        assert "search_findings" in offered

    def test_an_unknown_tool_is_refused(self, db, organization):
        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        with pytest.raises(ToolError, match="No such tool"):
            run_tool(ctx, "delete_everything", {})

    def test_bad_arguments_are_refused_with_an_explanation(self, db, organization):
        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        with pytest.raises(ToolError, match="severity must be one of"):
            run_tool(ctx, "search_findings", {"severity": "catastrophic"})

    def test_the_row_cap_cannot_be_raised_by_the_caller(
        self, db, organization, asset
    ):
        from app.core.config import settings

        for index in range(3):
            _finding(db, organization, asset, cve_id=f"CVE-2024-80{index:02d}")

        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        result = run_tool(ctx, "search_findings", {"limit": 100000})
        assert len(result.rows) <= settings.AGENT_MAX_ROWS_PER_TOOL


@requires_db
class TestReadOnly:
    def test_no_retrieval_tool_writes_to_the_database(self, db, organization, asset):
        """
        The guarantee the whole design rests on: retrieval cannot change state.

        Every tool is called with plausible arguments and the session is checked
        for pending writes afterwards.
        """
        finding = _finding(db, organization, asset)
        db.flush()

        ctx = ToolContext(db, organization.id, _user(db, organization, RoleName.ORG_ADMIN))
        arguments = {
            "count_findings": {"group_by": "severity"},
            "search_findings": {},
            "get_finding": {"finding_id": str(finding.id)},
            "count_assets": {},
            "search_assets": {},
            "get_asset": {"asset_id": str(asset.id)},
            "explain_asset_exposure": {"asset_id": str(asset.id)},
            "list_remediation_tasks": {},
            "get_compliance_status": {},
            "get_cve_intelligence": {"cve_id": "CVE-2024-3094"},
            "list_recent_scans": {},
        }

        from app.agents.tools import TOOLS_BY_NAME

        assert set(arguments) == set(TOOLS_BY_NAME), (
            "A retrieval tool was added without being covered by the read-only proof."
        )

        for name, args in arguments.items():
            run_tool(ctx, name, args)
            assert not db.new, f"{name} staged an INSERT"
            assert not db.dirty, f"{name} staged an UPDATE"
            assert not db.deleted, f"{name} staged a DELETE"


def test_the_retrieval_module_contains_no_write_operations():
    """
    A structural proof, independent of any test fixture.

    The read-only guarantee is what allows the agent to be pointed at
    production data at all. This walks the module's syntax tree and fails if a
    mutating call appears anywhere in it, so the guarantee cannot be eroded by
    a later edit that nobody thought to write a behavioural test for.
    """
    import ast
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "app" / "agents" / "tools.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))

    # Only session receivers matter: `refs.add(...)` on a Python set is not a
    # database write, and flagging it would make this guard noise.
    session_names = {"db", "session"}
    banned_methods = {
        "add", "add_all", "delete", "commit", "flush", "merge",
        "bulk_save_objects", "bulk_update_mappings", "bulk_insert_mappings",
    }
    banned_statements = {"insert", "update", "delete"}
    offenders: list[str] = []

    def _is_session(node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in session_names
        if isinstance(node, ast.Attribute):
            return node.attr in session_names
        return False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in banned_methods \
                and _is_session(func.value):
            offenders.append(f"line {node.lineno}: session.{func.attr}()")
        if isinstance(func, ast.Name) and func.id in banned_statements:
            offenders.append(f"line {node.lineno}: {func.id}() statement")

    assert not offenders, (
        "app/agents/tools.py must stay read-only; the agent may not change state "
        "without a confirmed proposal:\n  " + "\n  ".join(offenders)
    )
