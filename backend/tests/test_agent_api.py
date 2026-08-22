"""
The agent HTTP surface.

The concerns here are the ones an endpoint can get wrong independently of the
agent: that every route is permission-guarded, that one organization cannot
reach another's transcripts, that the confirmation route checks the confirming
user rather than the proposer, and that a disabled assistant is reported as a
configuration state instead of an error.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import requires_db

from app.agents import actions as action_registry
from app.api.v1.endpoints.agent import router as agent_router
from app.core.rbac import RoleName
from app.core.security import create_access_token, hash_password
from app.db.session import get_db
from app.models.agent import AgentConversation, ProposalStatus
from app.models.finding import (
    Confidence, Finding, FindingClass, FindingStatus, Severity,
)
from app.models.remediation import RemediationTask
from app.models.user import User
from app.services.finding_identity import compute_fingerprint
from app.services.org_provisioning import provision_new_organization


@pytest.fixture
def client(db):
    app = FastAPI()
    app.include_router(agent_router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


_ROLES: dict = {}


def _user(db, organization, role_name: RoleName = RoleName.ORG_ADMIN) -> User:
    key = (id(db), organization.id)
    if key not in _ROLES:
        _ROLES[key] = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Test User",
        hashed_password=hash_password("irrelevant"),
        is_active=True,
    )
    user.roles = [_ROLES[key][role_name.value]]
    db.add(user)
    db.flush()
    return user


def auth(user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _finding(db, organization, asset) -> Finding:
    record = Finding(
        organization_id=organization.id,
        asset_id=asset.id,
        title="Telnet is exposed on the management interface",
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        finding_class=FindingClass.EXPOSURE,
        confidence=Confidence.CONFIRMED,
        source="nmap",
        evidence="23/tcp open telnet",
        fingerprint=compute_fingerprint(
            asset_id=asset.id, finding_class=FindingClass.EXPOSURE,
            source="nmap", identifier="telnet", location="23/tcp",
        ),
    )
    db.add(record)
    db.flush()
    return record


@requires_db
class TestAccessControl:
    def test_every_route_requires_authentication(self, client):
        assert client.get("/agent/status").status_code == 401
        assert client.post("/agent/chat", json={"message": "hello"}).status_code == 401
        assert client.get("/agent/conversations").status_code == 401
        assert client.get("/agent/actions").status_code == 401

    def test_a_role_holding_no_permissions_is_refused(self, client, db, organization):
        """
        Authentication is not authorization. A valid token for an account whose
        role grants nothing must still be turned away.
        """
        from app.models.role import Role

        empty_role = Role(organization_id=organization.id, name="no-permissions")
        db.add(empty_role)
        db.flush()
        user = User(
            organization_id=organization.id,
            email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
            full_name="Powerless", hashed_password=hash_password("irrelevant"),
            is_active=True,
        )
        user.roles = [empty_role]
        db.add(user)
        db.flush()

        response = client.get("/agent/status", headers=auth(user))
        assert response.status_code == 403
        assert "view_findings" in response.json()["detail"]

    def test_another_organizations_conversation_is_not_reachable(
        self, client, db, organization, second_organization
    ):
        owner = _user(db, organization)
        outsider = _user(db, second_organization)
        conversation = AgentConversation(
            organization_id=organization.id, user_id=owner.id, title="private"
        )
        db.add(conversation)
        db.flush()

        response = client.get(
            f"/agent/conversations/{conversation.id}", headers=auth(outsider)
        )
        assert response.status_code == 404


@requires_db
class TestStatus:
    def test_status_reports_what_is_missing_and_how_to_supply_it(
        self, client, db, organization
    ):
        user = _user(db, organization)
        body = client.get("/agent/status", headers=auth(user)).json()

        provider = body["provider"]
        assert provider["configured"] is False
        assert "AGENT_LLM_PROVIDER" in provider["missing"]
        assert "AGENT_LLM_BASE_URL" in provider["how_to_enable"]
        assert provider["why_required"]
        assert provider["implemented_in"].endswith("provider.py")

    def test_status_lists_the_retrievals_the_caller_may_make(
        self, client, db, organization
    ):
        user = _user(db, organization)
        body = client.get("/agent/status", headers=auth(user)).json()
        names = {tool["name"] for tool in body["retrieval_tools"]}

        assert "search_findings" in names
        assert body["guarantees"]["retrieval_is_read_only"] is True
        assert body["guarantees"]["actions_require_human_confirmation"] is True

    def test_chat_without_a_model_answers_with_a_status_not_an_error(
        self, client, db, organization
    ):
        user = _user(db, organization)
        body = client.post(
            "/agent/chat", json={"message": "What is exposed?"}, headers=auth(user)
        ).json()

        assert body["available"] is False
        assert body["answer"] == ""
        assert "No language model is configured" in body["unavailable_reason"]
        # The question is still recorded, so an operator can see it was asked.
        assert body["conversation_id"]


@requires_db
class TestProposalRoutes:
    def _proposal(self, db, organization, user, finding):
        return action_registry.propose(
            db, organization_id=organization.id,
            action_type="create_remediation_task",
            parameters={"finding_id": str(finding.id)},
            rationale="Telnet is cleartext.",
            proposed_by_user_id=user.id,
        )

    def test_a_proposal_is_listed_with_the_effect_of_confirming_it(
        self, client, db, organization, asset
    ):
        user = _user(db, organization)
        finding = _finding(db, organization, asset)
        self._proposal(db, organization, user, finding)

        rows = client.get("/agent/actions", headers=auth(user)).json()
        assert len(rows) == 1
        assert rows[0]["status"] == "proposed"
        assert finding.title in rows[0]["effect"]
        assert rows[0]["required_permission"] == "manage_findings"

    def test_confirming_executes_and_reports_the_result(
        self, client, db, organization, asset
    ):
        user = _user(db, organization)
        finding = _finding(db, organization, asset)
        proposal = self._proposal(db, organization, user, finding)

        response = client.post(
            f"/agent/actions/{proposal.id}/confirm", headers=auth(user)
        )
        assert response.status_code == 200
        assert response.json()["status"] == "executed"
        assert db.query(RemediationTask).count() == 1

    def test_a_user_lacking_the_actions_permission_cannot_confirm(
        self, client, db, organization, asset
    ):
        proposer = _user(db, organization)
        viewer = _user(db, organization, RoleName.READ_ONLY)
        finding = _finding(db, organization, asset)
        proposal = self._proposal(db, organization, proposer, finding)

        response = client.post(
            f"/agent/actions/{proposal.id}/confirm", headers=auth(viewer)
        )
        assert response.status_code == 409
        assert "manage_findings" in response.json()["detail"]
        assert db.query(RemediationTask).count() == 0

    def test_another_organization_cannot_confirm_a_proposal(
        self, client, db, organization, second_organization, asset
    ):
        owner = _user(db, organization)
        outsider = _user(db, second_organization)
        finding = _finding(db, organization, asset)
        proposal = self._proposal(db, organization, owner, finding)

        response = client.post(
            f"/agent/actions/{proposal.id}/confirm", headers=auth(outsider)
        )
        assert response.status_code == 404
        assert db.query(RemediationTask).count() == 0

    def test_rejecting_records_the_decision(self, client, db, organization, asset):
        user = _user(db, organization)
        finding = _finding(db, organization, asset)
        proposal = self._proposal(db, organization, user, finding)

        response = client.post(
            f"/agent/actions/{proposal.id}/reject",
            json={"note": "The network team is decommissioning the host."},
            headers=auth(user),
        )
        assert response.status_code == 200
        assert response.json()["status"] == "rejected"
        assert proposal.status is ProposalStatus.REJECTED
        assert db.query(RemediationTask).count() == 0


def test_every_route_on_this_surface_declares_a_permission():
    """
    Syntax-tree guard to ensure all platform endpoints declare a required
    permission. Failures here indicate an endpoint that authenticates but
    does not authorize.
    """
    import ast
    from pathlib import Path

    tests_dir = Path(__file__).parent
    endpoints_dir = tests_dir.parent / "app" / "api" / "v1" / "endpoints"

    unguarded: list[str] = []
    for source in endpoints_dir.glob("*.py"):
        if source.name in ("__init__.py", "auth.py", "ws.py", "organizations.py", "users.py", "system.py"):
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                is_route = any(
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and getattr(decorator.func.value, "id", "") == "router"
                    for decorator in node.decorator_list
                )
                if not is_route:
                    continue

                guarded = "require_permission" in ast.dump(node.args) or "require_super_admin" in ast.dump(node.args)
                if not guarded:
                    unguarded.append(f"{source.name}:{node.name}")

    assert not unguarded, (
        f"Missing 'require_permission' or 'require_super_admin' on endpoints:\n" + "\n".join(unguarded)
    )
