"""
Authorized scope, enforced at launch.

`Network.is_authorized_scope` is described in the model as "the record of
consent", and the sites module states that "discovery and scanning both consult
this table". Neither did: the authorization endpoint existed, the Scan Centre
called it to *display* a warning, and nothing acted on the answer. The only
real gate was a private-range check, which stops a scan of the public internet
and stops nothing else.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import requires_db

from app.core.rbac import RoleName
from app.core.security import create_access_token, hash_password
from app.db.session import get_db
from app.models.network import Network
from app.models.scan_job import ScanJob
from app.models.user import User
from app.services.scan_authorization import (
    AuthorizationError, assert_target_authorized, check_target,
)
from app.services.org_provisioning import provision_new_organization

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


def _network(db, organization, cidr: str, *, authorized: bool) -> Network:
    network = Network(
        organization_id=organization.id,
        name=f"Range {cidr}",
        cidr=cidr,
        is_authorized_scope=authorized,
    )
    db.add(network)
    db.flush()
    return network


@requires_db
class TestScopeCheck:
    def test_a_declared_authorized_range_authorizes_a_subnet_of_it(
        self, db, organization
    ):
        _network(db, organization, "192.168.10.0/24", authorized=True)
        result = check_target(
            db, organization_id=organization.id, target="192.168.10.0/25"
        )
        assert result.authorized
        assert result.matched_network["cidr"] == "192.168.10.0/24"

    def test_a_single_address_inside_the_range_is_authorized(self, db, organization):
        _network(db, organization, "192.168.10.0/24", authorized=True)
        result = check_target(
            db, organization_id=organization.id, target="192.168.10.55"
        )
        assert result.authorized

    def test_a_declared_but_unauthorized_range_does_not_authorize(
        self, db, organization
    ):
        _network(db, organization, "192.168.10.0/24", authorized=False)
        result = check_target(
            db, organization_id=organization.id, target="192.168.10.0/24"
        )
        assert not result.authorized
        # The operator is told the range is known but not approved, which is a
        # different problem from never having registered it.
        assert "not marked as authorized scope" in result.message

    def test_a_range_that_was_never_declared_is_not_authorized(
        self, db, organization
    ):
        result = check_target(
            db, organization_id=organization.id, target="10.20.30.0/24"
        )
        assert not result.authorized
        assert result.matched_network is None

    def test_a_supernet_of_a_declared_range_is_not_authorized(self, db, organization):
        """Declaring a /24 does not authorize the /16 that contains it."""
        _network(db, organization, "192.168.10.0/24", authorized=True)
        result = check_target(
            db, organization_id=organization.id, target="192.168.0.0/16"
        )
        assert not result.authorized

    def test_another_organizations_authorization_does_not_apply(
        self, db, organization, second_organization
    ):
        _network(db, second_organization, "192.168.10.0/24", authorized=True)
        result = check_target(
            db, organization_id=organization.id, target="192.168.10.0/24"
        )
        assert not result.authorized

    def test_a_malformed_stored_range_authorizes_nothing(self, db, organization):
        """A corrupt row must not behave as a wildcard."""
        network = Network(
            organization_id=organization.id, name="Broken",
            cidr="not-a-cidr", is_authorized_scope=True,
        )
        db.add(network)
        db.flush()
        result = check_target(
            db, organization_id=organization.id, target="192.168.10.0/24"
        )
        assert not result.authorized

    def test_a_malformed_target_is_rejected_not_authorized(self, db, organization):
        _network(db, organization, "192.168.10.0/24", authorized=True)
        result = check_target(db, organization_id=organization.id, target="haystack")
        assert not result.authorized
        assert "not a valid IP address" in result.message

    def test_assert_raises_when_unauthorized(self, db, organization):
        with pytest.raises(AuthorizationError):
            assert_target_authorized(
                db, organization_id=organization.id, target="10.20.30.0/24"
            )


@requires_db
class TestScanEndpointEnforcement:
    @pytest.fixture
    def client(self, db):
        from app.api.v1.endpoints.scans import router

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app)

    @staticmethod
    def _auth(user):
        return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    def test_a_scan_of_an_unauthorized_range_is_refused(
        self, client, db, organization
    ):
        user = _user(db, organization)
        response = client.post(
            "/scans",
            json={
                "target_cidr": "192.168.77.0/24",
                "engine": "nmap",
                "authorization_confirmed": True,
            },
            headers=self._auth(user),
        )
        assert response.status_code == 403
        assert "authorized scope" in response.json()["detail"]
        assert db.query(ScanJob).count() == 0

    def test_confirmation_is_required_even_inside_an_authorized_range(
        self, client, db, organization
    ):
        """
        Registering a range once is not standing consent to scan it whenever.
        The specification requires confirmation before launch.
        """
        user = _user(db, organization)
        _network(db, organization, "192.168.77.0/24", authorized=True)

        response = client.post(
            "/scans",
            json={"target_cidr": "192.168.77.0/24", "engine": "nmap"},
            headers=self._auth(user),
        )
        assert response.status_code == 400
        assert "Confirm that you are authorized" in response.json()["detail"]
        assert db.query(ScanJob).count() == 0

    def test_a_refusal_is_recorded_in_the_audit_log(
        self, client, db, organization
    ):
        from app.models.audit_log import AuditLog

        user = _user(db, organization)
        client.post(
            "/scans",
            json={
                "target_cidr": "192.168.77.0/24",
                "engine": "nmap",
                "authorization_confirmed": True,
            },
            headers=self._auth(user),
        )
        actions = {
            row.action for row in db.query(AuditLog).filter(
                AuditLog.organization_id == organization.id
            ).all()
        }
        assert "scan_refused_unauthorized_scope" in actions
