"""
Sites, networks, and the authorization-scope record.

`is_authorized_scope` is the platform's evidence that someone with a name and
an account said "yes, we own this range". These tests pin down that the record
is created, attributed, and consulted.
"""
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.endpoints.sites import router as sites_router
from app.core.rbac import RoleName
from app.core.security import create_access_token, hash_password
from app.db.session import get_db
from app.models.network import Network
from app.models.user import User
from app.services.org_provisioning import provision_new_organization


@pytest.fixture
def client(db):
    app = FastAPI()
    app.include_router(sites_router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


@pytest.fixture
def admin(db, organization):
    roles = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Org Admin",
        hashed_password=hash_password("irrelevant"),
    )
    user.roles = [roles[RoleName.ORG_ADMIN.value]]
    db.add(user)
    db.flush()
    return user


@pytest.fixture
def viewer(db, organization):
    roles = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Read Only",
        hashed_password=hash_password("irrelevant"),
    )
    user.roles = [roles[RoleName.READ_ONLY.value]]
    db.add(user)
    db.flush()
    return user


def auth(user):
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


# --- sites ---------------------------------------------------------------

def test_create_and_list_sites(client, admin):
    created = client.post("/sites", json={"name": "HQ", "location": "Dubai"}, headers=auth(admin))
    assert created.status_code == 201
    assert created.json()["name"] == "HQ"

    listed = client.get("/sites", headers=auth(admin))
    assert listed.status_code == 200
    assert [site["name"] for site in listed.json()] == ["HQ"]


def test_duplicate_site_names_are_rejected(client, admin):
    client.post("/sites", json={"name": "HQ"}, headers=auth(admin))
    duplicate = client.post("/sites", json={"name": "HQ"}, headers=auth(admin))
    assert duplicate.status_code == 409


def test_a_read_only_user_cannot_create_a_site(client, viewer):
    response = client.post("/sites", json={"name": "HQ"}, headers=auth(viewer))
    assert response.status_code == 403


# --- networks ------------------------------------------------------------

def test_create_network_normalises_the_cidr(client, admin):
    response = client.post(
        "/networks",
        json={"name": "Server VLAN", "cidr": "192.168.10.55/24"},
        headers=auth(admin),
    )
    assert response.status_code == 201
    # A host address inside a /24 is stored as the network address.
    assert response.json()["cidr"] == "192.168.10.0/24"


def test_an_invalid_cidr_is_rejected(client, admin):
    response = client.post("/networks", json={"name": "Bad", "cidr": "not-a-range"}, headers=auth(admin))
    assert response.status_code == 422


def test_duplicate_ranges_are_rejected(client, admin):
    client.post("/networks", json={"name": "A", "cidr": "10.1.0.0/24"}, headers=auth(admin))
    duplicate = client.post("/networks", json={"name": "B", "cidr": "10.1.0.0/24"}, headers=auth(admin))
    assert duplicate.status_code == 409


def test_authorizing_a_range_records_who_did_it(db, client, admin):
    """Consent without attribution is not evidence."""
    response = client.post(
        "/networks",
        json={"name": "Server VLAN", "cidr": "192.168.10.0/24", "is_authorized_scope": True},
        headers=auth(admin),
    )
    assert response.status_code == 201

    network = db.query(Network).filter(Network.cidr == "192.168.10.0/24").one()
    assert network.is_authorized_scope is True
    assert network.authorized_by_user_id == admin.id


def test_authorizing_later_also_records_the_actor(db, client, admin):
    created = client.post("/networks", json={"name": "VLAN", "cidr": "10.9.0.0/24"}, headers=auth(admin))
    network_id = created.json()["id"]

    client.patch(f"/networks/{network_id}", json={"is_authorized_scope": True}, headers=auth(admin))

    network = db.query(Network).filter(Network.id == uuid.UUID(network_id)).one()
    assert network.authorized_by_user_id == admin.id


def test_networks_default_to_unauthorized(client, admin):
    """Nothing is scannable until someone says so."""
    response = client.post("/networks", json={"name": "VLAN", "cidr": "10.5.0.0/24"}, headers=auth(admin))
    assert response.json()["is_authorized_scope"] is False
    assert response.json()["is_internet_facing"] is False


# --- authorization check -------------------------------------------------

def test_authorization_check_confirms_a_declared_range(client, admin):
    client.post(
        "/networks",
        json={"name": "Server VLAN", "cidr": "192.168.10.0/24", "is_authorized_scope": True},
        headers=auth(admin),
    )
    response = client.get("/networks/authorization-check", params={"target": "192.168.10.0/25"}, headers=auth(admin))

    body = response.json()
    assert body["authorized"] is True
    assert body["matched_network"]["cidr"] == "192.168.10.0/24"


def test_authorization_check_rejects_an_undeclared_range(client, admin):
    response = client.get("/networks/authorization-check", params={"target": "172.20.0.0/24"}, headers=auth(admin))
    body = response.json()
    assert body["authorized"] is False
    assert body["matched_network"] is None


def test_a_declared_but_unauthorized_range_is_not_authorized(client, admin):
    """Knowing a range exists is not the same as being allowed to scan it."""
    client.post("/networks", json={"name": "Guest", "cidr": "10.77.0.0/24"}, headers=auth(admin))
    response = client.get("/networks/authorization-check", params={"target": "10.77.0.0/24"}, headers=auth(admin))
    assert response.json()["authorized"] is False


def test_a_target_wider_than_the_authorized_range_is_not_authorized(client, admin):
    """/16 is not covered by permission granted for a /24 inside it."""
    client.post(
        "/networks",
        json={"name": "Server VLAN", "cidr": "192.168.10.0/24", "is_authorized_scope": True},
        headers=auth(admin),
    )
    response = client.get("/networks/authorization-check", params={"target": "192.168.0.0/16"}, headers=auth(admin))
    assert response.json()["authorized"] is False


def test_authorization_check_rejects_malformed_input(client, admin):
    response = client.get("/networks/authorization-check", params={"target": "definitely not a range"}, headers=auth(admin))
    assert response.status_code == 400


def test_another_organizations_networks_are_invisible(db, client, admin, second_organization):
    db.add(Network(
        organization_id=second_organization.id, name="Theirs",
        cidr="10.200.0.0/24", is_authorized_scope=True,
    ))
    db.flush()

    listed = client.get("/networks", headers=auth(admin))
    assert [network["cidr"] for network in listed.json()] == []

    check = client.get("/networks/authorization-check", params={"target": "10.200.0.0/24"}, headers=auth(admin))
    assert check.json()["authorized"] is False
