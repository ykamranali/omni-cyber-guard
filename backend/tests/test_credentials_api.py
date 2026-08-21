"""
Credential vault API.

The single most important property is negative: no response may carry a secret.
That is asserted directly against the serialised JSON rather than against the
schema definition, so adding a field later cannot quietly pass.
"""
import json
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.endpoints.credentials import router as credentials_router
from app.core.rbac import RoleName
from app.core.security import create_access_token, hash_password
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.credential import CredentialProfile
from app.models.user import User
from app.services.credential_access import resolve_credential
from app.services.org_provisioning import provision_new_organization

SECRET = "D0ntL3akMe!Sup3r"


@pytest.fixture
def client(db):
    app = FastAPI()
    app.include_router(credentials_router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _user(db, organization, role):
    roles = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Test User",
        hashed_password=hash_password("irrelevant"),
    )
    user.roles = [roles[role]]
    db.add(user)
    db.flush()
    return user


@pytest.fixture
def admin(db, organization):
    return _user(db, organization, RoleName.ORG_ADMIN.value)


@pytest.fixture
def analyst(db, organization):
    return _user(db, organization, RoleName.SECURITY_ANALYST.value)


def auth(user):
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _create(client, user, **overrides):
    body = {
        "name": overrides.pop("name", "Domain scan account"),
        "credential_type": "windows",
        "username": "svc_scan",
        "domain": "CORP",
        "secret": SECRET,
    }
    body.update(overrides)
    return client.post("/credentials", json=body, headers=auth(user))


# --- the secret never comes back -----------------------------------------

def test_create_response_contains_no_secret(client, admin):
    response = _create(client, admin)
    assert response.status_code == 201

    raw = json.dumps(response.json())
    assert SECRET not in raw
    assert "secret_encrypted" not in raw
    assert response.json()["secret_set"] is True


def test_list_response_contains_no_secret(client, admin):
    _create(client, admin)
    response = client.get("/credentials", headers=auth(admin))
    raw = json.dumps(response.json())
    assert SECRET not in raw
    assert "secret_encrypted" not in raw


def test_the_stored_value_is_ciphertext(db, client, admin):
    _create(client, admin)
    profile = db.query(CredentialProfile).one()
    assert SECRET.encode() not in bytes(profile.secret_encrypted)


# --- authorization -------------------------------------------------------

def test_an_analyst_cannot_enumerate_credentials(client, analyst):
    """Running scans does not imply the right to read what they authenticate with."""
    assert client.get("/credentials", headers=auth(analyst)).status_code == 403
    assert _create(client, analyst).status_code == 403


def test_duplicate_names_are_rejected(client, admin):
    _create(client, admin)
    assert _create(client, admin).status_code == 409


def test_another_organizations_credentials_are_invisible(db, client, admin, second_organization):
    from app.core.crypto import encrypt_secret

    db.add(CredentialProfile(
        organization_id=second_organization.id,
        name="Theirs",
        credential_type="ldap",
        secret_encrypted=encrypt_secret("their-secret"),
    ))
    db.flush()

    listed = client.get("/credentials", headers=auth(admin))
    assert listed.json() == []


# --- rotation ------------------------------------------------------------

def test_rotating_replaces_the_secret_and_stamps_the_time(db, client, admin):
    created = _create(client, admin)
    credential_id = created.json()["id"]

    response = client.patch(
        f"/credentials/{credential_id}", json={"secret": "N3wSecret!"}, headers=auth(admin)
    )
    assert response.status_code == 200
    assert response.json()["rotated_at"] is not None

    resolved = resolve_credential(
        db, admin.organization_id, uuid.UUID(credential_id), purpose="test", actor_user_id=admin.id
    )
    assert resolved.secret == "N3wSecret!"


def test_updating_metadata_leaves_the_secret_intact(db, client, admin):
    created = _create(client, admin)
    credential_id = created.json()["id"]

    client.patch(f"/credentials/{credential_id}", json={"description": "updated"}, headers=auth(admin))

    resolved = resolve_credential(
        db, admin.organization_id, uuid.UUID(credential_id), purpose="test", actor_user_id=admin.id
    )
    assert resolved.secret == SECRET


# --- audited access ------------------------------------------------------

def test_resolving_a_credential_is_audited(db, client, admin):
    created = _create(client, admin)
    credential_id = uuid.UUID(created.json()["id"])

    resolve_credential(
        db, admin.organization_id, credential_id,
        purpose="windows_audit scan of 10.0.0.5", actor_user_id=admin.id,
    )
    db.flush()

    entry = (
        db.query(AuditLog)
        .filter(AuditLog.action == "credential_accessed")
        .order_by(AuditLog.created_at.desc())
        .first()
    )
    assert entry is not None
    assert entry.resource_id == str(credential_id)
    assert entry.metadata_json["purpose"] == "windows_audit scan of 10.0.0.5"
    # The audit trail records that access happened, never the secret itself.
    assert SECRET not in json.dumps(entry.metadata_json)


def test_resolving_stamps_last_used(db, client, admin):
    created = _create(client, admin)
    credential_id = uuid.UUID(created.json()["id"])

    resolve_credential(db, admin.organization_id, credential_id, purpose="test", actor_user_id=admin.id)
    db.flush()

    assert db.query(CredentialProfile).filter(CredentialProfile.id == credential_id).one().last_used_at is not None


def test_resolving_across_tenants_fails(db, client, admin, second_organization):
    created = _create(client, admin)
    credential_id = uuid.UUID(created.json()["id"])

    with pytest.raises(LookupError):
        resolve_credential(db, second_organization.id, credential_id, purpose="test")


def test_a_resolved_credential_does_not_print_its_secret(db, client, admin):
    """A traceback or a log line must not become a credential disclosure."""
    created = _create(client, admin)
    resolved = resolve_credential(
        db, admin.organization_id, uuid.UUID(created.json()["id"]), purpose="test"
    )
    assert SECRET not in repr(resolved)
    assert SECRET not in str(resolved)
    assert SECRET not in f"{resolved}"
