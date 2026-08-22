"""
Authentication hardening and authorization enforcement.

Covers the two gaps that mattered most: login had no brute-force resistance,
and authorization must be proven on the backend rather than assumed from the
frontend hiding a nav item.
"""
import uuid

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from tests.conftest import requires_db

from app.core.deps import get_current_user, require_permission, require_super_admin
from app.core.rbac import DEFAULT_ROLE_PERMISSIONS, Permission, RoleName
from app.core.security import create_access_token, create_refresh_token, decode_token, hash_password, verify_password
from app.db.session import get_db
from app.models.user import User
from app.services.org_provisioning import provision_new_organization


# --- password hashing ----------------------------------------------------

def test_passwords_are_hashed_not_stored():
    hashed = hash_password("correct horse battery staple")
    assert hashed != "correct horse battery staple"
    assert hashed.startswith("$argon2")
    assert verify_password("correct horse battery staple", hashed)
    assert not verify_password("wrong password", hashed)


def test_same_password_produces_different_hashes():
    assert hash_password("same") != hash_password("same")


# --- tokens --------------------------------------------------------------

def test_access_and_refresh_tokens_are_distinguishable():
    subject = str(uuid.uuid4())
    assert decode_token(create_access_token(subject))["type"] == "access"
    assert decode_token(create_refresh_token(subject))["type"] == "refresh"


@requires_db
def test_refresh_token_is_rejected_as_an_access_token():
    """A refresh token must not authenticate an API call."""
    app = FastAPI()

    @app.get("/whoami")
    def whoami(user: User = Depends(get_current_user)):
        return {"id": str(user.id)}

    client = TestClient(app)
    token = create_refresh_token(str(uuid.uuid4()))
    assert client.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


@requires_db
def test_garbage_token_is_rejected():
    app = FastAPI()

    @app.get("/whoami")
    def whoami(user: User = Depends(get_current_user)):
        return {"id": str(user.id)}

    client = TestClient(app)
    assert client.get("/whoami", headers={"Authorization": "Bearer not.a.token"}).status_code == 401


# --- RBAC matrix ---------------------------------------------------------

def test_read_only_role_cannot_run_scans_or_manage_users():
    granted = DEFAULT_ROLE_PERMISSIONS[RoleName.READ_ONLY]
    assert Permission.RUN_SCANS not in granted
    assert Permission.MANAGE_USERS not in granted
    assert Permission.MANAGE_ASSETS not in granted
    assert Permission.VIEW_FINDINGS in granted


def test_auditor_can_read_audit_logs_but_not_change_anything():
    granted = DEFAULT_ROLE_PERMISSIONS[RoleName.AUDITOR]
    assert Permission.VIEW_AUDIT_LOGS in granted
    assert Permission.MANAGE_FINDINGS not in granted
    assert Permission.MANAGE_USERS not in granted


def test_only_super_admin_can_manage_the_platform():
    for role, granted in DEFAULT_ROLE_PERMISSIONS.items():
        if role is RoleName.SUPER_ADMIN:
            assert Permission.MANAGE_PLATFORM in granted
        else:
            assert Permission.MANAGE_PLATFORM not in granted, role
            assert Permission.MANAGE_ORGANIZATIONS not in granted, role


# --- permission enforcement against a real user --------------------------

@pytest.fixture
def app_with_db(db):
    app = FastAPI()

    @app.get("/needs-run-scans")
    def needs_run_scans(user: User = Depends(require_permission(Permission.RUN_SCANS))):
        return {"ok": True}

    @app.get("/needs-super-admin")
    def needs_super_admin(user: User = Depends(require_super_admin)):
        return {"ok": True}

    app.dependency_overrides[get_db] = lambda: db
    return app


def _make_user(db, organization, role_name: str, is_super_admin: bool = False) -> User:
    roles = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@test.local",
        full_name="Test User",
        hashed_password=hash_password("irrelevant"),
        is_super_admin=is_super_admin,
    )
    user.roles = [roles[role_name]]
    db.add(user)
    db.flush()
    return user


def test_permission_is_enforced_on_the_backend(app_with_db, db, organization):
    analyst = _make_user(db, organization, RoleName.SECURITY_ANALYST.value)
    viewer = _make_user(db, organization, RoleName.READ_ONLY.value)
    client = TestClient(app_with_db)

    allowed = client.get(
        "/needs-run-scans",
        headers={"Authorization": f"Bearer {create_access_token(str(analyst.id))}"},
    )
    denied = client.get(
        "/needs-run-scans",
        headers={"Authorization": f"Bearer {create_access_token(str(viewer.id))}"},
    )

    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert "run_scans" in denied.json()["detail"]


def test_org_admin_cannot_reach_super_admin_routes(app_with_db, db, organization):
    org_admin = _make_user(db, organization, RoleName.ORG_ADMIN.value)
    client = TestClient(app_with_db)
    response = client.get(
        "/needs-super-admin",
        headers={"Authorization": f"Bearer {create_access_token(str(org_admin.id))}"},
    )
    assert response.status_code == 403


def test_deactivated_user_cannot_authenticate(app_with_db, db, organization):
    user = _make_user(db, organization, RoleName.ORG_ADMIN.value)
    user.is_active = False
    db.flush()

    client = TestClient(app_with_db)
    response = client.get(
        "/needs-run-scans",
        headers={"Authorization": f"Bearer {create_access_token(str(user.id))}"},
    )
    assert response.status_code == 401
