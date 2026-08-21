"""
Login lockout. Before this, the endpoint had no rate limit and no lockout, so
credential stuffing against a known email address was unbounded.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.endpoints.auth import MAX_FAILED_ATTEMPTS, router as auth_router
from app.core.rate_limit import limiter
from app.core.security import hash_password
from app.db.session import get_db
from app.models.user import User
from app.services.org_provisioning import provision_new_organization

PASSWORD = "S3cure!TestPassword"
# email_validator rejects special-use domains (.local, .test, .invalid), and
# LoginRequest.email is an EmailStr — so the address here must look real.
EMAIL = "lockout@omni-test.com"


@pytest.fixture
def login_client(db, organization):
    provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email="lockout@omni-test.com",
        full_name="Lockout Test",
        hashed_password=hash_password(PASSWORD),
    )
    db.add(user)
    db.flush()

    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(auth_router)
    app.dependency_overrides[get_db] = lambda: db
    # Disable the request-rate limiter so this test exercises the lockout logic
    # specifically; the limiter itself is covered separately.
    limiter.enabled = False
    yield TestClient(app), user
    limiter.enabled = True


def test_correct_credentials_return_tokens(login_client):
    client, _ = login_client
    response = client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] and body["refresh_token"]


def test_failed_attempts_are_counted(login_client, db):
    client, user = login_client
    client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": "wrong"})
    db.refresh(user)
    assert user.failed_login_attempts == 1


def test_account_locks_after_repeated_failures(login_client, db):
    client, user = login_client
    for _ in range(MAX_FAILED_ATTEMPTS):
        response = client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": "wrong"})
        assert response.status_code == 401

    db.refresh(user)
    assert user.locked_until is not None

    # The correct password must not work while the account is locked.
    locked = client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": PASSWORD})
    assert locked.status_code == 429


def test_successful_login_clears_the_failure_counter(login_client, db):
    client, user = login_client
    client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": "wrong"})
    client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": PASSWORD})
    db.refresh(user)
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


def test_expired_lock_allows_login_again(login_client, db):
    client, user = login_client
    user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.flush()
    response = client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": PASSWORD})
    assert response.status_code == 200


def test_unknown_email_returns_the_same_error_as_a_wrong_password(login_client):
    client, _ = login_client
    unknown = client.post("/auth/login", json={"email": "nobody@omni-test.com", "password": "whatever"})
    wrong = client.post("/auth/login", json={"email": "lockout@omni-test.com", "password": "wrong"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["detail"] == wrong.json()["detail"]
