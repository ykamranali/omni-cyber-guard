"""
Tenant isolation. Isolation currently depends on every query filtering by
organization_id, so it needs explicit coverage: a missed filter is a
cross-customer data leak, not a bug report.
"""
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.endpoints.assets import router as assets_router
from app.api.v1.endpoints.scans import router as scans_router
from app.core.security import create_access_token, hash_password
from app.db.session import get_db
from app.models.asset import Asset, AssetStatus, AssetType
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User
from app.core.rbac import RoleName
from app.services.org_provisioning import provision_new_organization


def _user_for(db, org, role=RoleName.ORG_ADMIN.value):
    roles = provision_new_organization(db, org)
    user = User(
        organization_id=org.id,
        email=f"{uuid.uuid4().hex[:8]}@tenant.local",
        full_name="Tenant User",
        hashed_password=hash_password("irrelevant"),
    )
    user.roles = [roles[role]]
    db.add(user)
    db.flush()
    return user


def _client(db):
    app = FastAPI()
    app.include_router(assets_router)
    app.include_router(scans_router)
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


def _auth(user):
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def test_assets_from_another_organization_are_not_listed(db, organization, second_organization):
    mine = Asset(organization_id=organization.id, hostname="mine",
                 ip_address="192.168.1.2", asset_type=AssetType.SERVER, status=AssetStatus.ACTIVE)
    theirs = Asset(organization_id=second_organization.id, hostname="theirs",
                   ip_address="192.168.1.3", asset_type=AssetType.SERVER, status=AssetStatus.ACTIVE)
    db.add_all([mine, theirs])
    db.flush()

    user = _user_for(db, organization)
    response = _client(db).get("/assets", headers=_auth(user))

    assert response.status_code == 200
    payload = response.json()
    hostnames = {item["hostname"] for item in (payload.get("items", payload) if isinstance(payload, dict) else payload)}
    assert "mine" in hostnames
    assert "theirs" not in hostnames


def test_scans_from_another_organization_are_not_listed(db, organization, second_organization):
    db.add_all([
        ScanJob(organization_id=organization.id, target_cidr="192.168.1.0/24", status=ScanStatus.COMPLETED),
        ScanJob(organization_id=second_organization.id, target_cidr="10.9.9.0/24", status=ScanStatus.COMPLETED),
    ])
    db.flush()

    user = _user_for(db, organization)
    response = _client(db).get("/scans", headers=_auth(user))

    assert response.status_code == 200
    targets = {item["target_cidr"] for item in response.json()}
    assert "192.168.1.0/24" in targets
    assert "10.9.9.0/24" not in targets


def test_fetching_another_organizations_scan_by_id_returns_404(db, organization, second_organization):
    theirs = ScanJob(organization_id=second_organization.id, target_cidr="10.9.9.0/24",
                     status=ScanStatus.COMPLETED)
    db.add(theirs)
    db.flush()

    user = _user_for(db, organization)
    response = _client(db).get(f"/scans/{theirs.id}", headers=_auth(user))
    assert response.status_code == 404
