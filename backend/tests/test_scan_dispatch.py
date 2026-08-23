"""
The create-scan happy path, and the two ways it used to fail silently.

This endpoint had no success-path test at all. Every test asserted a refusal —
unauthorized range, missing confirmation, unknown engine — so the one sequence
that matters, "an authorized scan is created and actually handed to a worker",
was never exercised. The bug that shipped was exactly there: the row committed,
`db.refresh` raised, and the dispatch line below it never ran. The Scan Centre
showed a job at QUEUED forever, with no error recorded against it, because the
code that records a dispatch failure had not been reached either.

A scan job that exists but was never queued is worse than one that failed. The
operator sees a scan they believe is about to start.
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
from app.models.scan_job import ScanJob, ScanStatus
from app.models.user import User
from app.scanners.contract import ConfigurationStatus
from app.services.org_provisioning import provision_new_organization

_ROLES: dict = {}


def _user(db, organization) -> User:
    key = (id(db), organization.id)
    if key not in _ROLES:
        _ROLES[key] = provision_new_organization(db, organization)
    user = User(
        organization_id=organization.id,
        email=f"{uuid.uuid4().hex[:8]}@omni-test.com",
        full_name="Scan Operator",
        hashed_password=hash_password("irrelevant"),
        is_active=True,
    )
    user.roles = [_ROLES[key][RoleName.ORG_ADMIN.value]]
    db.add(user)
    db.flush()
    return user


@requires_db
class TestScanDispatch:
    @pytest.fixture
    def client(self, db):
        from app.api.v1.endpoints.scans import router

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = lambda: db
        return TestClient(app)

    @pytest.fixture
    def nmap_available(self, monkeypatch):
        """
        The test host has no nmap binary; the endpoint's own logic is what is
        under test here, not tool discovery.
        """
        from app.scanners.nmap import NmapScanner

        monkeypatch.setattr(
            NmapScanner, "validate_configuration",
            lambda self: ConfigurationStatus.ready(summary="nmap stubbed for tests"),
        )

    @pytest.fixture
    def authorized_range(self, db, organization):
        network = Network(
            organization_id=organization.id, name="Lab",
            cidr="192.168.77.0/24", is_authorized_scope=True,
        )
        db.add(network)
        db.flush()
        return network

    @staticmethod
    def _auth(user):
        return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    def _payload(self):
        return {
            "target_cidr": "192.168.77.0/24",
            "engine": "nmap",
            "authorization_confirmed": True,
        }

    def _dispatch_recorder(self, monkeypatch, *, fail: bool = False):
        sent: list[str] = []

        def delay(job_id: str):
            if fail:
                raise RuntimeError("broker unreachable")
            sent.append(job_id)

        import app.tasks.scan_tasks as scan_tasks
        monkeypatch.setattr(scan_tasks.run_network_scan, "delay", delay)
        return sent

    def test_an_authorized_scan_is_created_and_dispatched(
        self, client, db, organization, monkeypatch, nmap_available, authorized_range
    ):
        sent = self._dispatch_recorder(monkeypatch)
        user = _user(db, organization)

        response = client.post("/scans", json=self._payload(), headers=self._auth(user))

        assert response.status_code == 202, response.text
        job_id = response.json()["id"]
        assert sent == [job_id], "the job was created but never handed to a worker"

        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(job_id)).one()
        assert job.status is ScanStatus.QUEUED
        assert job.target_cidr == "192.168.77.0/24"

    def test_a_failed_reload_after_commit_does_not_lose_the_scan(
        self, client, db, organization, monkeypatch, nmap_available, authorized_range
    ):
        """
        The regression this file exists for.

        `db.refresh` raised in the running deployment — "Could not refresh
        instance" — and because the dispatch sat below it, the scan was never
        queued and nothing recorded why. The reload is now advisory: whatever
        it does, the worker gets the job.
        """
        sent = self._dispatch_recorder(monkeypatch)
        user = _user(db, organization)

        from sqlalchemy.orm import Session as SASession
        original_refresh = SASession.refresh

        def refuse_scan_job_refresh(self, instance, *args, **kwargs):
            if isinstance(instance, ScanJob):
                raise RuntimeError("Could not refresh instance")
            return original_refresh(self, instance, *args, **kwargs)

        monkeypatch.setattr(SASession, "refresh", refuse_scan_job_refresh)

        response = client.post("/scans", json=self._payload(), headers=self._auth(user))

        assert response.status_code == 202, response.text
        assert len(sent) == 1, "a reload failure must not stop the dispatch"

        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(sent[0])).one()
        assert job.status is ScanStatus.QUEUED

    def test_a_dispatch_failure_marks_the_job_failed_rather_than_queued(
        self, client, db, organization, monkeypatch, nmap_available, authorized_range
    ):
        """
        A job nobody will run must not display as one about to start.
        """
        self._dispatch_recorder(monkeypatch, fail=True)
        user = _user(db, organization)

        response = client.post("/scans", json=self._payload(), headers=self._auth(user))

        assert response.status_code == 503
        assert "could not be handed to a worker" in response.json()["detail"]

        job = db.query(ScanJob).order_by(ScanJob.created_at.desc()).first()
        assert job is not None
        assert job.status is ScanStatus.FAILED
        assert "broker unreachable" in (job.error_message or "")
        assert "docker compose ps worker redis" in (job.error_message or "")
