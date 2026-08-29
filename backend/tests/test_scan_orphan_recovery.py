"""
Scans whose worker disappeared.

Cancellation is cooperative: the API sets cancel_requested and the worker,
polling, terminates the scanner. Nothing in that design covers the worker
itself going away — a restart, a deploy, an out-of-memory kill. The scanner
process dies with it, the row stays at RUNNING, and because the time budget is
enforced inside the task, nothing enforces it either.

What the operator saw was a scan running for over an hour and a Stop button
that reported success and changed nothing, because the flag it set had no
reader.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.conftest import requires_db

from app.core.rbac import RoleName
from app.core.security import create_access_token, hash_password
from app.db.session import get_db
from app.models.scan_job import ScanJob, ScanStatus, ScanType
from app.models.user import User
from app.services.org_provisioning import provision_new_organization
from app.tasks.scan_tasks import ORPHAN_AFTER_SECONDS

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


def _running_job(db, organization, *, silent_for_seconds: float) -> ScanJob:
    job = ScanJob(
        organization_id=organization.id,
        target_cidr="192.168.55.0/24",
        scan_type=ScanType.PORT_SERVICE_SCAN,
        engine="nmap",
        status=ScanStatus.RUNNING,
        heartbeat_at=datetime.now(timezone.utc) - timedelta(seconds=silent_for_seconds),
    )
    db.add(job)
    db.flush()
    return job


@requires_db
class TestCancelWithoutAWorker:
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

    def test_stopping_an_abandoned_scan_actually_stops_it(
        self, client, db, organization
    ):
        """
        The reported bug. Setting a flag nobody reads is not stopping a scan.
        """
        user = _user(db, organization)
        job = _running_job(db, organization, silent_for_seconds=ORPHAN_AFTER_SECONDS + 120)

        response = client.post(f"/scans/{job.id}/cancel", headers=self._auth(user))

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "canceled"

        db.refresh(job)
        assert job.status is ScanStatus.CANCELED
        assert "had not reported" in (job.error_message or "")

    def test_a_live_scan_is_asked_to_stop_not_declared_stopped(
        self, client, db, organization
    ):
        """
        A scan whose worker is still beating has a real process behind it. The
        flag is the correct mechanism there, and claiming it had already
        stopped would be reporting an outcome that has not happened.
        """
        user = _user(db, organization)
        job = _running_job(db, organization, silent_for_seconds=5)

        response = client.post(f"/scans/{job.id}/cancel", headers=self._auth(user))

        assert response.status_code == 200
        db.refresh(job)
        assert job.cancel_requested is True
        assert job.status is ScanStatus.RUNNING


@requires_db
class TestReaper:
    def test_an_abandoned_scan_is_recorded_as_failed(self, db, organization, monkeypatch):
        from app.tasks import scan_tasks

        job = _running_job(db, organization, silent_for_seconds=ORPHAN_AFTER_SECONDS + 60)
        job_id = job.id
        db.commit()

        monkeypatch.setattr(scan_tasks, "SessionLocal", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)

        result = scan_tasks.reap_orphaned_scans()

        assert str(job_id) in result["reaped"]
        db.refresh(job)
        assert job.status is ScanStatus.FAILED
        assert "worker running this scan stopped" in (job.error_message or "")
        # The partial output is kept: it was really observed.
        assert "[orphaned]" in (job.raw_summary or "")

    def test_a_scan_that_is_still_beating_is_left_alone(self, db, organization, monkeypatch):
        from app.tasks import scan_tasks

        job = _running_job(db, organization, silent_for_seconds=10)
        job_id = job.id
        db.commit()

        monkeypatch.setattr(scan_tasks, "SessionLocal", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)

        result = scan_tasks.reap_orphaned_scans()

        assert str(job_id) not in result["reaped"]
        db.refresh(job)
        assert job.status is ScanStatus.RUNNING

    def test_a_just_started_scan_with_no_heartbeat_yet_is_left_alone(
        self, db, organization, monkeypatch
    ):
        """
        There is a moment between a job going RUNNING and its first beat.
        Reaping there would kill scans for being new.
        """
        from app.tasks import scan_tasks

        job = ScanJob(
            organization_id=organization.id,
            target_cidr="192.168.56.0/24",
            scan_type=ScanType.PORT_SERVICE_SCAN,
            engine="nmap",
            status=ScanStatus.RUNNING,
            heartbeat_at=None,
        )
        db.add(job)
        db.commit()

        monkeypatch.setattr(scan_tasks, "SessionLocal", lambda: db)
        monkeypatch.setattr(db, "close", lambda: None)

        assert str(job.id) not in scan_tasks.reap_orphaned_scans()["reaped"]
