"""
Live notifications, and knowing whether anything is running.

Two silent failures are covered here.

The WebSocket manager keyed connections by the JWT's `org_id` claim, a string,
while `broadcast_to_org` was called with `current_user.organization_id`, a UUID
object. The dictionary lookup never matched, so every "Scan initiated"
notification was dropped while the request that sent it returned 202.

And a queued scan that no worker will ever take looks exactly like a queued
scan that is about to start. The health check answers that directly rather than
leaving the operator to guess.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import requires_db

from app.services.websocket import ConnectionManager


class FakeSocket:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[dict] = []
        self.accepted = False
        self._fail = fail

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(self, message: dict) -> None:
        if self._fail:
            raise ConnectionError("socket is gone")
        self.sent.append(message)


def _run(coroutine):
    return asyncio.run(coroutine)


class TestBroadcast:
    def test_a_uuid_publisher_reaches_a_string_subscriber(self):
        """
        The exact mismatch that silently swallowed every notification: the
        socket registers with the string form, the API broadcasts with the UUID.
        """
        organization_id = uuid.uuid4()
        manager = ConnectionManager()
        socket = FakeSocket()

        _run(manager.connect(socket, str(organization_id)))
        delivered = _run(manager.broadcast_to_org(organization_id, {"type": "info"}))

        assert delivered == 1
        assert socket.sent == [{"type": "info"}]

    def test_a_string_publisher_reaches_a_uuid_subscriber(self):
        organization_id = uuid.uuid4()
        manager = ConnectionManager()
        socket = FakeSocket()

        _run(manager.connect(socket, organization_id))
        delivered = _run(manager.broadcast_to_org(str(organization_id), {"n": 1}))

        assert delivered == 1

    def test_broadcast_reports_how_many_clients_it_reached(self):
        organization_id = uuid.uuid4()
        manager = ConnectionManager()
        for _ in range(3):
            _run(manager.connect(FakeSocket(), organization_id))

        assert _run(manager.broadcast_to_org(organization_id, {"n": 1})) == 3

    def test_delivering_to_nobody_is_distinguishable_from_delivering(self):
        manager = ConnectionManager()
        assert _run(manager.broadcast_to_org(uuid.uuid4(), {"n": 1})) == 0

    def test_another_organization_does_not_receive_the_message(self):
        manager = ConnectionManager()
        mine, theirs = uuid.uuid4(), uuid.uuid4()
        my_socket, their_socket = FakeSocket(), FakeSocket()
        _run(manager.connect(my_socket, mine))
        _run(manager.connect(their_socket, theirs))

        _run(manager.broadcast_to_org(mine, {"secret": True}))

        assert my_socket.sent
        assert their_socket.sent == []

    def test_a_dead_socket_is_dropped_and_does_not_break_the_others(self):
        organization_id = uuid.uuid4()
        manager = ConnectionManager()
        dead, alive = FakeSocket(fail=True), FakeSocket()
        _run(manager.connect(dead, organization_id))
        _run(manager.connect(alive, organization_id))

        delivered = _run(manager.broadcast_to_org(organization_id, {"n": 1}))

        assert delivered == 1
        assert alive.sent
        assert manager.connection_count(organization_id) == 1

    def test_disconnecting_the_last_client_removes_the_group(self):
        organization_id = uuid.uuid4()
        manager = ConnectionManager()
        socket = FakeSocket()
        _run(manager.connect(socket, organization_id))
        manager.disconnect(socket, str(organization_id))

        assert manager.connection_count(organization_id) == 0
        assert manager.active_connections == {}


@requires_db
class TestWorkerHealth:
    def test_no_scheduled_run_ever_is_reported_as_unknown_not_as_broken(self, db):
        """
        A fresh deployment and a dead scheduler produce the same empty table.
        Calling that "broken" would be a claim the data does not support.
        """
        from app.services.worker_health import check

        health = check(db)
        assert health.scheduler_running is None
        assert "new deployment" in health.scheduler_evidence

    def test_a_recent_scheduled_run_is_evidence_the_scheduler_is_alive(self, db):
        from app.models.vulnerability_intel import IntelSyncState
        from app.services.worker_health import check

        db.add(IntelSyncState(
            source="kev",
            last_attempt_at=datetime.now(timezone.utc) - timedelta(hours=2),
        ))
        db.flush()

        health = check(db)
        assert health.scheduler_running is True

    def test_a_long_silence_is_reported_as_a_stopped_scheduler(self, db):
        from app.models.vulnerability_intel import IntelSyncState
        from app.services.worker_health import check

        db.add(IntelSyncState(
            source="kev",
            last_attempt_at=datetime.now(timezone.utc) - timedelta(days=9),
        ))
        db.flush()

        health = check(db)
        assert health.scheduler_running is False
        payload = health.as_dict()
        assert "docker compose up -d beat" in payload["scheduler_remediation"]

    def test_the_broker_password_is_not_returned(self, db, monkeypatch):
        from app.core.config import settings
        from app.services.worker_health import check

        monkeypatch.setattr(
            settings, "REDIS_URL", "redis://someone:hunter2@redis:6379/0"
        )
        payload = check(db).as_dict()
        assert "hunter2" not in payload["broker"]
        assert "redis:6379" in payload["broker"]

    def test_an_unreachable_broker_is_reported_not_raised(self, db, monkeypatch):
        from app.core.config import settings
        from app.services.worker_health import check

        monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:1/0")
        health = check(db)

        assert health.healthy is False
        assert "docker compose up -d worker" in health.as_dict()["remediation"]
