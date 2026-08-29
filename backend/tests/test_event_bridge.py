"""
The worker-to-browser event bridge.

The WebSocket layer was half-built: connections lived in a dictionary inside
the API process, and every event worth pushing happened in the Celery worker,
which could not reach that dictionary. The frontend handled eleven event types
and ten of them could never arrive. This covers the piece that closes the gap,
and in particular the two properties that decide whether it can be trusted:

  * publishing never raises, so a notification failure cannot rewrite the
    record of the work it was announcing;
  * a malformed or unaddressed event is discarded rather than delivered to the
    wrong tenant.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from app.services import events


class FakeRedis:
    """Records publishes; can be told to fail."""

    def __init__(self, *, fail: bool = False) -> None:
        self.published: list[tuple[str, str]] = []
        self.fail = fail

    def publish(self, channel: str, payload: str) -> int:
        if self.fail:
            raise ConnectionError("broker unreachable")
        self.published.append((channel, payload))
        return 1


class FakeManager:
    """Stands in for ConnectionManager."""

    def __init__(self, *, delivered_per_call: int = 2, raises: bool = False) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.delivered_per_call = delivered_per_call
        self.raises = raises

    async def broadcast_to_org(self, organization_id, message):
        if self.raises:
            raise RuntimeError("socket exploded")
        self.calls.append((organization_id, message))
        return self.delivered_per_call


@pytest.fixture(autouse=True)
def _reset():
    events.reset_publisher()
    yield
    events.reset_publisher()


class TestPublish:
    def test_the_envelope_carries_type_tenant_and_time(self, monkeypatch):
        fake = FakeRedis()
        monkeypatch.setattr(events, "_get_publisher", lambda: fake)
        org = uuid.uuid4()

        assert events.publish_event(org, "scan_completed", message="Done.", hosts=4) is True

        channel, raw = fake.published[0]
        assert channel == events.EVENT_CHANNEL
        envelope = json.loads(raw)
        assert envelope["type"] == "scan_completed"
        assert envelope["organization_id"] == str(org)
        assert envelope["message"] == "Done."
        assert envelope["hosts"] == 4
        assert envelope["at"]

    def test_a_broker_failure_is_reported_not_raised(self, monkeypatch):
        """
        The scan already finished. A notification that cannot be sent must not
        turn a completed scan into a failed one.
        """
        monkeypatch.setattr(events, "_get_publisher", lambda: FakeRedis(fail=True))

        assert events.publish_event(uuid.uuid4(), "scan_completed") is False

    def test_a_broker_failure_drops_the_cached_client(self, monkeypatch):
        """A client that failed may be permanently broken; the next publish
        should build a fresh one rather than reuse it."""
        events._publisher = object()
        monkeypatch.setattr(events, "_get_publisher", lambda: FakeRedis(fail=True))

        events.publish_event(uuid.uuid4(), "scan_failed")
        assert events._publisher is None

    def test_an_unknown_event_type_still_publishes_but_warns(self, monkeypatch):
        # The warning is captured off the module's own logger rather than via
        # caplog: another test in the suite reconfigures logging, and a
        # root-handler assertion passes alone and fails in a full run.
        fake = FakeRedis()
        warnings: list[str] = []
        monkeypatch.setattr(events, "_get_publisher", lambda: fake)
        monkeypatch.setattr(
            events.logger, "warning",
            lambda msg, *args, **kwargs: warnings.append(msg % args if args else msg),
        )

        assert events.publish_event(uuid.uuid4(), "not_a_real_event") is True

        assert fake.published, "an unrecognised type must still reach the browser"
        assert any("unknown event type" in line for line in warnings)

    def test_uuids_in_the_payload_are_serialisable(self, monkeypatch):
        """json.dumps cannot encode a UUID; the publisher must not blow up on
        an id that a caller passed through unconverted."""
        fake = FakeRedis()
        monkeypatch.setattr(events, "_get_publisher", lambda: fake)

        assert events.publish_event(uuid.uuid4(), "scan_started", asset_id=uuid.uuid4()) is True
        assert json.loads(fake.published[0][1])["asset_id"]


class TestBridgeDispatch:
    def _bridge(self, manager):
        return events.EventBridge(manager, redis_url="redis://unused")

    def test_an_event_is_delivered_to_its_own_organization(self):
        manager = FakeManager()
        bridge = self._bridge(manager)
        org = str(uuid.uuid4())

        asyncio.run(bridge._dispatch(json.dumps(
            {"type": "scan_completed", "organization_id": org, "message": "Done."}
        )))

        assert len(manager.calls) == 1
        delivered_org, payload = manager.calls[0]
        assert delivered_org == org
        assert payload["type"] == "scan_completed"

    def test_the_tenant_is_stripped_before_delivery(self):
        """The routing key is not part of the message; leaving it in the
        payload sends the browser a field it has no use for."""
        manager = FakeManager()
        bridge = self._bridge(manager)

        asyncio.run(bridge._dispatch(json.dumps(
            {"type": "intel_synced", "organization_id": str(uuid.uuid4())}
        )))

        assert "organization_id" not in manager.calls[0][1]

    def test_an_event_with_no_organization_is_discarded(self):
        """Rather than guessed at. An unaddressed event has no correct
        recipient, and delivering it to everyone would be a tenant leak."""
        manager = FakeManager()
        bridge = self._bridge(manager)

        asyncio.run(bridge._dispatch(json.dumps({"type": "scan_completed"})))

        assert manager.calls == []

    def test_malformed_json_is_discarded_without_raising(self):
        manager = FakeManager()
        bridge = self._bridge(manager)

        asyncio.run(bridge._dispatch("{not json"))
        asyncio.run(bridge._dispatch(None))
        asyncio.run(bridge._dispatch(""))

        assert manager.calls == []

    def test_a_delivery_failure_does_not_kill_the_subscriber(self):
        """
        If _dispatch propagated, the bridge would fall into its reconnect loop
        over one bad socket and the application would go quietly back to not
        being live.
        """
        manager = FakeManager(raises=True)
        bridge = self._bridge(manager)

        asyncio.run(bridge._dispatch(json.dumps(
            {"type": "scan_completed", "organization_id": str(uuid.uuid4())}
        )))

        assert bridge.stats["received"] == 1
        assert bridge.stats["delivered"] == 0

    def test_stats_separate_received_from_delivered(self):
        """Nobody watching is not an error, and the numbers have to be able to
        say so."""
        manager = FakeManager(delivered_per_call=3)
        bridge = self._bridge(manager)
        org = str(uuid.uuid4())

        for _ in range(2):
            asyncio.run(bridge._dispatch(json.dumps(
                {"type": "scan_progress", "organization_id": org}
            )))

        assert bridge.stats == {"received": 2, "delivered": 6}


class TestBridgeLifecycle:
    def test_start_is_idempotent_and_stop_is_safe_when_never_started(self):
        async def scenario():
            manager = FakeManager()
            bridge = events.EventBridge(manager, redis_url="redis://127.0.0.1:1/0")

            await bridge.stop()          # never started — must not raise

            bridge.start()
            first = bridge._task
            bridge.start()               # second call must not spawn another
            assert bridge._task is first

            await bridge.stop()
            assert bridge._task is None

        asyncio.run(scenario())
