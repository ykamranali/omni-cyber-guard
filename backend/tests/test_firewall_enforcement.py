"""
Enforcement means a firewall accepted it.

The rule under test is narrow and load-bearing: `status = "enforced"` is only
ever written when the vendor's API returned success. If the push fails the
entry stays `recommended` and carries the reason — because an operator reading
"enforced" stops looking, and a block that silently did not happen is worse
than no block at all.

The automatic-blocking gates are tested individually because each one is a
limit on the platform cutting off network access by itself.
"""
from __future__ import annotations

import uuid

import pytest

from tests.conftest import requires_db

from app.core.crypto import encrypt_secret
from app.models.blocked_ip import BlockedIp
from app.models.firewall import FirewallIntegration, FirewallStatus, FirewallVendor
from app.services import firewall_enforcement
from app.services.firewall_enforcement import (
    EnforcementError, auto_block, enforce, is_exempt, withdraw,
)
from app.services.integrations.firewall import FirewallError, FirewallResult


class StubAdapter:
    """Stands in for a real firewall. Records what it was asked to do."""

    vendor = "opnsense"

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.blocked: list[str] = []
        self.unblocked: list[str] = []

    def test_connection(self, config):
        if self.fail:
            raise FirewallError("401 Unauthorized: the API key was rejected.")
        return FirewallResult(True, "Connected. The alias holds 0 address(es).")

    def block(self, config, ip_address, reason):
        if self.fail:
            raise FirewallError("The firewall refused the request.")
        self.blocked.append(ip_address)
        return FirewallResult(True, f"{ip_address} added to alias.")

    def unblock(self, config, ip_address):
        if self.fail:
            raise FirewallError("The firewall refused the removal.")
        self.unblocked.append(ip_address)
        return FirewallResult(True, f"{ip_address} removed from alias.")

    def list_blocked(self, config):
        return list(self.blocked)


@pytest.fixture
def adapter(monkeypatch):
    stub = StubAdapter()
    monkeypatch.setattr(firewall_enforcement, "get_adapter", lambda _vendor: stub)
    return stub


@pytest.fixture
def failing_adapter(monkeypatch):
    stub = StubAdapter(fail=True)
    monkeypatch.setattr(firewall_enforcement, "get_adapter", lambda _vendor: stub)
    return stub


def _integration(db, organization, **overrides) -> FirewallIntegration:
    values = dict(
        organization_id=organization.id,
        name=f"Edge {uuid.uuid4().hex[:6]}",
        vendor=FirewallVendor.OPNSENSE,
        base_url="https://firewall.internal",
        api_identity="key",
        encrypted_secret=encrypt_secret("secret"),
        blocklist_object="ocg_blocklist",
        status=FirewallStatus.CONNECTED,
        auto_block_enabled=False,
        auto_block_min_severity="critical",
        never_block=[],
        auto_block_duration_minutes=60,
    )
    values.update(overrides)
    record = FirewallIntegration(**values)
    db.add(record)
    db.flush()
    return record


def _entry(db, organization, ip="203.0.113.9") -> BlockedIp:
    record = BlockedIp(
        organization_id=organization.id,
        ip_address=ip,
        reason="Repeated authentication failures",
        status="recommended",
    )
    db.add(record)
    db.flush()
    return record


@requires_db
class TestManualEnforcement:
    def test_a_successful_push_marks_the_entry_enforced(
        self, db, organization, adapter
    ):
        integration = _integration(db, organization)
        entry = _entry(db, organization)

        outcome = enforce(db, entry=entry, integration=integration, actor_user_id=None)

        assert outcome.enforced is True
        assert entry.status == "enforced"
        assert adapter.blocked == ["203.0.113.9"]
        assert integration.enforced_count == 1

    def test_a_failed_push_leaves_the_entry_unenforced(
        self, db, organization, failing_adapter
    ):
        """The whole point: no silent claim that a block is in place."""
        integration = _integration(db, organization)
        entry = _entry(db, organization)

        with pytest.raises(EnforcementError, match="did not accept"):
            enforce(db, entry=entry, integration=integration, actor_user_id=None)

        assert entry.status == "recommended"
        assert integration.enforced_count == 0

    def test_a_failure_is_written_to_the_audit_log(
        self, db, organization, failing_adapter
    ):
        from app.models.audit_log import AuditLog

        integration = _integration(db, organization)
        entry = _entry(db, organization)
        with pytest.raises(EnforcementError):
            enforce(db, entry=entry, integration=integration, actor_user_id=None)

        actions = {row.action for row in db.query(AuditLog).all()}
        assert "firewall_block_failed" in actions

    def test_withdrawing_returns_the_entry_to_recommended(
        self, db, organization, adapter
    ):
        integration = _integration(db, organization)
        entry = _entry(db, organization)
        enforce(db, entry=entry, integration=integration, actor_user_id=None)

        withdraw(db, entry=entry, integration=integration, actor_user_id=None)

        assert entry.status == "recommended"
        assert adapter.unblocked == ["203.0.113.9"]

    def test_a_failed_withdrawal_does_not_claim_the_block_is_gone(
        self, db, organization, monkeypatch
    ):
        stub = StubAdapter()
        monkeypatch.setattr(firewall_enforcement, "get_adapter", lambda _v: stub)
        integration = _integration(db, organization)
        entry = _entry(db, organization)
        enforce(db, entry=entry, integration=integration, actor_user_id=None)

        stub.fail = True
        with pytest.raises(EnforcementError, match="still blocked there"):
            withdraw(db, entry=entry, integration=integration, actor_user_id=None)

        assert entry.status == "enforced"


@requires_db
class TestExemptions:
    def test_loopback_is_never_blocked(self, db, organization):
        integration = _integration(db, organization)
        assert "never blocked" in is_exempt(integration, "127.0.0.1")

    def test_link_local_is_never_blocked(self, db, organization):
        integration = _integration(db, organization)
        assert is_exempt(integration, "169.254.10.5")

    def test_the_never_block_list_is_honoured(self, db, organization):
        integration = _integration(db, organization, never_block=["192.168.1.0/24"])
        assert "never-block list" in is_exempt(integration, "192.168.1.1")

    def test_an_address_outside_the_list_is_not_exempt(self, db, organization):
        integration = _integration(db, organization, never_block=["192.168.1.0/24"])
        assert is_exempt(integration, "203.0.113.9") == ""

    def test_a_malformed_never_block_entry_exempts_nothing(self, db, organization):
        integration = _integration(db, organization, never_block=["not-a-range"])
        assert is_exempt(integration, "203.0.113.9") == ""

    def test_an_exempt_address_cannot_be_enforced(self, db, organization, adapter):
        integration = _integration(db, organization, never_block=["10.0.0.0/8"])
        entry = _entry(db, organization, ip="10.1.2.3")

        with pytest.raises(EnforcementError, match="never-block list"):
            enforce(db, entry=entry, integration=integration, actor_user_id=None)
        assert adapter.blocked == []


@requires_db
class TestAutomaticBlocking:
    def test_it_does_nothing_when_no_firewall_is_connected(self, db, organization):
        outcome = auto_block(
            db, organization_id=organization.id, ip_address="203.0.113.9",
            severity="critical", evidence="port scan",
        )
        assert outcome.enforced is False
        assert "No connected firewall" in outcome.message
        assert db.query(BlockedIp).count() == 0

    def test_it_is_off_by_default(self, db, organization, adapter):
        _integration(db, organization, auto_block_enabled=False)

        outcome = auto_block(
            db, organization_id=organization.id, ip_address="203.0.113.9",
            severity="critical", evidence="port scan",
        )
        assert outcome.enforced is False
        assert "switched off" in outcome.message
        assert adapter.blocked == []

    def test_an_event_below_the_threshold_does_not_trigger_one(
        self, db, organization, adapter
    ):
        _integration(
            db, organization, auto_block_enabled=True, auto_block_min_severity="critical"
        )

        outcome = auto_block(
            db, organization_id=organization.id, ip_address="203.0.113.9",
            severity="medium", evidence="single failed login",
        )
        assert outcome.enforced is False
        assert "below the automatic-block threshold" in outcome.message
        assert adapter.blocked == []

    def test_a_qualifying_event_is_blocked_and_expires(
        self, db, organization, adapter
    ):
        _integration(
            db, organization, auto_block_enabled=True,
            auto_block_min_severity="high", auto_block_duration_minutes=30,
        )

        outcome = auto_block(
            db, organization_id=organization.id, ip_address="203.0.113.9",
            severity="critical", evidence="1000 connections in 10s",
        )

        assert outcome.enforced is True
        assert adapter.blocked == ["203.0.113.9"]
        entry = db.query(BlockedIp).one()
        assert entry.status == "enforced"
        # Every automatic block carries its own expiry, so a wrong one heals.
        assert "Expires" in entry.reason
        assert "critical event" in entry.reason

    def test_the_never_block_list_beats_automatic_blocking(
        self, db, organization, adapter
    ):
        _integration(
            db, organization, auto_block_enabled=True,
            auto_block_min_severity="low", never_block=["203.0.113.0/24"],
        )

        outcome = auto_block(
            db, organization_id=organization.id, ip_address="203.0.113.9",
            severity="critical", evidence="port scan",
        )
        assert outcome.enforced is False
        assert adapter.blocked == []

    def test_a_firewall_failure_records_the_decision_but_not_enforcement(
        self, db, organization, failing_adapter
    ):
        _integration(db, organization, auto_block_enabled=True, auto_block_min_severity="low")

        outcome = auto_block(
            db, organization_id=organization.id, ip_address="203.0.113.9",
            severity="critical", evidence="port scan",
        )

        assert outcome.enforced is False
        entry = db.query(BlockedIp).one()
        # The decision is visible; the enforcement did not happen and says so.
        assert entry.status == "recommended"

    def test_another_organizations_firewall_is_not_used(
        self, db, organization, second_organization, adapter
    ):
        _integration(db, second_organization, auto_block_enabled=True,
                     auto_block_min_severity="low")

        outcome = auto_block(
            db, organization_id=organization.id, ip_address="203.0.113.9",
            severity="critical", evidence="port scan",
        )
        assert outcome.enforced is False
        assert "No connected firewall" in outcome.message


@requires_db
class TestConnectionState:
    def test_a_successful_test_marks_it_connected(self, db, organization, adapter):
        integration = _integration(db, organization, status=FirewallStatus.NOT_CONFIGURED)

        firewall_enforcement.test_integration(db, integration)

        assert integration.status is FirewallStatus.CONNECTED
        assert integration.last_success_at is not None

    def test_a_failed_test_marks_it_errored_and_does_not_advance_last_success(
        self, db, organization, failing_adapter
    ):
        integration = _integration(db, organization, status=FirewallStatus.NOT_CONFIGURED)

        with pytest.raises(FirewallError):
            firewall_enforcement.test_integration(db, integration)

        assert integration.status is FirewallStatus.ERROR
        assert integration.last_success_at is None
        assert "401" in integration.status_message
