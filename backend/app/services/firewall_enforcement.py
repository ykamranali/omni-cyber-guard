"""
Turning a block decision into an enforced one.

The rule this module exists to hold: `status = "enforced"` means a firewall
accepted the address. Not that the platform thinks it should be blocked, not
that a rule was generated for someone to paste — that the vendor's API returned
success. If the push fails, the entry stays `recommended` and carries the
reason, because an operator reading "enforced" will stop looking.

Automatic blocking is bounded here rather than in the caller:

* it is off unless an operator turned it on,
* only events at or above a configured severity qualify,
* the never-block list is checked before anything else and cannot be bypassed,
* every automatic block gets an expiry, so a wrong one heals on its own,
* and the whole decision is written to the audit log with the evidence that
  triggered it.

A platform that can cut off network access on its own judgement needs those to
be structural.
"""
from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_secret
from app.models.blocked_ip import BlockedIp
from app.models.firewall import FirewallIntegration, FirewallStatus
from app.services.audit import log_action
from app.services.integrations.firewall import (
    FirewallConfig, FirewallError, FirewallResult, get_adapter,
)

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Addresses that are never blocked, automatically or otherwise, regardless of
# configuration. Blocking loopback or a link-local address cannot help and can
# take the platform off the network.
ALWAYS_EXEMPT = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
)


class EnforcementError(RuntimeError):
    """The block could not be enforced. The reason is the message."""


@dataclass
class EnforcementOutcome:
    enforced: bool
    message: str
    integration_name: str = ""


def _config_for(integration: FirewallIntegration) -> FirewallConfig:
    return FirewallConfig(
        base_url=integration.base_url,
        identity=integration.api_identity,
        # The only place a firewall secret is decrypted.
        secret=decrypt_secret(integration.encrypted_secret),
        blocklist_object=integration.blocklist_object,
        verify_tls=integration.verify_tls,
    )


def is_exempt(integration: FirewallIntegration, ip_address: str) -> str:
    """Return the reason this address must not be blocked, or an empty string."""
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return f"{ip_address} is not a valid IP address."

    for network in ALWAYS_EXEMPT:
        if address.version == network.version and address in network:
            return (
                f"{ip_address} is in {network}, which is never blocked — doing so "
                f"cannot help and can take this platform off the network."
            )

    for entry in integration.never_block or []:
        try:
            network = ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return (
                f"{ip_address} is inside {entry}, which this integration's "
                f"never-block list protects."
            )
    return ""


def active_integration(db: Session, organization_id: uuid.UUID) -> FirewallIntegration | None:
    return db.execute(
        select(FirewallIntegration).where(
            FirewallIntegration.organization_id == organization_id,
            FirewallIntegration.status == FirewallStatus.CONNECTED,
        ).order_by(FirewallIntegration.created_at)
    ).scalars().first()


def test_integration(db: Session, integration: FirewallIntegration) -> FirewallResult:
    """Contact the firewall and record what came back."""
    adapter = get_adapter(integration.vendor.value)
    integration.last_checked_at = datetime.now(timezone.utc)
    try:
        result = adapter.test_connection(_config_for(integration))
    except FirewallError as exc:
        integration.status = FirewallStatus.ERROR
        integration.status_message = str(exc)
        db.add(integration)
        db.flush()
        raise

    integration.status = FirewallStatus.CONNECTED
    integration.status_message = result.message
    integration.last_success_at = integration.last_checked_at
    db.add(integration)
    db.flush()
    return result


def enforce(
    db: Session,
    *,
    entry: BlockedIp,
    integration: FirewallIntegration,
    actor_user_id: uuid.UUID | None,
) -> EnforcementOutcome:
    """
    Push one block to the firewall.

    The entry is only marked enforced if the vendor accepted it.
    """
    exempt = is_exempt(integration, entry.ip_address)
    if exempt:
        raise EnforcementError(exempt)

    adapter = get_adapter(integration.vendor.value)
    try:
        result = adapter.block(_config_for(integration), entry.ip_address, entry.reason)
    except FirewallError as exc:
        entry.status = "recommended"
        entry.reason = (entry.reason or "").strip()
        db.add(entry)
        log_action(
            db, "firewall_block_failed", "blocked_ip", entry.organization_id,
            actor_user_id, str(entry.id),
            metadata={"ip": entry.ip_address, "firewall": integration.name, "error": str(exc)},
        )
        raise EnforcementError(
            f"The firewall did not accept the block, so it has not been applied: {exc}"
        ) from exc

    entry.status = "enforced"
    db.add(entry)
    integration.enforced_count += 1
    integration.last_success_at = datetime.now(timezone.utc)
    db.add(integration)

    log_action(
        db, "firewall_block_enforced", "blocked_ip", entry.organization_id,
        actor_user_id, str(entry.id),
        metadata={
            "ip": entry.ip_address,
            "firewall": integration.name,
            "vendor": integration.vendor.value,
            "vendor_response": result.message,
        },
    )
    db.flush()
    return EnforcementOutcome(True, result.message, integration.name)


def withdraw(
    db: Session,
    *,
    entry: BlockedIp,
    integration: FirewallIntegration,
    actor_user_id: uuid.UUID | None,
) -> EnforcementOutcome:
    """Remove an enforced block from the firewall."""
    adapter = get_adapter(integration.vendor.value)
    try:
        result = adapter.unblock(_config_for(integration), entry.ip_address)
    except FirewallError as exc:
        raise EnforcementError(
            f"The firewall did not accept the removal, so {entry.ip_address} is "
            f"still blocked there: {exc}"
        ) from exc

    entry.status = "recommended"
    db.add(entry)
    log_action(
        db, "firewall_block_withdrawn", "blocked_ip", entry.organization_id,
        actor_user_id, str(entry.id),
        metadata={"ip": entry.ip_address, "firewall": integration.name},
    )
    db.flush()
    return EnforcementOutcome(False, result.message, integration.name)


def auto_block(
    db: Session,
    *,
    organization_id: uuid.UUID,
    ip_address: str,
    severity: str,
    evidence: str,
) -> EnforcementOutcome:
    """
    Consider an automatic block, and carry it out only if every gate passes.

    Returns an outcome describing what happened either way. A refusal is not an
    error — most events should not result in a block, and the reason is worth
    recording.
    """
    integration = active_integration(db, organization_id)
    if integration is None:
        return EnforcementOutcome(False, "No connected firewall to enforce with.")

    if not integration.auto_block_enabled:
        return EnforcementOutcome(
            False, f"Automatic blocking is switched off for {integration.name}."
        )

    threshold = SEVERITY_RANK.get(integration.auto_block_min_severity.lower(), 4)
    if SEVERITY_RANK.get(str(severity).lower(), 0) < threshold:
        return EnforcementOutcome(
            False,
            f"Severity '{severity}' is below the automatic-block threshold "
            f"('{integration.auto_block_min_severity}').",
        )

    exempt = is_exempt(integration, ip_address)
    if exempt:
        log_action(
            db, "firewall_auto_block_refused", "blocked_ip", organization_id, None,
            None, metadata={"ip": ip_address, "reason": exempt},
        )
        return EnforcementOutcome(False, exempt)

    existing = db.execute(
        select(BlockedIp).where(
            BlockedIp.organization_id == organization_id,
            BlockedIp.ip_address == ip_address,
        )
    ).scalar_one_or_none()
    if existing is not None and existing.status == "enforced":
        return EnforcementOutcome(True, f"{ip_address} is already enforced.")

    expires = datetime.now(timezone.utc) + timedelta(
        minutes=max(1, integration.auto_block_duration_minutes)
    )
    reason = (
        f"Automatic block: {severity} event. {evidence}"
        f" Expires {expires.isoformat(timespec='minutes')}."
    )[:500]

    entry = existing or BlockedIp(
        organization_id=organization_id, ip_address=ip_address
    )
    entry.reason = reason
    entry.status = "recommended"
    db.add(entry)
    db.flush()

    try:
        outcome = enforce(db, entry=entry, integration=integration, actor_user_id=None)
    except EnforcementError as exc:
        # The decision stands and is visible; the enforcement did not happen and
        # says so. These must not be conflated.
        return EnforcementOutcome(False, str(exc), integration.name)

    log_action(
        db, "firewall_auto_block", "blocked_ip", organization_id, None, str(entry.id),
        metadata={
            "ip": ip_address, "severity": severity, "evidence": evidence[:500],
            "expires_at": expires.isoformat(),
        },
    )
    return outcome
