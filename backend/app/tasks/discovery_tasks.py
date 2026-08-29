"""
External discovery.

Three tasks, one rule between them: a discovery run records what it actually
observed, and when it cannot observe anything it records *that* — as a state
against the integration, never as a row in the inventory.

The cloud and identity tasks previously did the opposite. Finding no
credentials, they inserted a `CloudResource` whose name was the error message
and an `IdentityProfile` whose email address was `admin_integration_failed@...`.
Both were then returned by their endpoints as discovered inventory. The
integration state table exists so that failure has somewhere honest to go.
"""
from __future__ import annotations

import logging
import socket
import ssl
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.tenancy import set_tenant
from app.models.discovery import AttackSurfaceDomain, CloudResource, IdentityProfile
from app.models.integration import IntegrationKind, IntegrationState, IntegrationStatus
from app.services.events import publish_event
from app.services.integrations import cloud as cloud_integrations
from app.services.integrations import identity as identity_integrations
from app.services.integrations.base import AdapterError

logger = logging.getLogger(__name__)

TLS_CONNECT_TIMEOUT_SECONDS = 5


def _record_state(
    db,
    *,
    organization_id: uuid.UUID,
    kind: IntegrationKind,
    provider: str,
    status: IntegrationStatus,
    message: str,
    missing: list[str] | None = None,
    records_discovered: int = 0,
) -> IntegrationState:
    """
    Upsert the integration's state.

    `last_success_at` only moves forward on an actual success, so a broken
    integration keeps showing when it last genuinely worked rather than
    appearing to have run fine a moment ago.
    """
    state = db.execute(
        select(IntegrationState).where(
            IntegrationState.organization_id == organization_id,
            IntegrationState.kind == kind,
            IntegrationState.provider == provider,
        )
    ).scalar_one_or_none()

    if state is None:
        state = IntegrationState(
            organization_id=organization_id, kind=kind, provider=provider
        )
        db.add(state)

    now = datetime.now(timezone.utc)
    state.status = status
    state.message = message
    state.missing_configuration = missing or []
    state.last_attempt_at = now
    state.records_discovered = records_discovered
    if status is IntegrationStatus.CONNECTED:
        state.last_success_at = now

    # Every discovery outcome passes through here, so this is the one place
    # that needs to announce it. The event carries the status rather than
    # implying success: a browser refreshing on "discovery finished" must be
    # able to render "not configured" as readily as a list of instances.
    publish_event(
        organization_id, "discovery_completed",
        message=message,
        kind=kind.value if hasattr(kind, "value") else str(kind),
        provider=provider,
        status=status.value if hasattr(status, "value") else str(status),
        records_discovered=records_discovered,
    )
    return state


def _session_for(organization_id: uuid.UUID):
    db = SessionLocal()
    set_tenant(db, organization_id)
    return db


# --------------------------------------------------------------------------
# External attack surface
# --------------------------------------------------------------------------

@celery_app.task(name="discovery_tasks.discover_attack_surface")
def discover_attack_surface(domain: str, organization_id: str) -> dict:
    """
    Resolve a domain and read the certificate its TLS endpoint presents.

    Both of those are real observations. Everything else about a domain that
    the record can hold — the registrar in particular — requires a WHOIS or
    RDAP lookup this platform does not perform, and is left empty rather than
    filled with a stand-in. The field previously read "Enumerated (Live)",
    which is not a registrar.

    The domain must already be registered as in-scope by an operator. See
    `app/api/v1/endpoints/attack_surface.py`: probing a host is an active
    reach-out to a third party and needs authorization, not just a name.
    """
    org_uuid = uuid.UUID(organization_id)
    db = _session_for(org_uuid)
    observations: list[str] = []

    try:
        record = db.execute(
            select(AttackSurfaceDomain).where(
                AttackSurfaceDomain.organization_id == org_uuid,
                AttackSurfaceDomain.domain_name == domain,
            )
        ).scalar_one_or_none()

        if record is None:
            # Not an error the operator caused mid-flight so much as a race:
            # the authorization row is created before the task is dispatched.
            message = (
                f"{domain} is not registered as an authorized scope for this "
                f"organization, so it was not probed."
            )
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.ATTACK_SURFACE,
                provider=domain, status=IntegrationStatus.ERROR, message=message,
            )
            db.commit()
            return {"succeeded": False, "message": message}

        ip_addresses: list[str] = []
        try:
            addr_info = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
            ip_addresses = sorted({info[4][0] for info in addr_info})
            observations.append(f"resolved to {len(ip_addresses)} address(es)")
        except socket.gaierror as exc:
            observations.append(f"DNS resolution failed ({exc})")

        cert_issuer = ""
        valid_from = None
        valid_to = None
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (domain, 443), timeout=TLS_CONNECT_TIMEOUT_SECONDS
            ) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls:
                    certificate = tls.getpeercert() or {}
                    for issuer_tuple in certificate.get("issuer", ()):
                        for key, value in issuer_tuple:
                            if key == "organizationName":
                                cert_issuer = value
                                break
                    if certificate.get("notBefore"):
                        valid_from = datetime.strptime(
                            certificate["notBefore"], "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                    if certificate.get("notAfter"):
                        valid_to = datetime.strptime(
                            certificate["notAfter"], "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
            observations.append("read the presented certificate")
        except Exception as exc:  # noqa: BLE001 — every TLS failure is reportable
            observations.append(f"TLS certificate could not be read ({exc})")

        record.ip_addresses = ",".join(ip_addresses)
        # Overwritten only when something was actually read, so a failed probe
        # does not erase the result of a successful earlier one.
        if cert_issuer:
            record.cert_issuer = cert_issuer
        if valid_from:
            record.cert_valid_from = valid_from
        if valid_to:
            record.cert_valid_to = valid_to
        record.last_checked_at = datetime.now(timezone.utc)
        db.add(record)

        succeeded = bool(ip_addresses) or bool(cert_issuer)
        _record_state(
            db, organization_id=org_uuid, kind=IntegrationKind.ATTACK_SURFACE,
            provider=domain,
            status=IntegrationStatus.CONNECTED if succeeded else IntegrationStatus.ERROR,
            message="; ".join(observations),
            records_discovered=len(ip_addresses),
        )
        db.commit()
        return {"succeeded": succeeded, "message": "; ".join(observations)}

    except Exception as exc:  # noqa: BLE001
        logger.exception("Attack surface discovery failed for %s", domain)
        db.rollback()
        _record_state(
            db, organization_id=org_uuid, kind=IntegrationKind.ATTACK_SURFACE,
            provider=domain, status=IntegrationStatus.ERROR,
            message=f"The probe did not complete: {exc}",
        )
        db.commit()
        return {"succeeded": False, "message": str(exc)}
    finally:
        db.close()


# --------------------------------------------------------------------------
# Cloud posture
# --------------------------------------------------------------------------

@celery_app.task(name="discovery_tasks.discover_cloud_assets")
def discover_cloud_assets(provider: str, organization_id: str) -> dict:
    """
    Read cloud inventory through a configured provider adapter.

    If the adapter is not configured, or the attempt fails, the only thing
    written is the integration's state. `cloud_resources` is left exactly as it
    was.
    """
    org_uuid = uuid.UUID(organization_id)
    db = _session_for(org_uuid)

    try:
        try:
            adapter = cloud_integrations.get_adapter(provider)
        except AdapterError as exc:
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.CLOUD,
                provider=provider, status=IntegrationStatus.ERROR, message=str(exc),
            )
            db.commit()
            return {"succeeded": False, "message": str(exc)}

        description = adapter.describe()
        if not description.configured:
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.CLOUD,
                provider=adapter.provider, status=IntegrationStatus.NOT_CONFIGURED,
                message=description.how_to_enable,
                missing=description.missing,
            )
            db.commit()
            return {"succeeded": False, "message": "not configured"}

        try:
            result = adapter.discover()
        except AdapterError as exc:
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.CLOUD,
                provider=adapter.provider, status=IntegrationStatus.ERROR,
                message=str(exc),
            )
            db.commit()
            return {"succeeded": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Cloud discovery failed for %s", provider)
            db.rollback()
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.CLOUD,
                provider=adapter.provider, status=IntegrationStatus.ERROR,
                message=f"The provider API call did not complete: {exc}",
            )
            db.commit()
            return {"succeeded": False, "message": str(exc)}

        written = _upsert_cloud_resources(db, org_uuid, adapter.provider, result.records)
        _record_state(
            db, organization_id=org_uuid, kind=IntegrationKind.CLOUD,
            provider=adapter.provider, status=IntegrationStatus.CONNECTED,
            message=result.message, records_discovered=written,
        )
        db.commit()
        return {"succeeded": True, "records": written, "message": result.message}
    finally:
        db.close()


def _upsert_cloud_resources(db, organization_id, provider, records) -> int:
    written = 0
    for entry in records:
        resource_id = str(entry.get("resource_id") or "").strip()
        if not resource_id:
            # A record with no provider-side identity cannot be deduplicated
            # and cannot be traced back. Skipped rather than given one.
            continue
        existing = db.execute(
            select(CloudResource).where(
                CloudResource.organization_id == organization_id,
                CloudResource.provider == provider,
                CloudResource.resource_id == resource_id,
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = CloudResource(
                organization_id=organization_id,
                provider=provider,
                resource_id=resource_id,
            )
            db.add(existing)
        existing.resource_type = str(entry.get("resource_type") or "")[:100]
        existing.name = str(entry.get("name") or resource_id)[:255]
        existing.region = str(entry.get("region") or "")[:100]
        existing.status = str(entry.get("status") or "")[:50]
        # Posture assessment is a separate capability. Reading an inventory
        # says nothing about whether a resource is compliant, so the field
        # stays UNKNOWN rather than defaulting to a verdict.
        existing.compliance_status = "UNKNOWN"
        written += 1
    return written


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

@celery_app.task(name="discovery_tasks.discover_identity")
def discover_identity(provider: str, organization_id: str) -> dict:
    """Read directory accounts through a configured identity adapter."""
    org_uuid = uuid.UUID(organization_id)
    db = _session_for(org_uuid)

    try:
        try:
            adapter = identity_integrations.get_adapter(provider)
        except AdapterError as exc:
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.IDENTITY,
                provider=provider, status=IntegrationStatus.ERROR, message=str(exc),
            )
            db.commit()
            return {"succeeded": False, "message": str(exc)}

        description = adapter.describe()
        if not description.configured:
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.IDENTITY,
                provider=adapter.provider, status=IntegrationStatus.NOT_CONFIGURED,
                message=description.how_to_enable, missing=description.missing,
            )
            db.commit()
            return {"succeeded": False, "message": "not configured"}

        try:
            result = adapter.discover()
        except AdapterError as exc:
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.IDENTITY,
                provider=adapter.provider, status=IntegrationStatus.ERROR,
                message=str(exc),
            )
            db.commit()
            return {"succeeded": False, "message": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("Identity discovery failed for %s", provider)
            db.rollback()
            _record_state(
                db, organization_id=org_uuid, kind=IntegrationKind.IDENTITY,
                provider=adapter.provider, status=IntegrationStatus.ERROR,
                message=f"The directory API call did not complete: {exc}",
            )
            db.commit()
            return {"succeeded": False, "message": str(exc)}

        written = _upsert_identities(db, org_uuid, adapter.provider, result.records)
        _record_state(
            db, organization_id=org_uuid, kind=IntegrationKind.IDENTITY,
            provider=adapter.provider, status=IntegrationStatus.CONNECTED,
            message=result.message, records_discovered=written,
        )
        db.commit()
        return {"succeeded": True, "records": written, "message": result.message}
    finally:
        db.close()


def _upsert_identities(db, organization_id, provider, records) -> int:
    written = 0
    for entry in records:
        email = str(entry.get("email") or "").strip().lower()
        if not email:
            continue
        existing = db.execute(
            select(IdentityProfile).where(
                IdentityProfile.organization_id == organization_id,
                IdentityProfile.provider == provider,
                IdentityProfile.email == email,
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = IdentityProfile(
                organization_id=organization_id, provider=provider, email=email
            )
            db.add(existing)
        existing.full_name = str(entry.get("full_name") or "")[:255]
        existing.is_active = bool(entry.get("is_active", True))
        # None means the directory listing does not carry it. Recording False
        # would assert that MFA is off, which is a security claim the response
        # does not support.
        existing.mfa_enabled = entry.get("mfa_enabled")
        existing.privilege_level = str(entry.get("privilege_level") or "")[:50]
        written += 1
    return written
