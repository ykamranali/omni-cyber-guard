"""
External attack surface.

Probing a domain means resolving it and opening a TLS connection to a host
someone else owns. That is an active reach-out to a third party, so it is
gated the same way network scanning is: the domain must first be registered as
authorized scope by a named operator, and the probe must be confirmed at
launch.

The endpoint previously accepted any domain string from any authenticated user
and dispatched a live probe against it, with no permission check and no scope
check at all. That is the clearest authorization failure in the codebase: the
platform would connect to any host on the internet that anyone named.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.discovery import AttackSurfaceDomain
from app.models.integration import IntegrationKind, IntegrationState
from app.models.user import User
from app.services.audit import log_action

router = APIRouter()

# Deliberately strict. A hostname is all this accepts: no scheme, no port, no
# path, no address literal. Anything else is a different kind of target and
# should not be smuggled through a domain field.
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class DomainRegistration(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    #: The operator affirming they are authorized to probe this domain.
    authorization_confirmed: bool = False

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, value: str) -> str:
        cleaned = (value or "").strip().lower().rstrip(".")
        if not DOMAIN_PATTERN.match(cleaned):
            raise ValueError(
                "Enter a bare domain name such as example.com — no scheme, "
                "port or path."
            )
        return cleaned


def _serialise(domain: AttackSurfaceDomain, state: IntegrationState | None) -> dict:
    return {
        "id": str(domain.id),
        "domain_name": domain.domain_name,
        "ip_addresses": [
            address for address in (domain.ip_addresses or "").split(",") if address
        ],
        # Empty because the platform performs no WHOIS or RDAP lookup. Shown as
        # unknown rather than filled with a stand-in.
        "registrar": domain.registrar,
        "registrar_note": (
            "" if domain.registrar
            else "Not looked up — this platform performs no WHOIS/RDAP query."
        ),
        "is_active": domain.is_active,
        "cert_issuer": domain.cert_issuer,
        "cert_valid_from": (
            domain.cert_valid_from.isoformat() if domain.cert_valid_from else None
        ),
        "cert_valid_to": (
            domain.cert_valid_to.isoformat() if domain.cert_valid_to else None
        ),
        "cert_expires_in_days": _days_until(domain.cert_valid_to),
        "authorized_at": (
            domain.authorized_at.isoformat() if domain.authorized_at else None
        ),
        "last_checked_at": (
            domain.last_checked_at.isoformat() if domain.last_checked_at else None
        ),
        # Null last_checked_at is "never probed", which is a different statement
        # from "probed and found nothing".
        "probe_status": state.status.value if state else "never_run",
        "probe_message": state.message if state else "This domain has not been probed yet.",
    }


def _days_until(moment: datetime | None) -> int | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment - datetime.now(timezone.utc)).days


@router.get("/")
def get_attack_surface(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> Any:
    """Domains registered as in scope, and what the last probe of each observed."""
    domains = db.execute(
        select(AttackSurfaceDomain)
        .where(AttackSurfaceDomain.organization_id == current_user.organization_id)
        .order_by(AttackSurfaceDomain.domain_name)
    ).scalars().all()

    states = {
        state.provider: state
        for state in db.execute(
            select(IntegrationState).where(
                IntegrationState.organization_id == current_user.organization_id,
                IntegrationState.kind == IntegrationKind.ATTACK_SURFACE,
            )
        ).scalars().all()
    }

    return {
        "domains": [
            _serialise(domain, states.get(domain.domain_name)) for domain in domains
        ],
        "empty_state_note": (
            "No domains are registered. Add the domains you are authorized to "
            "assess; the platform does not discover them on its own, because "
            "guessing which domains belong to you and probing them would not "
            "be authorized testing."
        ) if not domains else "",
    }


@router.post("/domains", status_code=status.HTTP_201_CREATED)
def register_domain(
    payload: DomainRegistration,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
) -> Any:
    """Register a domain as authorized scope. This is what makes probing it legal."""
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail=(
                "Confirm that you are authorized to assess this domain before "
                "registering it."
            ),
        )

    existing = db.execute(
        select(AttackSurfaceDomain).where(
            AttackSurfaceDomain.organization_id == current_user.organization_id,
            AttackSurfaceDomain.domain_name == payload.domain,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409, detail=f"{payload.domain} is already registered."
        )

    domain = AttackSurfaceDomain(
        organization_id=current_user.organization_id,
        domain_name=payload.domain,
        authorized_by_user_id=current_user.id,
        authorized_at=datetime.now(timezone.utc),
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)

    log_action(
        db, "authorize_domain", "attack_surface_domain",
        current_user.organization_id, current_user.id, str(domain.id),
        metadata={"domain": domain.domain_name},
    )
    return _serialise(domain, None)


@router.delete("/domains/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_domain(
    domain_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    """Withdraw a domain from scope. Removing it revokes the authorization to probe it."""
    domain = db.execute(
        select(AttackSurfaceDomain).where(
            AttackSurfaceDomain.id == domain_id,
            AttackSurfaceDomain.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if domain is None:
        raise HTTPException(status_code=404, detail="Domain not found")

    name = domain.domain_name
    db.delete(domain)
    db.commit()
    log_action(
        db, "revoke_domain_authorization", "attack_surface_domain",
        current_user.organization_id, current_user.id, str(domain_id),
        metadata={"domain": name},
    )


@router.post("/domains/{domain_id}/probe")
def probe_domain(
    domain_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
) -> Any:
    """
    Probe one registered domain now.

    The domain must already be registered — the row is the authorization — so
    this takes an id, not a free-text name. That is the difference between
    "check something I told you I own" and "connect to whatever I type".
    """
    domain = db.execute(
        select(AttackSurfaceDomain).where(
            AttackSurfaceDomain.id == domain_id,
            AttackSurfaceDomain.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if domain is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "That domain is not registered as authorized scope for this "
                "organization."
            ),
        )

    from app.tasks.discovery_tasks import discover_attack_surface

    try:
        discover_attack_surface.delay(
            domain.domain_name, str(current_user.organization_id)
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=(
                f"The probe could not be handed to a worker: {exc}. Check that "
                f"the Celery worker and Redis are running."
            ),
        )

    log_action(
        db, "probe_domain", "attack_surface_domain",
        current_user.organization_id, current_user.id, str(domain.id),
        metadata={"domain": domain.domain_name},
    )
    return {
        "queued": True,
        "domain": domain.domain_name,
        "note": (
            "The probe resolves the name and reads the certificate the TLS "
            "endpoint presents. Results appear against the domain when it "
            "completes; nothing is written if it fails."
        ),
    }
