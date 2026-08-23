"""
Firewall integration API.

The secret is write-only: it goes in encrypted and no response schema ever
returns it, in ciphertext or plaintext. `has_secret` tells the UI whether one
is stored so it can show "configured" without ever handling the value.

`POST /firewall/{id}/test` is what moves an integration to CONNECTED. There is
no way to mark it connected by asserting so — the status reflects a round trip
to the firewall that actually succeeded.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import encrypt_secret
from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.firewall import FirewallIntegration, FirewallStatus, FirewallVendor
from app.models.user import User
from app.services.audit import log_action
from app.services.firewall_enforcement import test_integration
from app.services.integrations.firewall import ADAPTERS, VENDOR_SETUP, FirewallError

router = APIRouter(prefix="/firewall", tags=["Firewall"])

SEVERITIES = ("low", "medium", "high", "critical")


class FirewallCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    vendor: FirewallVendor
    base_url: str = Field(min_length=8, max_length=512)
    api_identity: str = Field(default="", max_length=255)
    api_secret: str = Field(min_length=1, max_length=4096)
    blocklist_object: str = Field(min_length=1, max_length=120)
    verify_tls: bool = True

    @field_validator("base_url")
    @classmethod
    def https_only(cls, value: str) -> str:
        cleaned = value.strip().rstrip("/")
        if not cleaned.startswith(("https://", "http://")):
            raise ValueError("base_url must start with https:// or http://")
        if cleaned.startswith("http://"):
            # Allowed, because plenty of management interfaces sit on a
            # management VLAN with a self-signed certificate — but the operator
            # is told what they are sending in clear.
            pass
        return cleaned


class FirewallUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    base_url: str | None = Field(default=None, max_length=512)
    api_identity: str | None = Field(default=None, max_length=255)
    #: Only sent when the operator is replacing it. Omitted leaves it untouched.
    api_secret: str | None = Field(default=None, min_length=1, max_length=4096)
    blocklist_object: str | None = Field(default=None, min_length=1, max_length=120)
    verify_tls: bool | None = None
    auto_block_enabled: bool | None = None
    auto_block_min_severity: str | None = None
    auto_block_duration_minutes: int | None = Field(default=None, ge=5, le=10080)
    never_block: list[str] | None = None

    @field_validator("auto_block_min_severity")
    @classmethod
    def known_severity(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().lower()
        if cleaned not in SEVERITIES:
            raise ValueError(f"auto_block_min_severity must be one of: {', '.join(SEVERITIES)}")
        return cleaned


def _serialise(integration: FirewallIntegration) -> dict:
    return {
        "id": str(integration.id),
        "name": integration.name,
        "vendor": integration.vendor.value,
        "base_url": integration.base_url,
        "api_identity": integration.api_identity,
        # The secret is never returned, in any form. Its presence is.
        "has_secret": bool(integration.encrypted_secret),
        "blocklist_object": integration.blocklist_object,
        "verify_tls": integration.verify_tls,
        "status": integration.status.value,
        "status_message": integration.status_message,
        "last_checked_at": (
            integration.last_checked_at.isoformat() if integration.last_checked_at else None
        ),
        "last_success_at": (
            integration.last_success_at.isoformat() if integration.last_success_at else None
        ),
        "auto_block_enabled": integration.auto_block_enabled,
        "auto_block_min_severity": integration.auto_block_min_severity,
        "auto_block_duration_minutes": integration.auto_block_duration_minutes,
        "never_block": integration.never_block or [],
        "enforced_count": integration.enforced_count,
        "setup_guidance": VENDOR_SETUP.get(integration.vendor.value, ""),
    }


def _load(db: Session, user: User, integration_id: uuid.UUID) -> FirewallIntegration:
    integration = db.execute(
        select(FirewallIntegration).where(
            FirewallIntegration.id == integration_id,
            FirewallIntegration.organization_id == user.organization_id,
        )
    ).scalar_one_or_none()
    if integration is None:
        raise HTTPException(status_code=404, detail="Firewall integration not found")
    return integration


@router.get("/vendors")
def list_vendors(
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    """Supported firewalls and what each needs, so the form can explain itself."""
    return {
        "vendors": [
            {
                "vendor": vendor,
                "setup_guidance": VENDOR_SETUP.get(vendor, ""),
            }
            for vendor in sorted(ADAPTERS)
        ],
        "note": (
            "The platform adds addresses to a blocklist object you already "
            "control — an alias or address group. It never creates rules or "
            "changes policy, so what a block actually does stays your decision."
        ),
    }


@router.get("")
def list_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    integrations = db.execute(
        select(FirewallIntegration)
        .where(FirewallIntegration.organization_id == current_user.organization_id)
        .order_by(FirewallIntegration.created_at)
    ).scalars().all()
    return {"integrations": [_serialise(item) for item in integrations]}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_integration(
    payload: FirewallCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORG_SETTINGS)),
) -> Any:
    existing = db.execute(
        select(FirewallIntegration).where(
            FirewallIntegration.organization_id == current_user.organization_id,
            FirewallIntegration.name == payload.name,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"'{payload.name}' already exists.")

    integration = FirewallIntegration(
        organization_id=current_user.organization_id,
        name=payload.name,
        vendor=payload.vendor,
        base_url=payload.base_url,
        api_identity=payload.api_identity,
        encrypted_secret=encrypt_secret(payload.api_secret),
        blocklist_object=payload.blocklist_object,
        verify_tls=payload.verify_tls,
        # Not CONNECTED until a test round-trips. Saving a form is not evidence
        # that a firewall is reachable.
        status=FirewallStatus.NOT_CONFIGURED,
        status_message="Saved. Run a connection test to confirm it works.",
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)

    log_action(
        db, "create", "firewall_integration", current_user.organization_id,
        current_user.id, str(integration.id),
        metadata={"vendor": integration.vendor.value, "name": integration.name},
    )
    return _serialise(integration)


@router.patch("/{integration_id}")
def update_integration(
    integration_id: uuid.UUID,
    payload: FirewallUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORG_SETTINGS)),
) -> Any:
    integration = _load(db, current_user, integration_id)
    changes = payload.model_dump(exclude_unset=True)

    secret = changes.pop("api_secret", None)
    if secret:
        integration.encrypted_secret = encrypt_secret(secret)

    enabling_auto = changes.get("auto_block_enabled") is True
    if enabling_auto and integration.status is not FirewallStatus.CONNECTED:
        raise HTTPException(
            status_code=409,
            detail=(
                "Run a successful connection test before enabling automatic "
                "blocking. Turning it on for a firewall that has never answered "
                "would mean the platform believes it is enforcing when it is not."
            ),
        )

    for field, value in changes.items():
        setattr(integration, field, value)

    db.commit()
    db.refresh(integration)

    log_action(
        db, "update", "firewall_integration", current_user.organization_id,
        current_user.id, str(integration.id),
        # The secret is never logged, only the fact that it changed.
        metadata={**changes, "secret_replaced": bool(secret)},
    )
    return _serialise(integration)


@router.post("/{integration_id}/test")
def test_connection(
    integration_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORG_SETTINGS)),
) -> Any:
    """Contact the firewall and record what it said. The only path to CONNECTED."""
    integration = _load(db, current_user, integration_id)
    try:
        result = test_integration(db, integration)
    except FirewallError as exc:
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc))

    db.commit()
    log_action(
        db, "test_connection", "firewall_integration", current_user.organization_id,
        current_user.id, str(integration.id), metadata={"result": result.message},
    )
    return {"connected": True, "message": result.message, **_serialise(integration)}


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(
    integration_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORG_SETTINGS)),
):
    """
    Remove the integration.

    Addresses already pushed to the firewall stay there — this platform did not
    create the rule that references the blocklist object and will not silently
    undo it. Remove them from the blocklist first if that is what you want.
    """
    integration = _load(db, current_user, integration_id)
    name = integration.name
    db.delete(integration)
    db.commit()
    log_action(
        db, "delete", "firewall_integration", current_user.organization_id,
        current_user.id, str(integration_id), metadata={"name": name},
    )
