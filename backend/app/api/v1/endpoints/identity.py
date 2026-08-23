"""
Identity inventory.

Same shape as the cloud endpoint and for the same reason: an empty list means
nothing without knowing whether a directory was ever read.

Two fields here are nullable on purpose. `mfa_enabled` is null when the
directory's user listing does not report factor enrolment — recording False
would assert that MFA is off, which is a security claim the API response does
not support, and it is exactly the kind of claim someone would act on. Same for
`privilege_level`: empty means the directory did not say, not "ordinary user".
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.discovery import IdentityProfile
from app.models.integration import IntegrationKind, IntegrationState
from app.models.user import User
from app.services.audit import log_action
from app.services.integrations import identity as identity_integrations
from app.services.integrations.base import AdapterError

router = APIRouter()


class IdentityScanRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=64)


def _integration_status(db: Session, organization_id) -> list[dict]:
    states = {
        state.provider: state
        for state in db.execute(
            select(IntegrationState).where(
                IntegrationState.organization_id == organization_id,
                IntegrationState.kind == IntegrationKind.IDENTITY,
            )
        ).scalars().all()
    }

    entries = []
    for adapter in identity_integrations.ADAPTERS.values():
        description = adapter.describe()
        state = states.get(adapter.provider)
        entries.append({
            **description.as_dict(),
            "status": state.status.value if state else (
                "not_configured" if not description.configured else "never_run"
            ),
            "message": state.message if state else "",
            "last_attempt_at": (
                state.last_attempt_at.isoformat()
                if state and state.last_attempt_at else None
            ),
            "last_success_at": (
                state.last_success_at.isoformat()
                if state and state.last_success_at else None
            ),
            "records_discovered": state.records_discovered if state else 0,
        })
    return entries


@router.get("/")
def get_identities(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> Any:
    profiles = db.execute(
        select(IdentityProfile)
        .where(IdentityProfile.organization_id == current_user.organization_id)
        .order_by(IdentityProfile.email)
    ).scalars().all()

    integrations = _integration_status(db, current_user.organization_id)
    any_configured = any(entry["configured"] for entry in integrations)

    mfa_unknown = sum(1 for profile in profiles if profile.mfa_enabled is None)

    return {
        "identities": [
            {
                "id": str(profile.id),
                "email": profile.email,
                "full_name": profile.full_name,
                "provider": profile.provider,
                "is_active": profile.is_active,
                # Three states, not two.
                "mfa_enabled": profile.mfa_enabled,
                "mfa_note": (
                    "The directory listing does not report factor enrolment, "
                    "so this is unknown — not 'no MFA'."
                    if profile.mfa_enabled is None else ""
                ),
                "last_login": (
                    profile.last_login.isoformat() if profile.last_login else None
                ),
                "privilege_level": profile.privilege_level or None,
                "last_seen": (
                    profile.updated_at.isoformat() if profile.updated_at else None
                ),
            }
            for profile in profiles
        ],
        "integrations": integrations,
        "summary": {
            "total": len(profiles),
            "inactive": sum(1 for profile in profiles if not profile.is_active),
            "mfa_enabled": sum(1 for profile in profiles if profile.mfa_enabled is True),
            "mfa_disabled": sum(1 for profile in profiles if profile.mfa_enabled is False),
            "mfa_unknown": mfa_unknown,
        },
        "summary_note": (
            f"{mfa_unknown} account(s) have unknown MFA status. They are counted "
            f"separately and are not included in the disabled figure."
            if mfa_unknown else ""
        ),
        "empty_state_note": (
            ""
            if profiles else (
                "No identity provider is configured, so no accounts have been "
                "read. Configure one below to see real directory data."
                if not any_configured else
                "The configured directory returned no accounts."
            )
        ),
    }


@router.post("/scan")
def run_discovery(
    payload: IdentityScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
) -> Any:
    try:
        adapter = identity_integrations.get_adapter(payload.provider)
    except AdapterError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    description = adapter.describe()
    if not description.configured:
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    f"The {adapter.provider} integration is not configured, so "
                    f"there is nothing to read."
                ),
                **description.as_dict(),
            },
        )

    from app.tasks.discovery_tasks import discover_identity

    try:
        discover_identity.delay(adapter.provider, str(current_user.organization_id))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=(
                f"Discovery could not be handed to a worker: {exc}. Check that "
                f"the Celery worker and Redis are running."
            ),
        )

    log_action(
        db, "identity_discovery", "identity_integration",
        current_user.organization_id, current_user.id, adapter.provider,
    )
    return {"queued": True, "provider": adapter.provider}
