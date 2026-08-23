"""
Cloud inventory.

The response always carries the integration's state alongside whatever
resources exist, because "no resources" and "no integration" look identical on
a page that only lists rows — and the difference matters enormously. An empty
list with `configured: false` means nothing has been read; an empty list with
`configured: true` means the account genuinely holds nothing.

The previous implementation resolved that ambiguity by writing a fake resource
named "Discovery Failed: No active credentials found for AWS" into the
inventory table so the page had something to show. That row was returned here
as a discovered cloud resource.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.discovery import CloudResource
from app.models.integration import IntegrationKind, IntegrationState
from app.models.user import User
from app.services.audit import log_action
from app.services.integrations import cloud as cloud_integrations
from app.services.integrations.base import AdapterError

router = APIRouter()


class CloudScanRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=64)


def _integration_status(db: Session, organization_id) -> list[dict]:
    """
    One entry per adapter the platform knows about, whether or not it has ever
    run. A provider that has never been attempted still needs to appear, with
    what it would require.
    """
    states = {
        state.provider: state
        for state in db.execute(
            select(IntegrationState).where(
                IntegrationState.organization_id == organization_id,
                IntegrationState.kind == IntegrationKind.CLOUD,
            )
        ).scalars().all()
    }

    entries = []
    for adapter in cloud_integrations.ADAPTERS.values():
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
def get_cloud_resources(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
) -> Any:
    """Cloud resources read from configured providers, plus each integration's state."""
    resources = db.execute(
        select(CloudResource)
        .where(CloudResource.organization_id == current_user.organization_id)
        .order_by(CloudResource.provider, CloudResource.name)
    ).scalars().all()

    integrations = _integration_status(db, current_user.organization_id)
    any_configured = any(entry["configured"] for entry in integrations)

    return {
        "resources": [
            {
                "id": str(resource.id),
                "provider": resource.provider,
                "resource_type": resource.resource_type,
                "resource_id": resource.resource_id,
                "name": resource.name,
                "region": resource.region,
                "status": resource.status,
                "compliance_status": resource.compliance_status,
                "compliance_note": (
                    "Reading the inventory says nothing about compliance. "
                    "Posture assessment is not implemented, so this is UNKNOWN "
                    "rather than a verdict."
                ),
                "last_seen": (
                    resource.updated_at.isoformat() if resource.updated_at else None
                ),
            }
            for resource in resources
        ],
        "integrations": integrations,
        "empty_state_note": (
            ""
            if resources else (
                "No cloud provider is configured, so nothing has been read. "
                "Configure one below to see real inventory."
                if not any_configured else
                "The configured provider returned no resources. That is what "
                "the account holds, not a failure."
            )
        ),
    }


@router.post("/scan")
def run_discovery(
    payload: CloudScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.RUN_SCANS)),
) -> Any:
    """
    Read the configured provider's inventory now.

    Refused up front when the adapter is not configured, so the operator gets
    the reason immediately instead of a queued job that quietly records a
    failure they have to go looking for.
    """
    try:
        adapter = cloud_integrations.get_adapter(payload.provider)
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

    from app.tasks.discovery_tasks import discover_cloud_assets

    try:
        discover_cloud_assets.delay(adapter.provider, str(current_user.organization_id))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=(
                f"Discovery could not be handed to a worker: {exc}. Check that "
                f"the Celery worker and Redis are running."
            ),
        )

    log_action(
        db, "cloud_discovery", "cloud_integration",
        current_user.organization_id, current_user.id, adapter.provider,
    )
    return {"queued": True, "provider": adapter.provider}
