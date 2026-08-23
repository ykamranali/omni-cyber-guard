"""
Infrastructure protection.

Records IP addresses an operator has decided to block, together with the
justification and who made the call. These records are *recommendations with
an audit trail* — Omni Cyber Guard does not interrupt network traffic itself.

The previous implementation kept the blocklist in a module-level Python set
and forged spoofed TCP RST packets to tear down connections. That approach
had three problems: the list was lost on every restart, it was invisible to
the worker process that actually inspected traffic (so in a Docker deployment
it did nothing at all), and packet forging is an active-disruption technique
that this platform does not perform.
"""
import ipaddress
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.blocked_ip import BlockedIp
from app.models.user import User
from app.services.audit import log_action
from app.services.threat_monitor import monitor_status

router = APIRouter(prefix="/infrastructure", tags=["Infrastructure"])

ALLOWED_STATUSES = ("recommended", "enforced", "expired")


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual block"
    #: Push the address to a connected firewall as well as recording it. The
    #: entry is only marked enforced if the firewall accepts it.
    enforce: bool = False

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError as exc:
            raise ValueError(f"'{v}' is not a valid IP address.") from exc


class BlockedIPStatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def valid_status(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ALLOWED_STATUSES:
            raise ValueError(f"status must be one of: {', '.join(ALLOWED_STATUSES)}")
        return v


class BlockedIPResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str
    reason: str
    status: str
    created_at: datetime


class EnforcementInfo(BaseModel):
    """Tells the UI, unambiguously, what the platform does and does not do."""
    platform_enforces_blocks: bool = False
    explanation: str = (
        "Omni Cyber Guard records block decisions and their justification. It does "
        "not drop or reset traffic itself. Apply the rule at your firewall, edge "
        "ACL or host firewall, then mark the entry as enforced."
    )
    passive_monitor: dict


@router.get("/enforcement", response_model=EnforcementInfo)
def enforcement_info(
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    return EnforcementInfo(passive_monitor=monitor_status())


@router.get("/blocked-ips", response_model=list[BlockedIPResponse])
def list_blocked_ips(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    return (
        db.query(BlockedIp)
        .filter(BlockedIp.organization_id == current_user.organization_id)
        .order_by(BlockedIp.created_at.desc())
        .all()
    )


@router.post("/blocked-ips", response_model=BlockedIPResponse, status_code=201)
def block_ip(
    payload: BlockIPRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    existing = (
        db.query(BlockedIp)
        .filter(
            BlockedIp.organization_id == current_user.organization_id,
            BlockedIp.ip_address == payload.ip,
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail=f"{payload.ip} is already on the blocklist.")

    entry = BlockedIp(
        organization_id=current_user.organization_id,
        created_by_user_id=current_user.id,
        ip_address=payload.ip,
        reason=payload.reason,
        # Always starts as a recorded decision. It becomes "enforced" only if a
        # firewall accepts it below — never because the request asked for it.
        status="recommended",
    )
    db.add(entry)
    db.flush()

    log_action(
        db, "block_ip", "blocked_ip", current_user.organization_id, current_user.id,
        str(entry.id), metadata={"ip": entry.ip_address, "reason": entry.reason},
    )

    if payload.enforce:
        from app.services.firewall_enforcement import (
            EnforcementError, active_integration, enforce as push_block,
        )

        integration = active_integration(db, current_user.organization_id)
        if integration is None:
            db.commit()
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{entry.ip_address} has been recorded, but no connected "
                    f"firewall is available to enforce it. Connect one under "
                    f"Firewall integrations, or apply the rule yourself."
                ),
            )
        try:
            push_block(
                db, entry=entry, integration=integration,
                actor_user_id=current_user.id,
            )
        except EnforcementError as exc:
            db.commit()
            raise HTTPException(status_code=502, detail=str(exc))

    db.commit()
    db.refresh(entry)
    return entry


@router.patch("/blocked-ips/{entry_id}", response_model=BlockedIPResponse)
def update_blocked_ip_status(
    entry_id: uuid.UUID,
    payload: BlockedIPStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    entry = (
        db.query(BlockedIp)
        .filter(BlockedIp.id == entry_id, BlockedIp.organization_id == current_user.organization_id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Blocklist entry not found")

    entry.status = payload.status
    db.commit()
    db.refresh(entry)

    log_action(
        db, "update_blocked_ip", "blocked_ip", current_user.organization_id,
        current_user.id, str(entry.id), metadata={"status": entry.status},
    )
    return entry


@router.delete("/blocked-ips/{entry_id}", status_code=204)
def unblock_ip(
    entry_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    entry = (
        db.query(BlockedIp)
        .filter(BlockedIp.id == entry_id, BlockedIp.organization_id == current_user.organization_id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Blocklist entry not found")

    ip = entry.ip_address
    db.delete(entry)
    db.commit()
    log_action(
        db, "unblock_ip", "blocked_ip", current_user.organization_id,
        current_user.id, str(entry_id), metadata={"ip": ip},
    )
