from typing import List, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.services.threat_monitor import add_blocked_ip, remove_blocked_ip, blocked_ips

router = APIRouter(prefix="/infrastructure", tags=["Infrastructure"])

# In-memory store for metadata about blocked IPs (in a real app, this would be a DB table)
blocked_ip_metadata: Dict[str, dict] = {}

class BlockIPRequest(BaseModel):
    ip: str
    reason: str = "Manual Block"

class BlockedIPResponse(BaseModel):
    ip: str
    reason: str
    blocked_at: datetime

@router.get("/blocked-ips", response_model=List[BlockedIPResponse])
def get_blocked_ips(
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS))
):
    result = []
    for ip in blocked_ips:
        meta = blocked_ip_metadata.get(ip, {"reason": "Unknown", "blocked_at": datetime.now(timezone.utc)})
        result.append({
            "ip": ip,
            "reason": meta.get("reason"),
            "blocked_at": meta.get("blocked_at")
        })
    return sorted(result, key=lambda x: x["blocked_at"], reverse=True)

@router.post("/blocked-ips", status_code=201)
def block_ip(
    payload: BlockIPRequest,
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS))
):
    add_blocked_ip(payload.ip)
    blocked_ip_metadata[payload.ip] = {
        "reason": payload.reason,
        "blocked_at": datetime.now(timezone.utc)
    }
    return {"status": "success", "message": f"IP {payload.ip} is now actively blocked via TCP RST injection."}

@router.delete("/blocked-ips/{ip}")
def unblock_ip(
    ip: str,
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS))
):
    remove_blocked_ip(ip)
    if ip in blocked_ip_metadata:
        del blocked_ip_metadata[ip]
    return {"status": "success"}
