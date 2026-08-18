"""
Real system health checks — not a hardcoded "All systems operational"
string. Each component is actually probed.
"""
import redis
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps import get_db, get_current_active_user
from app.models.user import User
from app.schemas.system import SystemStatusOut, ComponentStatus, NetworkInfoOut
from fastapi import Request
import socket

router = APIRouter(prefix="/system", tags=["System"])


@router.get("/status", response_model=SystemStatusOut)
def system_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    components: list[ComponentStatus] = []

    try:
        db.execute(text("SELECT 1"))
        components.append(ComponentStatus(name="Database", status="operational"))
    except Exception as exc:  # noqa: BLE001
        components.append(ComponentStatus(name="Database", status="down", detail=str(exc)[:200]))

    try:
        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=2)
        client.ping()
        components.append(ComponentStatus(name="Background Jobs (Redis)", status="operational"))
    except Exception as exc:  # noqa: BLE001
        components.append(ComponentStatus(name="Background Jobs (Redis)", status="down", detail=str(exc)[:200]))

    from app.services.network_scanner import nmap_available
    components.append(ComponentStatus(
        name="Network Scan Engine",
        status="operational" if nmap_available() else "degraded",
        detail="" if nmap_available() else "nmap binary not found in this environment",
    ))

    overall = "operational" if all(c.status == "operational" for c in components) else (
        "down" if any(c.status == "down" for c in components) else "degraded"
    )
    return SystemStatusOut(overall_status=overall, components=components)

@router.get("/network-info", response_model=NetworkInfoOut)
def get_network_info(request: Request, current_user: User = Depends(get_current_active_user)):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    
    return NetworkInfoOut(
        client_ip=request.client.host if request.client else "unknown",
        server_local_ip=local_ip
    )

