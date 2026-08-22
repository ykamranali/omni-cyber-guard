from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.deps import get_db, get_current_active_user, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])

@router.get("")
def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_AUDIT_LOGS))
):
    query = db.query(AuditLog, User.email).outerjoin(User, AuditLog.actor_user_id == User.id)\
        .filter(AuditLog.organization_id == current_user.organization_id)
    
    total = query.count()
    results = query.order_by(desc(AuditLog.created_at)).offset(skip).limit(limit).all()
    
    return {
        "items": [
            {
                "id": str(log.id),
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "ip_address": log.ip_address,
                "created_at": log.created_at.isoformat(),
                "actor_user_id": str(log.actor_user_id) if log.actor_user_id else None,
                "actor_email": email,
                "metadata": log.metadata_json
            }
            for log, email in results
        ],
        "total": total,
        "skip": skip,
        "limit": limit
    }
