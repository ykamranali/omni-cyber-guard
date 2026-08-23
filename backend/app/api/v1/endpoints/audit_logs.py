"""
Audit log.

Two things were wrong. It was guarded by `get_current_active_user`, so any
authenticated account — a helpdesk technician, a read-only user — could read
the entire organization's audit trail, including who changed what and from
where. `VIEW_AUDIT_LOGS` exists precisely for this and is granted only to
organization administrators, auditors and super administrators.

And it had no filters, which makes an audit log close to unusable: the question
an auditor asks is "what did this person do", not "show me the last fifty
things that happened".
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, time, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import String, desc, func, or_, select
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user, get_db, require_permission
from app.core.rbac import Permission
from app.models.audit_log import AuditLog
from app.models.user import User
from app.reports.audit_pdf import render_audit_log_pdf

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])

MAX_EXPORT_ROWS = 5000


def _filtered_statement(
    organization_id: uuid.UUID,
    *,
    search: str | None,
    action: str | None,
    resource_type: str | None,
    actor_user_id: uuid.UUID | None,
    date_from: date | None,
    date_to: date | None,
):
    statement = (
        select(AuditLog, User.email, User.full_name)
        .outerjoin(User, AuditLog.actor_user_id == User.id)
        .where(AuditLog.organization_id == organization_id)
    )

    if search:
        # One box that matches the things a person actually types: a name, an
        # email, an action, a resource type, an IP, or a record id.
        pattern = f"%{search.strip().lower()}%"
        statement = statement.where(or_(
            func.lower(User.email).like(pattern),
            func.lower(User.full_name).like(pattern),
            func.lower(AuditLog.action).like(pattern),
            func.lower(AuditLog.resource_type).like(pattern),
            func.lower(func.coalesce(AuditLog.resource_id, "")).like(pattern),
            func.lower(func.coalesce(AuditLog.ip_address, "")).like(pattern),
            func.lower(func.cast(AuditLog.metadata_json, String)).like(pattern),
        ))

    if action:
        statement = statement.where(AuditLog.action == action.strip())
    if resource_type:
        statement = statement.where(AuditLog.resource_type == resource_type.strip())
    if actor_user_id:
        statement = statement.where(AuditLog.actor_user_id == actor_user_id)
    if date_from:
        statement = statement.where(
            AuditLog.created_at >= datetime.combine(date_from, time.min, tzinfo=timezone.utc)
        )
    if date_to:
        statement = statement.where(
            AuditLog.created_at <= datetime.combine(date_to, time.max, tzinfo=timezone.utc)
        )

    return statement


def _serialise(log: AuditLog, email: str | None, full_name: str | None) -> dict:
    return {
        "id": str(log.id),
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "ip_address": log.ip_address,
        "created_at": log.created_at.isoformat() if log.created_at else None,
        "actor_user_id": str(log.actor_user_id) if log.actor_user_id else None,
        "actor_email": email,
        "actor_name": full_name,
        # A record whose actor has since been deleted keeps the entry but loses
        # the name. Saying so is better than rendering an empty cell.
        "actor_note": (
            "" if log.actor_user_id else "Performed by the system, or by an account since deleted."
        ),
        "metadata": log.metadata_json or {},
    }


@router.get("")
def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: str | None = Query(default=None, max_length=200),
    action: str | None = Query(default=None, max_length=100),
    resource_type: str | None = Query(default=None, max_length=100),
    actor_user_id: uuid.UUID | None = Query(default=None),
    date_from: date | None = Query(default=None),
    date_to: date | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_AUDIT_LOGS)),
):
    statement = _filtered_statement(
        current_user.organization_id,
        search=search, action=action, resource_type=resource_type,
        actor_user_id=actor_user_id, date_from=date_from, date_to=date_to,
    )

    total = db.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one()

    rows = db.execute(
        statement.order_by(desc(AuditLog.created_at)).offset(skip).limit(limit)
    ).all()

    return {
        "items": [_serialise(log, email, name) for log, email, name in rows],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/filters")
def available_filters(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_AUDIT_LOGS)),
):
    """
    The distinct values present in this organization's log.

    Derived from the data rather than hardcoded, so a filter dropdown can never
    offer a value that returns nothing, and never omit an action that a newly
    added feature started recording.
    """
    actions = db.execute(
        select(AuditLog.action)
        .where(AuditLog.organization_id == current_user.organization_id)
        .distinct().order_by(AuditLog.action)
    ).scalars().all()

    resource_types = db.execute(
        select(AuditLog.resource_type)
        .where(AuditLog.organization_id == current_user.organization_id)
        .distinct().order_by(AuditLog.resource_type)
    ).scalars().all()

    actors = db.execute(
        select(User.id, User.email, User.full_name)
        .join(AuditLog, AuditLog.actor_user_id == User.id)
        .where(AuditLog.organization_id == current_user.organization_id)
        .distinct().order_by(User.email)
    ).all()

    return {
        "actions": list(actions),
        "resource_types": list(resource_types),
        "actors": [
            {"id": str(identifier), "email": email, "full_name": name}
            for identifier, email, name in actors
        ],
    }


@router.get("/export.pdf")
def export_audit_log_pdf(
    search: str | None = Query(default=None, max_length=200),
    action: str | None = Query(default=None, max_length=100),
    resource_type: str | None = Query(default=None, max_length=100),
    actor_user_id: uuid.UUID | None = Query(default=None),
    date_from: date | None = Query(default=None),
    date_to: date | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_AUDIT_LOGS)),
):
    """
    Export the filtered log as a PDF.

    The export applies exactly the filters the screen is showing, and the
    document states them on its first page — an audit export whose scope is not
    recorded on the document itself is not evidence of anything.
    """
    statement = _filtered_statement(
        current_user.organization_id,
        search=search, action=action, resource_type=resource_type,
        actor_user_id=actor_user_id, date_from=date_from, date_to=date_to,
    )

    total = db.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one()

    rows = db.execute(
        statement.order_by(desc(AuditLog.created_at)).limit(MAX_EXPORT_ROWS)
    ).all()

    entries = [_serialise(log, email, name) for log, email, name in rows]

    pdf = render_audit_log_pdf(
        organization_name=current_user.organization.name if current_user.organization else "",
        entries=entries,
        total_matching=total,
        exported_by=current_user.email,
        filters={
            "search": search, "action": action, "resource_type": resource_type,
            "actor_user_id": str(actor_user_id) if actor_user_id else None,
            "date_from": date_from.isoformat() if date_from else None,
            "date_to": date_to.isoformat() if date_to else None,
        },
        row_cap=MAX_EXPORT_ROWS,
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="audit-log-{stamp}.pdf"'
        },
    )
