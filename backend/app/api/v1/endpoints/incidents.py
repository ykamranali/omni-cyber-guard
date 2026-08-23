import uuid
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.incident import Incident
from app.models.user import User
from app.schemas.incident import IncidentOut, IncidentCreate, IncidentUpdate
from app.services.audit import log_action

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("", response_model=List[IncidentOut])
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    query = db.query(Incident).filter(Incident.organization_id == current_user.organization_id)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if search:
        pattern = f"%{search.strip().lower()}%"
        query = query.filter(
            func.lower(Incident.title).like(pattern)
            | func.lower(func.coalesce(Incident.description, "")).like(pattern)
        )

    return query.order_by(Incident.created_at.desc()).all()

@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    incident = Incident(organization_id=current_user.organization_id, **payload.model_dump())
    db.add(incident)
    db.commit()
    db.refresh(incident)
    log_action(db, "create", "incident", current_user.organization_id, current_user.id, str(incident.id))
    return incident

@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    incident = db.query(Incident).filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: uuid.UUID,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    incident = db.query(Incident).filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(incident, field, value)
        
    if payload.status == "resolved" and not incident.resolved_at:
        incident.resolved_at = datetime.now(timezone.utc)
        
    db.commit()
    db.refresh(incident)
    log_action(db, "update", "incident", current_user.organization_id, current_user.id, str(incident.id))
    return incident

@router.post("/{incident_id}/playbook", response_model=IncidentOut)
def generate_ai_playbook(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    incident = db.query(Incident).filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    if incident.ai_playbook:
        return incident # Already generated
        
    # Generate the playbook through the LLM service.
    #
    # A failure here used to be written into `incident.ai_playbook` as the text
    # "Error generating playbook: <exception>" and returned with a 200. The
    # exception string became the incident's response playbook, sitting in the
    # field a responder reads under pressure. Now a failure is a failure: the
    # field is left untouched and the caller gets a status code that says so.
    try:
        from app.services.llm import generate_playbook_content
        playbook = generate_playbook_content(
            title=incident.title,
            description=incident.description or "",
            severity=incident.severity.value,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=(
                f"The playbook could not be generated: {exc}. The incident is "
                f"unchanged."
            ),
        )

    if not playbook or not playbook.strip():
        raise HTTPException(
            status_code=503,
            detail="The playbook service returned nothing. The incident is unchanged.",
        )

    incident.ai_playbook = playbook
    db.commit()
    db.refresh(incident)

    log_action(
        db, "generate_playbook", "incident", current_user.organization_id,
        current_user.id, str(incident.id),
    )
    return incident
