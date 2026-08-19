import uuid
from typing import List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
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
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    query = db.query(Incident).filter(Incident.organization_id == current_user.organization_id)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
        
    return query.order_by(Incident.created_at.desc()).all()

@router.post("", response_model=IncidentOut, status_code=201)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)), # Use highest permission for incident management for now
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
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
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
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
):
    incident = db.query(Incident).filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    if incident.ai_playbook:
        return incident # Already generated
        
    # Generate dynamic playbook using the LLM service
    try:
        from app.services.llm import generate_playbook_content
        playbook = generate_playbook_content(
            title=incident.title,
            description=incident.description or "",
            severity=incident.severity.value
        )
    except Exception as e:
        playbook = f"Error generating playbook: {str(e)}"

    incident.ai_playbook = playbook
    db.commit()
    db.refresh(incident)
    
    log_action(db, "generate_playbook", "incident", current_user.organization_id, current_user.id, str(incident.id))
    return incident
