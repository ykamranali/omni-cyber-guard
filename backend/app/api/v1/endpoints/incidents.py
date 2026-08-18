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
        
    # Mock AI Generation Logic based on incident title and severity
    title = incident.title.lower()
    
    if "sql" in title or "injection" in title:
        playbook = f"""# AI Remediation Playbook: SQL Injection
        
## Overview
The scanner identified a potential SQL Injection vulnerability in the application. This allows an attacker to manipulate backend database queries.

## Immediate Containment
1. Identify the vulnerable endpoint and parameter from the evidence.
2. Implement a Web Application Firewall (WAF) rule to block common SQLi payloads (e.g., `' OR '1'='1`).

## Permanent Remediation
To fix this vulnerability permanently, update the source code to use parameterized queries or Prepared Statements.

### ❌ Vulnerable Code Example (Python/FastAPI)
```python
query = f"SELECT * FROM users WHERE username = '{{username}}'"
db.execute(query)
```

### ✅ Secure Code Example (Using SQLAlchemy)
```python
from sqlalchemy import text
query = text("SELECT * FROM users WHERE username = :username")
db.execute(query, {{"username": username}})
```

## Validation
After applying the patch, re-run the **OWASP ZAP** scanner via the Scan Center to confirm the vulnerability is resolved.
"""
    elif "cve" in title or "windows" in title or "openssh" in title:
        playbook = f"""# AI Remediation Playbook: Infrastructure Vulnerability
        
## Overview
A known vulnerability ({incident.title}) was detected on the infrastructure. Exploitation could lead to unauthorized access or remote code execution.

## Immediate Containment
1. Isolate the affected host(s) from the public internet if they do not need to be exposed.
2. Monitor EDR/SIEM logs for any signs of active exploitation attempts targeting this service.

## Permanent Remediation
Apply the latest security patches provided by the vendor.

### Remediation Steps (Linux/Debian)
```bash
# Update package lists
sudo apt-get update

# Upgrade the vulnerable package (e.g. OpenSSH)
sudo apt-get install --only-upgrade openssh-server

# Restart the service to apply changes
sudo systemctl restart sshd
```

### Remediation Steps (Windows)
```powershell
# Install the KB security update via PowerShell
Install-WindowsUpdate -AcceptAll -AutoReboot
```

## Validation
Run an **OpenVAS** or **Nmap** scan to ensure the service banner reflects the patched version.
"""
    else:
        playbook = f"""# AI Remediation Playbook: {incident.title}
        
## Overview
This incident requires investigation. It was flagged with a severity of **{incident.severity.upper()}**.

## Containment Strategy
1. Verify the authenticity of the finding (False Positive check).
2. If legitimate, restrict access to the affected asset to prevent lateral movement.

## Remediation Steps
1. Review the application or system logs for anomalies.
2. Update the affected software to the latest stable release.
3. If this is a misconfiguration, enforce secure defaults (e.g., disable default credentials, close unused ports).

## Post-Incident
Update the asset registry and document the resolution notes in this Incident ticket.
"""

    incident.ai_playbook = playbook
    db.commit()
    db.refresh(incident)
    
    log_action(db, "generate_playbook", "incident", current_user.organization_id, current_user.id, str(incident.id))
    return incident
