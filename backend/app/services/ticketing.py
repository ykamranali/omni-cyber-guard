from typing import Optional
from sqlalchemy.orm import Session
import requests

from app.models.integration import TicketIntegration, IntegrationProvider
from app.models.remediation import RemediationTask
from app.models.credential import CredentialProfile


def sync_remediation_task_to_ticket(
    db: Session,
    task: RemediationTask,
    integration_id: str
) -> Optional[str]:
    """
    Syncs a remediation task to an external ticketing system (e.g. Jira/ServiceNow)
    and returns the external ticket ID.
    """
    integration = db.query(TicketIntegration).filter(TicketIntegration.id == integration_id).first()
    if not integration or not integration.is_active:
        return None

    # Retrieve credentials via the vault (pseudo-code using plain text for now, 
    # in reality this uses the Fernet decryption service from Phase 2)
    api_token = "dummy_token"  
    if integration.credential_id:
        cred = db.query(CredentialProfile).filter(CredentialProfile.id == integration.credential_id).first()
        if cred:
            # We would decrypt the credential secret here
            api_token = "decrypted_secret"

    ticket_id = None

    if integration.provider == IntegrationProvider.JIRA.value:
        ticket_id = _create_jira_issue(
            base_url=integration.base_url,
            username=integration.username,
            api_token=api_token,
            project_key=integration.project_key,
            summary=f"Remediation: {task.title}",
            description=task.description or "No description provided."
        )
    elif integration.provider == IntegrationProvider.SERVICENOW.value:
        ticket_id = _create_servicenow_incident(
            base_url=integration.base_url,
            username=integration.username,
            password=api_token,
            short_description=f"Remediation: {task.title}",
            description=task.description or "No description provided."
        )

    if ticket_id:
        # Assuming RemediationTask gets an external_ticket_id field or similar
        # For now, we just return the ID
        pass

    return ticket_id


def _create_jira_issue(base_url: str, username: str, api_token: str, project_key: str, summary: str, description: str) -> str:
    """Creates a Jira issue and returns the issue key."""
    # Simulation of external HTTP call
    print(f"Creating Jira issue in project {project_key} on {base_url}...")
    return f"{project_key}-1001"


def _create_servicenow_incident(base_url: str, username: str, password: str, short_description: str, description: str) -> str:
    """Creates a ServiceNow incident and returns the INC number."""
    # Simulation of external HTTP call
    print(f"Creating ServiceNow incident on {base_url}...")
    return "INC0001234"
