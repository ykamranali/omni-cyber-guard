"""
Confirmation-gated actions.

The agent's retrieval tools cannot write. When it concludes that something
should be done it records a proposal here, and nothing happens until a human
who holds the required permission confirms it. That is the whole design: the
model proposes in words, the platform describes the proposal in its own words,
and a person decides.

Three properties are deliberate:

* **The effect summary is not written by the model.** It is generated from the
  validated parameters by the action definition below, so what the operator
  reads is what the executor will do — not the model's description of it.
* **Validation runs twice.** Once when the proposal is recorded, so an
  impossible action is never offered, and again at confirmation, because the
  world may have changed in between. A finding closed since the proposal was
  made cannot be acted on.
* **Permission is checked against the confirming human**, not against whoever
  was chatting. Proposing costs nothing; confirming is the privileged step.

Risk acceptance is intentionally absent. It suppresses a finding for a period a
person must own, and no part of that decision belongs to a model, even behind a
confirmation.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import Permission
from app.models.agent import AgentActionProposal, ProposalStatus
from app.models.finding import CLOSED_STATUSES, Finding
from app.models.organization import Organization
from app.models.remediation import RemediationStatus, RemediationTask, TERMINAL_STATUSES
from app.models.user import User
from app.services import remediation_engine
from app.services.audit import log_action


class ActionError(ValueError):
    """The proposal cannot be made or cannot be executed as described."""


@dataclass(frozen=True)
class ValidatedAction:
    parameters: dict
    effect_summary: str


@dataclass(frozen=True)
class ActionDefinition:
    action_type: str
    description: str
    required_permission: Permission
    parameters: dict
    validate: Callable[[Session, uuid.UUID, dict], ValidatedAction]
    execute: Callable[[Session, AgentActionProposal, User], dict]


# --------------------------------------------------------------------------
# create_remediation_task
# --------------------------------------------------------------------------

def _validate_create_task(db: Session, organization_id: uuid.UUID, params: dict) -> ValidatedAction:
    raw = params.get("finding_id")
    try:
        finding_id = uuid.UUID(str(raw))
    except (TypeError, ValueError):
        raise ActionError(f"finding_id must be a UUID, received {raw!r}")

    finding = db.execute(
        select(Finding).where(
            Finding.id == finding_id, Finding.organization_id == organization_id
        )
    ).scalar_one_or_none()
    if finding is None:
        raise ActionError("No finding with that identifier exists in this organization.")
    if finding.status in CLOSED_STATUSES:
        raise ActionError(
            f"That finding is already {finding.status.value.replace('_', ' ')}; "
            f"there is nothing to remediate."
        )

    existing = db.execute(
        select(RemediationTask).where(
            RemediationTask.finding_id == finding.id,
            RemediationTask.status.notin_(list(TERMINAL_STATUSES)),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ActionError(
            f"An open remediation task already exists for that finding "
            f"({existing.status.value.replace('_', ' ')})."
        )

    return ValidatedAction(
        parameters={"finding_id": str(finding.id)},
        effect_summary=(
            f"Open a remediation task for the {finding.severity.value} finding "
            f"\"{finding.title}\". The due date is set from your organization's SLA "
            f"policy for that severity, and the finding moves from open to "
            f"acknowledged. Nothing about the finding's severity or status as a "
            f"security issue changes, and it is not marked resolved."
        ),
    )


def _execute_create_task(db: Session, proposal: AgentActionProposal, actor: User) -> dict:
    validated = _validate_create_task(db, proposal.organization_id, proposal.parameters)
    finding = db.execute(
        select(Finding).where(Finding.id == uuid.UUID(validated.parameters["finding_id"]))
    ).scalar_one()
    organization = db.execute(
        select(Organization).where(Organization.id == finding.organization_id)
    ).scalar_one()
    task = remediation_engine.create_task(
        db, finding=finding, organization=organization, created_by_user_id=actor.id,
    )
    return {
        "remediation_task_id": str(task.id),
        "due_date": task.due_date.isoformat() if task.due_date else None,
        "priority": task.priority.value,
    }


# --------------------------------------------------------------------------
# assign_remediation_task
# --------------------------------------------------------------------------

def _validate_assign_task(db: Session, organization_id: uuid.UUID, params: dict) -> ValidatedAction:
    try:
        task_id = uuid.UUID(str(params.get("task_id")))
        assignee_id = uuid.UUID(str(params.get("assignee_user_id")))
    except (TypeError, ValueError):
        raise ActionError("task_id and assignee_user_id must both be UUIDs.")

    task = db.execute(
        select(RemediationTask).where(
            RemediationTask.id == task_id,
            RemediationTask.organization_id == organization_id,
        )
    ).scalar_one_or_none()
    if task is None:
        raise ActionError("No remediation task with that identifier exists here.")
    if task.status in TERMINAL_STATUSES:
        raise ActionError(f"That task is {task.status.value} and cannot be reassigned.")

    assignee = db.execute(
        select(User).where(
            User.id == assignee_id, User.organization_id == organization_id
        )
    ).scalar_one_or_none()
    if assignee is None:
        raise ActionError("No user with that identifier belongs to this organization.")
    if not assignee.is_active:
        raise ActionError(f"{assignee.email} is not an active account.")

    return ValidatedAction(
        parameters={"task_id": str(task.id), "assignee_user_id": str(assignee.id)},
        effect_summary=(
            f"Assign the remediation task \"{task.title}\" to {assignee.email}. "
            f"They become responsible for the fix; the task is not marked done."
        ),
    )


def _execute_assign_task(db: Session, proposal: AgentActionProposal, actor: User) -> dict:
    validated = _validate_assign_task(db, proposal.organization_id, proposal.parameters)
    task = db.execute(
        select(RemediationTask).where(
            RemediationTask.id == uuid.UUID(validated.parameters["task_id"])
        )
    ).scalar_one()
    remediation_engine.assign_task(
        db, task=task,
        user_id=uuid.UUID(validated.parameters["assignee_user_id"]),
        actor_user_id=actor.id,
    )
    return {"remediation_task_id": str(task.id), "status": task.status.value}


ACTIONS: tuple[ActionDefinition, ...] = (
    ActionDefinition(
        action_type="create_remediation_task",
        description=(
            "Propose opening a remediation task for a finding. Requires a human to "
            "confirm before anything is created."
        ),
        required_permission=Permission.MANAGE_FINDINGS,
        parameters={
            "type": "object",
            "properties": {
                "finding_id": {
                    "type": "string",
                    "description": "The finding to open remediation work against.",
                },
            },
            "required": ["finding_id"],
            "additionalProperties": False,
        },
        validate=_validate_create_task,
        execute=_execute_create_task,
    ),
    ActionDefinition(
        action_type="assign_remediation_task",
        description=(
            "Propose assigning an existing remediation task to a user. Requires a "
            "human to confirm."
        ),
        required_permission=Permission.MANAGE_FINDINGS,
        parameters={
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "assignee_user_id": {"type": "string"},
            },
            "required": ["task_id", "assignee_user_id"],
            "additionalProperties": False,
        },
        validate=_validate_assign_task,
        execute=_execute_assign_task,
    ),
)

ACTIONS_BY_TYPE: dict[str, ActionDefinition] = {
    action.action_type: action for action in ACTIONS
}


def propose(
    db: Session,
    *,
    organization_id: uuid.UUID,
    action_type: str,
    parameters: dict,
    rationale: str,
    proposed_by_user_id: uuid.UUID | None,
    conversation_id: uuid.UUID | None = None,
    message_id: uuid.UUID | None = None,
) -> AgentActionProposal:
    """Record a proposal after checking it could actually be carried out."""
    definition = ACTIONS_BY_TYPE.get(action_type)
    if definition is None:
        raise ActionError(f"{action_type} is not an action this platform can perform.")

    validated = definition.validate(db, organization_id, parameters or {})

    proposal = AgentActionProposal(
        organization_id=organization_id,
        conversation_id=conversation_id,
        message_id=message_id,
        action_type=definition.action_type,
        parameters=validated.parameters,
        rationale=(rationale or "").strip()[:4000],
        effect_summary=validated.effect_summary,
        required_permission=definition.required_permission.value,
        status=ProposalStatus.PROPOSED,
        proposed_by_user_id=proposed_by_user_id,
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes=settings.AGENT_PROPOSAL_TTL_MINUTES),
    )
    db.add(proposal)
    db.flush()
    return proposal


def _held_permissions(user: User) -> set[str]:
    if user.is_super_admin:
        return {member.value for member in Permission}
    return {perm.code for role in user.roles for perm in role.permissions}


def _expired(proposal: AgentActionProposal) -> bool:
    deadline = proposal.expires_at
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return deadline < datetime.now(timezone.utc)


def confirm(db: Session, proposal: AgentActionProposal, actor: User) -> AgentActionProposal:
    """
    Execute a proposal on a human's authority.

    Everything is rechecked here — status, expiry, the confirming user's
    permissions, and the action's own preconditions — because the proposal may
    have been sitting in a queue while the underlying records changed.
    """
    if proposal.status != ProposalStatus.PROPOSED:
        raise ActionError(
            f"This proposal is already {proposal.status.value} and cannot be confirmed again."
        )
    if _expired(proposal):
        proposal.status = ProposalStatus.EXPIRED
        db.add(proposal)
        db.flush()
        raise ActionError(
            "This proposal has expired. Ask again so it can be re-checked against "
            "current data before anything is changed."
        )

    definition = ACTIONS_BY_TYPE.get(proposal.action_type)
    if definition is None:
        raise ActionError(f"{proposal.action_type} is no longer a supported action.")

    if definition.required_permission.value not in _held_permissions(actor):
        raise ActionError(
            f"Confirming this requires {definition.required_permission.value}, "
            f"which this account does not hold."
        )

    proposal.decided_by_user_id = actor.id
    proposal.decided_at = datetime.now(timezone.utc)

    try:
        result = definition.execute(db, proposal, actor)
    except (ActionError, ValueError) as exc:
        proposal.status = ProposalStatus.FAILED
        proposal.error = str(exc)
        db.add(proposal)
        db.flush()
        log_action(
            db, "agent_action_failed", "agent_action_proposal",
            proposal.organization_id, actor.id, str(proposal.id),
            metadata={"action_type": proposal.action_type, "error": str(exc)},
        )
        raise

    proposal.status = ProposalStatus.EXECUTED
    proposal.executed_at = datetime.now(timezone.utc)
    proposal.result = result
    db.add(proposal)
    db.flush()

    log_action(
        db, "agent_action_executed", "agent_action_proposal",
        proposal.organization_id, actor.id, str(proposal.id),
        metadata={
            "action_type": proposal.action_type,
            "parameters": proposal.parameters,
            "result": result,
        },
    )
    return proposal


def reject(
    db: Session, proposal: AgentActionProposal, actor: User, note: str = ""
) -> AgentActionProposal:
    if proposal.status != ProposalStatus.PROPOSED:
        raise ActionError(f"This proposal is already {proposal.status.value}.")

    proposal.status = ProposalStatus.REJECTED
    proposal.decided_by_user_id = actor.id
    proposal.decided_at = datetime.now(timezone.utc)
    proposal.decision_note = (note or "").strip()[:2000]
    db.add(proposal)
    db.flush()

    log_action(
        db, "agent_action_rejected", "agent_action_proposal",
        proposal.organization_id, actor.id, str(proposal.id),
        metadata={"action_type": proposal.action_type, "note": proposal.decision_note},
    )
    return proposal


def proposal_tool_schema() -> dict:
    """
    The single tool through which the model may request a change.

    It records intent. It does not perform anything, and the model is told so
    in the description, because a model that believes it has acted will report
    that it has.
    """
    return {
        "type": "function",
        "function": {
            "name": "propose_action",
            "description": (
                "Record a proposed change for a human to review. This does NOT "
                "perform the action — nothing changes until an operator with the "
                "required permission confirms it. Say that you have proposed it, "
                "never that you have done it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "enum": [action.action_type for action in ACTIONS],
                    },
                    "parameters": {
                        "type": "object",
                        "description": (
                            "Arguments for the action. create_remediation_task takes "
                            "finding_id. assign_remediation_task takes task_id and "
                            "assignee_user_id."
                        ),
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Why this is worth doing, citing the finding.",
                    },
                },
                "required": ["action_type", "parameters", "rationale"],
            },
        },
    }
