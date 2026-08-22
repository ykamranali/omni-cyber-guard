"""
API for the grounded security engineer.

Every route is permission-guarded, and the response shape is built so the
operator can check the assistant rather than take it on trust: alongside the
answer come the records that were retrieved, which tools ran, and the outcome
of the grounding check. When no model is configured the endpoints still work
and report exactly that — a disabled assistant is a visible state, not an
error message dressed as analysis.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents import actions as action_registry
from app.agents.security_engineer import AgentAnswer, SecurityEngineerAgent
from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.agent import (
    AgentActionProposal, AgentConversation, AgentMessage, MessageRole, ProposalStatus,
)
from app.models.finding import Finding
from app.models.user import User

router = APIRouter(prefix="/agent", tags=["agent"])


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: uuid.UUID | None = None


class AnalyzeRequest(BaseModel):
    finding_id: uuid.UUID
    conversation_id: uuid.UUID | None = None


class RejectRequest(BaseModel):
    note: str = Field(default="", max_length=2000)


def _proposal_dict(proposal: AgentActionProposal) -> dict:
    return {
        "id": str(proposal.id),
        "action_type": proposal.action_type,
        "parameters": proposal.parameters,
        "rationale": proposal.rationale,
        # What confirming will do, in the platform's words rather than the
        # model's.
        "effect": proposal.effect_summary,
        "required_permission": proposal.required_permission,
        "status": proposal.status.value,
        "expires_at": proposal.expires_at.isoformat() if proposal.expires_at else None,
        "decided_at": proposal.decided_at.isoformat() if proposal.decided_at else None,
        "executed_at": proposal.executed_at.isoformat() if proposal.executed_at else None,
        "result": proposal.result or {},
        "error": proposal.error,
    }


def _answer_dict(answer: AgentAnswer) -> dict:
    payload = answer.as_dict()
    payload["proposals"] = [_proposal_dict(item) for item in answer.proposals]
    return payload


def _conversation_for(
    db: Session, user: User, conversation_id: uuid.UUID | None
) -> AgentConversation:
    if conversation_id is not None:
        conversation = db.execute(
            select(AgentConversation).where(
                AgentConversation.id == conversation_id,
                AgentConversation.organization_id == user.organization_id,
            )
        ).scalar_one_or_none()
        if conversation is None:
            raise HTTPException(status_code=404, detail="Conversation not found")
        return conversation

    conversation = AgentConversation(
        organization_id=user.organization_id, user_id=user.id, title=""
    )
    db.add(conversation)
    db.flush()
    return conversation


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@router.get("/status")
def agent_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    """
    Whether the assistant can run, and what is missing if it cannot.

    Reported as configuration state so the UI can show "not configured" instead
    of putting a connection error where analysis belongs.
    """
    agent = SecurityEngineerAgent(db, current_user)
    provider = agent.status()
    available_tools = [
        {
            "name": tool.name,
            "description": tool.description,
            "required_permission": tool.required_permission.value,
        }
        for tool in agent.retrieval_tools()
    ]
    return {
        "provider": provider.as_dict(),
        "retrieval_tools": available_tools,
        "proposable_actions": [
            {
                "action_type": action.action_type,
                "description": action.description,
                "required_permission": action.required_permission.value,
            }
            for action in action_registry.ACTIONS
        ],
        "guarantees": {
            "retrieval_is_read_only": True,
            "answers_validated_against_retrieved_records": True,
            "actions_require_human_confirmation": True,
        },
    }


@router.post("/chat")
def chat(
    request: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    conversation = _conversation_for(db, current_user, request.conversation_id)
    if not conversation.title:
        conversation.title = request.message.strip()[:120]
        db.add(conversation)

    agent = SecurityEngineerAgent(db, current_user)
    answer = agent.ask(request.message, conversation)
    db.commit()
    return _answer_dict(answer)


@router.post("/analyze")
def analyze(
    request: AnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    finding = db.execute(
        select(Finding).where(
            Finding.id == request.finding_id,
            Finding.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    conversation = _conversation_for(db, current_user, request.conversation_id)
    if not conversation.title:
        conversation.title = f"Analysis: {finding.title}"[:120]
        db.add(conversation)

    agent = SecurityEngineerAgent(db, current_user)
    answer = agent.analyze_finding(finding, conversation)
    db.commit()
    return _answer_dict(answer)


@router.get("/conversations")
def list_conversations(
    limit: int = Query(default=25, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    rows = db.execute(
        select(AgentConversation).where(
            AgentConversation.organization_id == current_user.organization_id
        ).order_by(AgentConversation.updated_at.desc()).limit(limit)
    ).scalars().all()
    return [
        {
            "id": str(row.id),
            "title": row.title,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
        for row in rows
    ]


@router.get("/conversations/{conversation_id}")
def get_conversation(
    conversation_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    conversation = db.execute(
        select(AgentConversation).where(
            AgentConversation.id == conversation_id,
            AgentConversation.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if conversation is None:
        raise HTTPException(status_code=404, detail="Conversation not found")

    messages = db.execute(
        select(AgentMessage).where(
            AgentMessage.conversation_id == conversation.id
        ).order_by(AgentMessage.created_at.asc())
    ).scalars().all()

    return {
        "id": str(conversation.id),
        "title": conversation.title,
        "messages": [
            {
                "id": str(message.id),
                "role": message.role.value,
                # A withheld draft is never returned here. It stays in the
                # database for review and is reachable only through the audit
                # path, so it cannot be mistaken for analysis.
                "content": message.content,
                "tool_name": message.tool_name,
                "tool_row_count": message.tool_row_count,
                "grounding_status": message.grounding_status.value,
                "evidence_refs": message.evidence_refs or [],
                "unsupported_refs": message.unsupported_refs or [],
                "answer_withheld": bool(message.withheld_draft),
                "created_at": message.created_at.isoformat() if message.created_at else None,
            }
            for message in messages
            if message.role != MessageRole.SYSTEM
        ],
    }


@router.get("/actions")
def list_proposals(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    stmt = select(AgentActionProposal).where(
        AgentActionProposal.organization_id == current_user.organization_id
    )
    if status_filter:
        try:
            stmt = stmt.where(AgentActionProposal.status == ProposalStatus(status_filter))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    "status must be one of: "
                    + ", ".join(member.value for member in ProposalStatus)
                ),
            )
    rows = db.execute(
        stmt.order_by(AgentActionProposal.created_at.desc()).limit(limit)
    ).scalars().all()
    return [_proposal_dict(row) for row in rows]


def _load_proposal(db: Session, user: User, proposal_id: uuid.UUID) -> AgentActionProposal:
    proposal = db.execute(
        select(AgentActionProposal).where(
            AgentActionProposal.id == proposal_id,
            AgentActionProposal.organization_id == user.organization_id,
        )
    ).scalar_one_or_none()
    if proposal is None:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return proposal


@router.post("/actions/{proposal_id}/confirm")
def confirm_proposal(
    proposal_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    """
    Carry out a proposed action on this operator's authority.

    The permission this route requires is only the one needed to see the
    proposal. The permission the *action* needs is checked inside
    `actions.confirm` against the confirming user, so a viewer cannot execute
    something they could not have done directly.
    """
    proposal = _load_proposal(db, current_user, proposal_id)
    try:
        action_registry.confirm(db, proposal, current_user)
    except action_registry.ActionError as exc:
        db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    db.commit()
    return _proposal_dict(proposal)


@router.post("/actions/{proposal_id}/reject")
def reject_proposal(
    proposal_id: uuid.UUID,
    request: RejectRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
) -> Any:
    proposal = _load_proposal(db, current_user, proposal_id)
    try:
        action_registry.reject(db, proposal, current_user, request.note)
    except action_registry.ActionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    db.commit()
    return _proposal_dict(proposal)
