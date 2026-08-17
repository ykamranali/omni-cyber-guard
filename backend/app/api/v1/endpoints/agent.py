from typing import Any
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_user
from app.models.user import User
from app.models.finding import Finding
from app.agents.security_engineer import SecurityEngineerAgent

router = APIRouter(prefix="/agent", tags=["agent"])

class AnalyzeFindingRequest(BaseModel):
    finding_id: uuid.UUID

class AgentChatRequest(BaseModel):
    message: str

class AgentResponse(BaseModel):
    response: str

@router.post("/analyze", response_model=AgentResponse)
def analyze_finding(
    request: AnalyzeFindingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Analyze a specific finding using the Omni Security Engineer Agent."""
    finding = db.query(Finding).filter(
        Finding.id == request.finding_id,
        Finding.organization_id == current_user.organization_id
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    agent = SecurityEngineerAgent(db)
    result = agent.analyze_finding(finding)
    return AgentResponse(response=result)

@router.post("/chat", response_model=AgentResponse)
def chat_with_agent(
    request: AgentChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Ask a general question to the Omni Security Engineer Agent."""
    agent = SecurityEngineerAgent(db)
    result = agent.ask_question(request.message, str(current_user.organization_id))
    return AgentResponse(response=result)
