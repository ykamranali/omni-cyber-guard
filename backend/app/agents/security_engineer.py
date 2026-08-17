import json
import logging
import os
import requests
from typing import Any

from app.models.finding import Finding
from app.models.asset import Asset
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# Defaults to Ollama running locally if no external provider is configured
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "local")
LLM_API_BASE = os.getenv("LLM_API_BASE", "http://localhost:11434/api")
LLM_MODEL = os.getenv("LLM_MODEL", "llama3")

SYSTEM_PROMPT = """You are Omni Security Engineer, an expert cybersecurity analyst agent.
Your purpose is to analyze scan results, prioritize vulnerabilities, and provide remediation guidance.
CRITICAL RULES:
1. NEVER invent or hallucinate scan evidence, vulnerabilities, or assets.
2. Only answer based on the database context provided to you.
3. If evidence is missing, state clearly that it is not available.
4. Distinguish between Confirmed, Likely, and Potential issues.
5. Provide concise, professional, and actionable advice.
"""

class SecurityEngineerAgent:
    def __init__(self, db: Session):
        self.db = db

    def _call_local_llm(self, prompt: str, context: str = "") -> str:
        """Call a local OpenAI-compatible or Ollama API."""
        try:
            full_prompt = f"{SYSTEM_PROMPT}\n\nCONTEXT:\n{context}\n\nUSER PROMPT:\n{prompt}"
            payload = {
                "model": LLM_MODEL,
                "prompt": full_prompt,
                "stream": False
            }
            response = requests.post(f"{LLM_API_BASE}/generate", json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "No response generated.")
        except Exception as e:
            logger.error(f"LLM interaction failed: {e}")
            return f"Error: Unable to reach the LLM provider. Please check if {LLM_PROVIDER} is running at {LLM_API_BASE}. Exception: {e}"

    def analyze_finding(self, finding: Finding) -> str:
        """Provide detailed analysis of a single finding."""
        context = f"Asset ID: {finding.asset_id}\nTitle: {finding.title}\nSeverity: {finding.severity.value}\nDescription: {finding.description}\nEvidence: {finding.evidence}\nRemediation: {finding.remediation_guidance}"
        prompt = "Analyze this vulnerability. Explain what it means, why it matters, the potential business risk, and recommend a clear remediation strategy."
        return self._call_local_llm(prompt, context)

    def ask_question(self, question: str, org_id: str) -> str:
        """Answer general questions using the organization's current vulnerability context."""
        # Simple context gathering (in a real app, this would use RAG or specific aggregations)
        findings = self.db.query(Finding).filter(Finding.organization_id == org_id, Finding.status == "open").limit(50).all()
        assets = self.db.query(Asset).filter(Asset.organization_id == org_id).all()
        
        context_lines = [f"Total Assets: {len(assets)}", f"Open Findings Context (up to 50):"]
        for f in findings:
            context_lines.append(f"- {f.severity.value.upper()} on Asset {f.asset_id}: {f.title}")
            
        context = "\n".join(context_lines)
        return self._call_local_llm(question, context)
