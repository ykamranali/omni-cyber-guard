import os
import requests
import json
import logging

logger = logging.getLogger(__name__)

# Fallback to localhost if host.docker.internal isn't resolving (e.g. native linux)
LITELLM_URL = os.environ.get("LITELLM_URL", "http://host.docker.internal:4000/v1/chat/completions")
# Default model route setup in litellm, or whatever the user has configured
DEFAULT_MODEL = os.environ.get("LITELLM_MODEL", "gpt-3.5-turbo")

def generate_playbook_content(title: str, description: str, severity: str) -> str:
    """
    Calls the LiteLLM/OpenAI-compatible endpoint to generate an incident remediation playbook.
    """
    system_prompt = (
        "You are an elite cybersecurity incident response expert. "
        "Your task is to generate a concise, actionable, step-by-step remediation playbook "
        "for the provided security incident. Format the output in Markdown. "
        "Include sections for: Overview, Immediate Containment, Permanent Remediation, and Validation."
    )
    
    user_prompt = f"Incident Title: {title}\nSeverity: {severity}\nDescription: {description or 'N/A'}"
    
    payload = {
        "model": DEFAULT_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 1000
    }
    
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(LITELLM_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        # Parse standard OpenAI chat completion response format
        return data["choices"][0]["message"]["content"]
    except requests.exceptions.ConnectionError:
        logger.error(f"Failed to connect to LLM at {LITELLM_URL}. Make sure LiteLLM is running.")
        return _fallback_playbook(title, description, severity)
    except Exception as e:
        logger.error(f"Error generating LLM playbook: {str(e)}")
        return _fallback_playbook(title, description, severity)

def _fallback_playbook(title: str, description: str, severity: str) -> str:
    """Fallback playbook generator when LLM is unreachable."""
    return f"""# AI Remediation Playbook (Fallback Mode)
    
## Overview
The system was unable to reach the local LLM service to generate a dynamic playbook.
Incident: **{title}** (Severity: {severity})

## Containment Strategy
1. Verify the authenticity of the finding.
2. If legitimate, restrict access to the affected asset to prevent lateral movement.

## Remediation Steps
1. Review the application or system logs for anomalies.
2. Apply relevant patches or configuration changes.

*Please ensure your `omni-litellm` container is running and accessible to use dynamic playbooks.*
"""
