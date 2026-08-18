from datetime import datetime, timedelta, timezone
import random

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_active_user
from app.models.user import User

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

MOCK_THREATS = [
    {
        "id": "CVE-2024-3094",
        "title": "XZ Utils Backdoor (Supply Chain Attack)",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Malicious code discovered in xz/liblzma leading to RCE in OpenSSH.",
        "published_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
        "tags": ["Supply Chain", "RCE", "Linux"],
    },
    {
        "id": "CVE-2024-21412",
        "title": "Windows SmartScreen Security Feature Bypass",
        "severity": "HIGH",
        "cvss": 8.1,
        "description": "An attacker can bypass Windows SmartScreen protections by crafting a malicious internet shortcut.",
        "published_at": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
        "tags": ["Bypass", "Windows", "Phishing"],
    },
    {
        "id": "CVE-2023-46805",
        "title": "Ivanti Connect Secure Authentication Bypass",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Authentication bypass vulnerability in the web component of Ivanti ICS 9.x, 22.x allowing arbitrary command execution.",
        "published_at": (datetime.now(timezone.utc) - timedelta(days=12)).isoformat(),
        "tags": ["Auth Bypass", "VPN", "RCE"],
    },
    {
        "id": "CVE-2023-22527",
        "title": "Atlassian Confluence Template Injection",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "description": "Unauthenticated template injection vulnerability allowing RCE on older out-of-date Confluence Server and Data Center instances.",
        "published_at": (datetime.now(timezone.utc) - timedelta(days=15)).isoformat(),
        "tags": ["RCE", "Atlassian", "Web"],
    },
    {
        "id": "CVE-2023-48795",
        "title": "Terrapin SSH Attack",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "description": "Prefix truncation attack in SSH cryptographic handshakes affecting multiple implementations.",
        "published_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
        "tags": ["Crypto", "SSH", "MitM"],
    },
    {
        "id": "CVE-2023-4966",
        "title": "Citrix NetScaler Information Disclosure (Citrix Bleed)",
        "severity": "CRITICAL",
        "cvss": 9.4,
        "description": "Sensitive information disclosure leading to session hijacking in Citrix NetScaler ADC and Gateway.",
        "published_at": (datetime.now(timezone.utc) - timedelta(days=45)).isoformat(),
        "tags": ["Info Disclosure", "Gateway", "Active Exploitation"],
    },
]

from app.services.threat_monitor import get_recent_threats, add_threat
from pydantic import BaseModel

class ThreatEventCreate(BaseModel):
    title: str
    description: str
    severity: str
    tags: list[str]

@router.get("")
def get_threat_intelligence(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    recent = get_recent_threats()
    return {
        "global_risk_level": "ELEVATED" if any(e["severity"] == "CRITICAL" for e in recent) else "MONITORING",
        "active_campaigns": len(recent),
        "zero_days_tracked": len(MOCK_THREATS),
        "latest_advisories": recent,
        "global_cves": MOCK_THREATS
    }

@router.post("/test-event", status_code=201)
def trigger_test_event(
    payload: ThreatEventCreate,
    current_user: User = Depends(get_current_active_user)
):
    """Hidden endpoint to inject test events to demonstrate the live feed"""
    add_threat(payload.title, payload.description, payload.severity, payload.tags)
    return {"status": "success"}
