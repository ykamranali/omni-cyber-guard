from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.asset import Asset
from app.models.finding import Finding
from app.services.threat_monitor import get_recent_threats

router = APIRouter(prefix="/intelligence", tags=["Intelligence"])

@router.get("/insights", response_model=List[Dict[str, Any]])
def get_heuristic_insights(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_DASHBOARD))
):
    """
    Automated Security Intelligence (Heuristic Engine)
    Correlates real-time threat events with known vulnerabilities on assets.
    """
    insights = []
    
    # 1. Fetch open, critical/high findings
    critical_findings = db.query(Finding).join(Asset).filter(
        Asset.organization_id == current_user.organization_id,
        Finding.status == "open",
        Finding.severity.in_(["critical", "high"])
    ).all()
    
    # 2. Fetch real-time network threats
    recent_threats = get_recent_threats()
    
    # 3. Correlation Heuristic: Are any assets with critical vulns currently being attacked?
    vulnerable_ips = {f.asset.ip_address for f in critical_findings if f.asset.ip_address}
    
    targeted_vulnerable_assets = set()
    for threat in recent_threats:
        # We need to extract the target IP from the threat description since it's a string in the new structure
        desc = threat.get("description", "")
        for ip in vulnerable_ips:
            if ip in desc:
                targeted_vulnerable_assets.add(ip)
            
    # Generate Insights
    for ip in targeted_vulnerable_assets:
        insights.append({
            "id": f"insight-corr-{ip}",
            "type": "critical",
            "title": "High Risk Correlation: Active Targeting",
            "description": f"Asset {ip} has Critical/High severity vulnerabilities and is actively being targeted by network threats. Immediate isolation recommended.",
            "asset_ip": ip,
            "confidence_score": 98
        })
        
    # Generic Volume Anomaly Heuristic (Mocked for demonstration)
    if len(recent_threats) > 50:
         insights.append({
            "id": "insight-vol-anomaly",
            "type": "warning",
            "title": "Anomalous Traffic Volume",
            "description": f"The network is experiencing an unusually high volume of security events ({len(recent_threats)} in the recent window).",
            "confidence_score": 85
        })
         
    # Optimization Recommendation Heuristic
    ftp_findings = [f for f in critical_findings if "ftp" in f.title.lower()]
    if ftp_findings:
        insights.append({
            "id": "insight-rec-ftp",
            "type": "recommendation",
            "title": "Automated Policy Optimization",
            "description": "Based on historical findings, disabling insecure FTP across your subnets will reduce your overall attack surface significantly.",
            "confidence_score": 95
        })

    # If everything is perfectly clean, give an all-clear
    if not insights:
        insights.append({
            "id": "insight-all-clear",
            "type": "recommendation",
            "title": "Posture is Optimal",
            "description": "No immediate critical correlations detected between active threats and known vulnerabilities.",
            "confidence_score": 100
        })

    return insights
