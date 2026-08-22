from typing import Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.deps import get_db, get_current_active_user
from app.models.user import User
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.vulnerability_intel import Cve

router = APIRouter()


@router.get("")
def global_search(
    q: str = Query(..., min_length=1),
    limit_per_category: int = Query(5, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
) -> Any:
    # A global search endpoint across multiple entity types
    
    # 1. Search Assets (hostname or ip_address)
    assets = db.query(Asset).filter(
        Asset.organization_id == current_user.organization_id,
        or_(
            Asset.hostname.ilike(f"%{q}%"),
            Asset.ip_address.ilike(f"%{q}%")
        )
    ).limit(limit_per_category).all()

    # 2. Search Findings (title or evidence)
    findings = db.query(Finding).filter(
        Finding.organization_id == current_user.organization_id,
        or_(
            Finding.title.ilike(f"%{q}%"),
            Finding.evidence.ilike(f"%{q}%")
        )
    ).limit(limit_per_category).all()

    # 3. Search CVE Intelligence (cve_id or description)
    # CVE intel is global, not tenant-scoped
    cves = db.query(Cve).filter(
        or_(
            Cve.id.ilike(f"%{q}%"),
            Cve.description.ilike(f"%{q}%")
        )
    ).limit(limit_per_category).all()

    return {
        "assets": [
            {
                "id": a.id,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "type": a.asset_type
            } for a in assets
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status
            } for f in findings
        ],
        "cves": [
            {
                "id": c.id,
                "description": c.description,
                "cvss_score": c.cvss_v3_score
            } for c in cves
        ]
    }
