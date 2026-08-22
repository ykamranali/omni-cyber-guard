"""
Threat intelligence.

This endpoint returns only what the platform has actually observed or
synchronised. It previously shipped a `MOCK_THREATS` list of six hardcoded
CVEs with timestamps manufactured from `now() - timedelta(days=N)`, presented
to the UI as `global_cves` and counted as `zero_days_tracked`. That list was
removed.

Real CVE / KEV / EPSS ingestion (NVD 2.0 API, the CISA KEV feed and the FIRST
EPSS dataset, each stored with its own source and sync timestamp) is Phase 4
of the roadmap. Until those feeds are wired up, this endpoint reports that the
catalogue is unsynchronised rather than inventing entries.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.user import User
from app.models.vulnerability_intel import Cve, EpssScore, IntelSyncState, KevEntry
from app.services.threat_monitor import get_recent_threats, monitor_status

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


@router.get("")
def get_threat_intelligence(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    observed = get_recent_threats()
    status = monitor_status()

    if not status["available"]:
        posture = "MONITOR_UNAVAILABLE"
    elif any(event["severity"] == "CRITICAL" for event in observed):
        posture = "ELEVATED"
    elif observed:
        posture = "MONITORING"
    else:
        posture = "QUIET"

    return {
        # Derived from observed events only.
        "global_risk_level": posture,
        "observed_events": len(observed),
        "latest_advisories": observed,
        "passive_monitor": status,
        "cve_catalogue": _cve_catalogue(db),
    }


def _cve_catalogue(db: Session) -> dict:
    """
    The most recently published CVEs held locally, with exploitation context.

    Reports what has actually been synchronised. An unsynchronised catalogue
    says so instead of returning an empty list, because "no recent CVEs" and
    "we have never downloaded any CVEs" would otherwise look identical.
    """
    states = {row.source: row for row in db.execute(select(IntelSyncState)).scalars()}
    nvd_state = states.get("nvd")
    total = db.execute(select(func.count(Cve.id))).scalar_one()

    if nvd_state is None or nvd_state.last_success_at is None:
        return {
            "configured": False,
            "sources": ["NVD", "CISA KEV", "FIRST EPSS"],
            "last_synced_at": None,
            "total_records": total,
            "entries": [],
            "message": (
                "The vulnerability catalogue has not been synchronised yet. Open CVE "
                "Intelligence to run the first synchronisation."
            ),
        }

    recent = db.execute(
        select(Cve).order_by(Cve.published_at.desc().nullslast()).limit(10)
    ).scalars().all()
    identifiers = [row.cve_id for row in recent]

    kev = {
        row.cve_id for row in
        db.execute(select(KevEntry).where(KevEntry.cve_id.in_(identifiers))).scalars()
    }
    epss = {
        row.cve_id: row.score for row in
        db.execute(select(EpssScore).where(EpssScore.cve_id.in_(identifiers))).scalars()
    }

    return {
        "configured": True,
        "sources": ["NVD", "CISA KEV", "FIRST EPSS"],
        "last_synced_at": nvd_state.last_success_at.isoformat(),
        "total_records": total,
        "entries": [
            {
                "id": row.cve_id,
                "title": row.cve_id,
                "description": (row.description or "")[:400],
                "severity": (row.cvss_v3_severity or "INFO").upper(),
                "cvss": row.cvss_v3_score,
                "epss": epss.get(row.cve_id),
                "known_exploited": row.cve_id in kev,
                "timestamp": row.published_at.isoformat() if row.published_at else None,
                "tags": (row.cwe_ids or [])[:3],
            }
            for row in recent
        ],
        "message": "",
    }
