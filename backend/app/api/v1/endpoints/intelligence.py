"""
Automated intelligence — evidence-backed correlations only.

Every insight returned here must name the assets and the observations it was
derived from. The previous implementation emitted insights with invented
confidence scores (85, 95, 98, 100) and a canned "disabling insecure FTP will
reduce your attack surface significantly" recommendation that was returned
whether or not it applied. Those were removed.

An insight carries `evidence`, which lists the concrete records behind it. If
there is nothing to correlate, this endpoint returns an empty list — the UI
shows an empty state rather than a reassuring "posture is optimal" message
that was never actually computed.
"""
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset
from app.models.finding import Finding, FindingStatus, Severity
from app.models.user import User
from app.services.threat_monitor import get_recent_threats

router = APIRouter(prefix="/intelligence", tags=["Intelligence"])


@router.get("/insights", response_model=list[dict[str, Any]])
def get_correlated_insights(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    insights: list[dict[str, Any]] = []

    severe_findings = (
        db.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Finding.organization_id == current_user.organization_id,
            Finding.status == FindingStatus.OPEN,
            Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]),
        )
        .all()
    )

    observed_events = get_recent_threats()

    # --- Correlation: an asset with open severe findings appears in a
    # currently-observed network event. Both halves are real records. ---
    findings_by_ip: dict[str, list[Finding]] = {}
    for finding in severe_findings:
        ip = finding.asset.ip_address if finding.asset else None
        if ip:
            findings_by_ip.setdefault(ip, []).append(finding)

    for ip, ip_findings in findings_by_ip.items():
        matching_events = [
            event for event in observed_events
            if ip in event.get("description", "")
        ]
        if not matching_events:
            continue

        insights.append({
            "id": f"insight-correlation-{ip}",
            "type": "critical",
            "title": "Asset with open severe findings appears in observed network activity",
            "description": (
                f"{ip} has {len(ip_findings)} open critical/high finding(s) and was "
                f"referenced in {len(matching_events)} network event(s) observed by the "
                f"passive monitor. Review whether the exposure and the activity are related."
            ),
            "asset_ip": ip,
            "evidence": {
                "finding_ids": [str(f.id) for f in ip_findings],
                "finding_titles": [f.title for f in ip_findings][:5],
                "event_ids": [e["id"] for e in matching_events][:5],
                "event_titles": [e["title"] for e in matching_events][:5],
            },
        })

    # --- Aggregation: repeated exposure of the same service across assets.
    # This is a count over real findings, not a heuristic guess. ---
    by_title: dict[str, list[Finding]] = {}
    for finding in severe_findings:
        by_title.setdefault(finding.title, []).append(finding)

    for title, group in by_title.items():
        distinct_assets = {f.asset_id for f in group}
        if len(distinct_assets) < 3:
            continue
        insights.append({
            "id": f"insight-recurring-{abs(hash(title)) % (10 ** 10)}",
            "type": "recommendation",
            "title": "Same exposure repeated across multiple assets",
            "description": (
                f'"{title}" is open on {len(distinct_assets)} assets. A single '
                f"configuration or policy change is likely to close all of them."
            ),
            "evidence": {
                "affected_asset_count": len(distinct_assets),
                "finding_ids": [str(f.id) for f in group][:10],
            },
        })

    return insights
