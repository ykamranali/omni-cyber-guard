"""
The agent's retrieval layer.

Every fact the assistant is allowed to state has to come through here. There is
no path by which it receives free-form context: it asks for specific records
with typed arguments, this module runs a real query against the operator's own
database, and the rows that come back are both what the model sees and what the
answer is later validated against.

Three properties hold for every tool in this module, and the tests enforce them:

* **Read-only.** Nothing here writes, updates or deletes. Changing state is the
  job of `app.agents.actions`, which requires a human confirmation first.
* **Tenant-scoped.** Each query filters on `organization_id` explicitly, on top
  of the row-level security already applied to the session. Two independent
  mechanisms have to fail before one organization sees another's data.
* **Bounded and honest about it.** A result set larger than the row cap is
  truncated and says so in the payload, so "3 findings" is never the model's
  reading of a silently trimmed list.

Each row carries a reference string — `finding:<uuid>`, `asset:<uuid>`,
`cve:CVE-2024-3094` — collected into the evidence set for the request. An
answer naming an identifier that is not in that set did not get it from the
database.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import Permission
from app.models.asset import Asset, AssetStatus, Criticality
from app.models.asset_detail import AssetService, AssetSoftware
from app.models.compliance import ComplianceAssessment, ComplianceFramework
from app.models.finding import CLOSED_STATUSES, Finding, FindingClass, FindingStatus, Severity
from app.models.remediation import RemediationStatus, RemediationTask
from app.models.scan_job import ScanJob
from app.models.vulnerability_intel import Cve, EpssScore, KevEntry
from app.models.user import User


class ToolError(ValueError):
    """A tool was called with arguments it cannot honour. Reported to the model
    verbatim so it can correct the call, never surfaced as an answer."""


@dataclass
class ToolContext:
    db: Session
    organization_id: uuid.UUID
    user: User

    @property
    def permissions(self) -> set[str]:
        if self.user.is_super_admin:
            return {p.value for p in Permission}
        return {perm.code for role in self.user.roles for perm in role.permissions}


@dataclass
class ToolResult:
    """
    What a retrieval returned.

    `refs` is the part that matters for grounding: the set of record
    identifiers the model has now genuinely been shown.
    """
    rows: list[dict] = field(default_factory=list)
    refs: set[str] = field(default_factory=set)
    total_matching: int | None = None
    truncated: bool = False
    note: str = ""

    def as_payload(self) -> dict:
        payload: dict[str, Any] = {"rows": self.rows, "row_count": len(self.rows)}
        if self.total_matching is not None:
            payload["total_matching"] = self.total_matching
        if self.truncated:
            payload["truncated"] = True
            payload["truncation_note"] = (
                f"Only the first {len(self.rows)} of {self.total_matching} matching records "
                f"are shown. Do not describe this as the complete set."
            )
        if self.note:
            payload["note"] = self.note
        if not self.rows:
            payload.setdefault(
                "note",
                "No records matched. This means the database holds no such data, "
                "not that the environment is clean.",
            )
        return payload


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    parameters: dict
    handler: Callable[..., ToolResult]
    required_permission: Permission

    def schema(self) -> dict:
        """OpenAI / Ollama tool-calling schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


# --------------------------------------------------------------------------
# Argument helpers
# --------------------------------------------------------------------------

def _row_cap(requested: Any) -> int:
    cap = settings.AGENT_MAX_ROWS_PER_TOOL
    if requested is None:
        return min(20, cap)
    try:
        value = int(requested)
    except (TypeError, ValueError):
        raise ToolError(f"limit must be a whole number, received {requested!r}")
    if value < 1:
        raise ToolError("limit must be at least 1")
    return min(value, cap)


def _enum_arg(value: Any, enum_cls, argument: str):
    if value is None or value == "":
        return None
    try:
        return enum_cls(str(value).lower())
    except ValueError:
        allowed = ", ".join(member.value for member in enum_cls)
        raise ToolError(f"{argument} must be one of: {allowed}")


def _uuid_arg(value: Any, argument: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        raise ToolError(f"{argument} must be a UUID, received {value!r}")


def _excerpt(text: str | None, limit: int = 400) -> str:
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + " […truncated]"


# --------------------------------------------------------------------------
# Serialisers — the exact shape the model sees
# --------------------------------------------------------------------------

def _finding_row(finding: Finding, asset: Asset | None) -> dict:
    return {
        "ref": f"finding:{finding.id}",
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "finding_class": finding.finding_class.value,
        "confidence": finding.confidence.value,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "epss_score": finding.epss_score,
        "known_exploited": finding.is_known_exploited,
        "source": finding.source,
        "asset": {
            "ref": f"asset:{asset.id}",
            "id": str(asset.id),
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
        } if asset is not None else None,
        "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
        "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
        "occurrence_count": finding.occurrence_count,
    }


def _asset_row(asset: Asset) -> dict:
    return {
        "ref": f"asset:{asset.id}",
        "id": str(asset.id),
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        "asset_type": asset.asset_type.value,
        "status": asset.status.value,
        "criticality": asset.criticality.value,
        "operating_system": asset.operating_system,
        "internet_facing": asset.is_internet_facing,
        "production": asset.is_production,
        "exposure_score": asset.exposure_score,
        "exposure_assessed_at": (
            asset.exposure_calculated_at.isoformat() if asset.exposure_calculated_at else None
        ),
        "classification_confidence": asset.fingerprint_confidence,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


# --------------------------------------------------------------------------
# Tool implementations
# --------------------------------------------------------------------------

def _count_findings(ctx: ToolContext, group_by: str = "severity", **_: Any) -> ToolResult:
    if group_by not in ("severity", "status", "finding_class"):
        raise ToolError("group_by must be one of: severity, status, finding_class")
    column = {"severity": Finding.severity, "status": Finding.status,
              "finding_class": Finding.finding_class}[group_by]

    open_only = column is not Finding.status
    stmt = select(column, func.count(Finding.id)).where(
        Finding.organization_id == ctx.organization_id
    )
    if open_only:
        stmt = stmt.where(Finding.status.notin_(list(CLOSED_STATUSES)))
    stmt = stmt.group_by(column)

    rows = [
        {"group": key.value if hasattr(key, "value") else str(key), "count": count}
        for key, count in ctx.db.execute(stmt).all()
    ]
    total = sum(row["count"] for row in rows)
    note = (
        "Counts cover findings that are not closed (remediated, false positive "
        "or accepted risk are excluded)." if open_only else
        "Counts cover every finding regardless of status."
    )
    return ToolResult(rows=rows, total_matching=total, note=note)


def _search_findings(
    ctx: ToolContext,
    severity: str | None = None,
    status: str | None = None,
    finding_class: str | None = None,
    cve_id: str | None = None,
    asset_id: str | None = None,
    known_exploited_only: bool = False,
    open_only: bool = True,
    limit: Any = None,
    **_: Any,
) -> ToolResult:
    cap = _row_cap(limit)
    stmt = select(Finding, Asset).join(Asset, Finding.asset_id == Asset.id).where(
        Finding.organization_id == ctx.organization_id
    )
    if severity:
        stmt = stmt.where(Finding.severity == _enum_arg(severity, Severity, "severity"))
    if status:
        stmt = stmt.where(Finding.status == _enum_arg(status, FindingStatus, "status"))
    elif open_only:
        stmt = stmt.where(Finding.status.notin_(list(CLOSED_STATUSES)))
    if finding_class:
        stmt = stmt.where(
            Finding.finding_class == _enum_arg(finding_class, FindingClass, "finding_class")
        )
    if cve_id:
        stmt = stmt.where(func.upper(Finding.cve_id) == str(cve_id).upper())
    if asset_id:
        stmt = stmt.where(Finding.asset_id == _uuid_arg(asset_id, "asset_id"))
    if known_exploited_only:
        stmt = stmt.where(Finding.is_known_exploited.is_(True))

    total = ctx.db.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    ordered = stmt.order_by(
        Finding.is_known_exploited.desc(),
        Finding.cvss_score.desc().nullslast(),
        Finding.last_seen.desc(),
    ).limit(cap)

    rows: list[dict] = []
    refs: set[str] = set()
    for finding, asset in ctx.db.execute(ordered).all():
        rows.append(_finding_row(finding, asset))
        refs.add(f"finding:{finding.id}")
        refs.add(f"asset:{asset.id}")
        if finding.cve_id:
            refs.add(f"cve:{finding.cve_id.upper()}")
        if asset.ip_address:
            refs.add(f"ip:{asset.ip_address}")
        refs.add(f"host:{asset.hostname.lower()}")

    return ToolResult(rows=rows, refs=refs, total_matching=total, truncated=total > len(rows))


def _get_finding(ctx: ToolContext, finding_id: str, **_: Any) -> ToolResult:
    identifier = _uuid_arg(finding_id, "finding_id")
    row = ctx.db.execute(
        select(Finding, Asset).join(Asset, Finding.asset_id == Asset.id).where(
            Finding.id == identifier,
            Finding.organization_id == ctx.organization_id,
        )
    ).first()
    if row is None:
        return ToolResult(note="No finding with that identifier exists in this organization.")

    finding, asset = row
    detail = _finding_row(finding, asset)
    detail.update({
        "description": _excerpt(finding.description, 1500),
        "evidence": _excerpt(finding.evidence, 2000),
        "evidence_note": "Verbatim scanner output. Quote it; do not paraphrase it as observation.",
        "remediation_guidance": _excerpt(finding.remediation_guidance, 1500),
        "affected_product": finding.affected_product,
        "affected_version": finding.affected_version,
        "cvss_vector": finding.cvss_vector,
        "cwe_id": finding.cwe_id,
    })
    refs = {f"finding:{finding.id}", f"asset:{asset.id}", f"host:{asset.hostname.lower()}"}
    if finding.cve_id:
        refs.add(f"cve:{finding.cve_id.upper()}")
    if asset.ip_address:
        refs.add(f"ip:{asset.ip_address}")
    return ToolResult(rows=[detail], refs=refs, total_matching=1)


def _count_assets(ctx: ToolContext, **_: Any) -> ToolResult:
    stmt = select(Asset.asset_type, func.count(Asset.id)).where(
        Asset.organization_id == ctx.organization_id,
        Asset.status != AssetStatus.DECOMMISSIONED,
    ).group_by(Asset.asset_type)
    rows = [{"asset_type": key.value, "count": count} for key, count in ctx.db.execute(stmt).all()]
    return ToolResult(
        rows=rows,
        total_matching=sum(row["count"] for row in rows),
        note="Decommissioned assets are excluded.",
    )


def _search_assets(
    ctx: ToolContext,
    hostname_contains: str | None = None,
    ip_address: str | None = None,
    criticality: str | None = None,
    internet_facing_only: bool = False,
    order_by_exposure: bool = True,
    limit: Any = None,
    **_: Any,
) -> ToolResult:
    cap = _row_cap(limit)
    stmt = select(Asset).where(
        Asset.organization_id == ctx.organization_id,
        Asset.status != AssetStatus.DECOMMISSIONED,
    )
    if hostname_contains:
        stmt = stmt.where(Asset.hostname.ilike(f"%{hostname_contains}%"))
    if ip_address:
        stmt = stmt.where(Asset.ip_address == str(ip_address))
    if criticality:
        stmt = stmt.where(Asset.criticality == _enum_arg(criticality, Criticality, "criticality"))
    if internet_facing_only:
        stmt = stmt.where(Asset.is_internet_facing.is_(True))

    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    ordered = stmt.order_by(
        Asset.exposure_score.desc() if order_by_exposure else Asset.hostname.asc()
    ).limit(cap)

    rows: list[dict] = []
    refs: set[str] = set()
    for asset in ctx.db.execute(ordered).scalars():
        rows.append(_asset_row(asset))
        refs.add(f"asset:{asset.id}")
        refs.add(f"host:{asset.hostname.lower()}")
        if asset.ip_address:
            refs.add(f"ip:{asset.ip_address}")

    return ToolResult(rows=rows, refs=refs, total_matching=total, truncated=total > len(rows))


def _get_asset(ctx: ToolContext, asset_id: str, **_: Any) -> ToolResult:
    identifier = _uuid_arg(asset_id, "asset_id")
    asset = ctx.db.execute(
        select(Asset).where(
            Asset.id == identifier, Asset.organization_id == ctx.organization_id
        )
    ).scalar_one_or_none()
    if asset is None:
        return ToolResult(note="No asset with that identifier exists in this organization.")

    services = ctx.db.execute(
        select(AssetService).where(AssetService.asset_id == asset.id).limit(100)
    ).scalars().all()
    software = ctx.db.execute(
        select(AssetSoftware).where(AssetSoftware.asset_id == asset.id).limit(100)
    ).scalars().all()
    open_findings = ctx.db.execute(
        select(Finding.severity, func.count(Finding.id)).where(
            Finding.asset_id == asset.id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
        ).group_by(Finding.severity)
    ).all()

    detail = _asset_row(asset)
    detail.update({
        "classification_evidence": asset.fingerprint_evidence or [],
        "services": [
            {"port": service.port, "protocol": service.protocol,
             "service_name": service.service_name, "product": service.product,
             "version": service.version, "banner": _excerpt(service.banner, 200)}
            for service in services
        ],
        "software": [
            {"name": item.name, "version": item.version, "cpe": item.cpe,
             "cpe_note": None if item.cpe else
             "No CPE — this component cannot be matched against CVE data."}
            for item in software
        ],
        "open_findings_by_severity": {
            severity.value: count for severity, count in open_findings
        },
    })
    refs = {f"asset:{asset.id}", f"host:{asset.hostname.lower()}"}
    if asset.ip_address:
        refs.add(f"ip:{asset.ip_address}")
    return ToolResult(rows=[detail], refs=refs, total_matching=1)


def _explain_asset_exposure(ctx: ToolContext, asset_id: str, **_: Any) -> ToolResult:
    identifier = _uuid_arg(asset_id, "asset_id")
    asset = ctx.db.execute(
        select(Asset).where(
            Asset.id == identifier, Asset.organization_id == ctx.organization_id
        )
    ).scalar_one_or_none()
    if asset is None:
        return ToolResult(note="No asset with that identifier exists in this organization.")

    breakdown = asset.exposure_breakdown or {}
    if not breakdown:
        return ToolResult(
            rows=[],
            refs={f"asset:{asset.id}"},
            note=(
                f"{asset.hostname} has no exposure assessment yet. Report that the score "
                f"has not been computed rather than describing the stored value of "
                f"{asset.exposure_score}."
            ),
        )
    return ToolResult(
        rows=[{
            "ref": f"asset:{asset.id}",
            "hostname": asset.hostname,
            "exposure_score": asset.exposure_score,
            "assessed_at": (
                asset.exposure_calculated_at.isoformat()
                if asset.exposure_calculated_at else None
            ),
            "breakdown": breakdown,
        }],
        refs={f"asset:{asset.id}", f"host:{asset.hostname.lower()}"},
        total_matching=1,
        note=(
            "The breakdown is the whole explanation of the score. State the "
            "contributors as given, including any factors marked unavailable."
        ),
    )


def _list_remediation_tasks(
    ctx: ToolContext,
    status: str | None = None,
    overdue_only: bool = False,
    limit: Any = None,
    **_: Any,
) -> ToolResult:
    from datetime import date

    cap = _row_cap(limit)
    stmt = select(RemediationTask).where(
        RemediationTask.organization_id == ctx.organization_id
    )
    if status:
        stmt = stmt.where(
            RemediationTask.status == _enum_arg(status, RemediationStatus, "status")
        )
    if overdue_only:
        stmt = stmt.where(
            RemediationTask.due_date < date.today(),
            RemediationTask.status.notin_([
                RemediationStatus.VERIFIED, RemediationStatus.CLOSED,
                RemediationStatus.CANCELLED,
            ]),
        )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    ordered = stmt.order_by(RemediationTask.due_date.asc().nullslast()).limit(cap)

    rows: list[dict] = []
    refs: set[str] = set()
    for task in ctx.db.execute(ordered).scalars():
        rows.append({
            "ref": f"remediation_task:{task.id}",
            "id": str(task.id),
            "title": task.title,
            "status": task.status.value,
            "priority": task.priority.value,
            "due_date": task.due_date.isoformat() if task.due_date else None,
            "finding_ref": f"finding:{task.finding_id}",
            "assigned": task.assigned_to_user_id is not None,
            "verified_by_scan": task.verified_by_scan_job_id is not None,
        })
        refs.add(f"remediation_task:{task.id}")
        refs.add(f"finding:{task.finding_id}")

    return ToolResult(
        rows=rows, refs=refs, total_matching=total, truncated=total > len(rows),
        note=(
            "A task in 'awaiting_verification' has been reported fixed but not "
            "yet confirmed by a rescan. Do not describe it as resolved."
        ),
    )


def _get_compliance_status(ctx: ToolContext, **_: Any) -> ToolResult:
    frameworks = ctx.db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.organization_id == ctx.organization_id
        )
    ).scalars().all()

    rows: list[dict] = []
    refs: set[str] = set()
    for framework in frameworks:
        latest = ctx.db.execute(
            select(ComplianceAssessment).where(
                ComplianceAssessment.framework_id == framework.id,
                ComplianceAssessment.organization_id == ctx.organization_id,
            ).order_by(ComplianceAssessment.created_at.desc()).limit(1)
        ).scalar_one_or_none()

        if latest is None:
            rows.append({
                "ref": f"compliance_framework:{framework.id}",
                "framework": framework.name,
                "assessed": False,
                "note": "Never assessed. There is no score to report for this framework.",
            })
        else:
            rows.append({
                "ref": f"compliance_assessment:{latest.id}",
                "framework": framework.name,
                "assessed": True,
                "assessed_at": latest.created_at.isoformat() if latest.created_at else None,
                "compliance_percent": latest.compliance_percent,
                "assessable_percent": latest.assessable_percent,
                "percent_note": (
                    "compliance_percent counts only controls that were actually "
                    "assessed. Controls requiring manual attestation are excluded "
                    "and are not passes."
                ),
            })
            refs.add(f"compliance_assessment:{latest.id}")
        refs.add(f"compliance_framework:{framework.id}")

    return ToolResult(rows=rows, refs=refs, total_matching=len(rows))


def _get_cve_intelligence(ctx: ToolContext, cve_id: str, **_: Any) -> ToolResult:
    identifier = str(cve_id).strip().upper()
    if not identifier.startswith("CVE-"):
        raise ToolError("cve_id must look like CVE-2024-3094")

    cve = ctx.db.execute(select(Cve).where(Cve.cve_id == identifier)).scalar_one_or_none()
    if cve is None:
        return ToolResult(
            note=(
                f"{identifier} is not in the local vulnerability intelligence store. "
                f"That means it has not been synchronised, not that it does not exist. "
                f"Do not describe its severity, impact or exploitability from memory."
            )
        )

    epss = ctx.db.execute(
        select(EpssScore).where(EpssScore.cve_id == identifier)
    ).scalar_one_or_none()
    kev = ctx.db.execute(
        select(KevEntry).where(KevEntry.cve_id == identifier)
    ).scalar_one_or_none()

    return ToolResult(
        rows=[{
            "ref": f"cve:{identifier}",
            "cve_id": identifier,
            "description": _excerpt(cve.description, 1200),
            "cvss_score": cve.cvss_v3_score,
            "cvss_vector": cve.cvss_v3_vector,
            "published": cve.published_at.isoformat() if cve.published_at else None,
            "epss_score": epss.score if epss else None,
            "epss_percentile": epss.percentile if epss else None,
            "known_exploited": kev is not None,
            "kev_due_date": (
                kev.due_date.isoformat() if kev is not None and kev.due_date else None
            ),
        }],
        refs={f"cve:{identifier}"},
        total_matching=1,
    )


def _list_recent_scans(ctx: ToolContext, limit: Any = None, **_: Any) -> ToolResult:
    cap = _row_cap(limit)
    stmt = select(ScanJob).where(
        ScanJob.organization_id == ctx.organization_id
    ).order_by(ScanJob.created_at.desc()).limit(cap)

    rows: list[dict] = []
    refs: set[str] = set()
    for job in ctx.db.execute(stmt).scalars():
        rows.append({
            "ref": f"scan_job:{job.id}",
            "id": str(job.id),
            "engine": job.engine,
            "target": job.target_cidr,
            "status": job.status.value,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "hosts_discovered": job.hosts_discovered,
            "findings_generated": job.findings_generated,
            "error_message": job.error_message,
        })
        refs.add(f"scan_job:{job.id}")

    return ToolResult(
        rows=rows, refs=refs, total_matching=len(rows),
        note=(
            "Coverage is limited to what these scans targeted. Anything outside "
            "their scope is unassessed, not clean."
        ),
    )


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

def _obj(properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


_LIMIT = {"type": "integer", "description": "Maximum rows to return.", "minimum": 1}

TOOLS: tuple[AgentTool, ...] = (
    AgentTool(
        name="count_findings",
        description=(
            "Count this organization's findings, grouped by severity, status or class. "
            "Use this before making any statement about how many issues exist."
        ),
        parameters=_obj({
            "group_by": {
                "type": "string",
                "enum": ["severity", "status", "finding_class"],
                "description": "Dimension to group the counts by.",
            }
        }),
        handler=_count_findings,
        required_permission=Permission.VIEW_FINDINGS,
    ),
    AgentTool(
        name="search_findings",
        description=(
            "List findings matching filters, highest risk first. Returns the record "
            "identifier for each one so it can be cited."
        ),
        parameters=_obj({
            "severity": {"type": "string",
                         "enum": [member.value for member in Severity]},
            "status": {"type": "string",
                       "enum": [member.value for member in FindingStatus]},
            "finding_class": {"type": "string",
                              "enum": [member.value for member in FindingClass]},
            "cve_id": {"type": "string", "description": "Exact CVE identifier."},
            "asset_id": {"type": "string", "description": "Restrict to one asset."},
            "known_exploited_only": {
                "type": "boolean",
                "description": "Only findings on the CISA Known Exploited list.",
            },
            "open_only": {
                "type": "boolean",
                "description": "Exclude remediated, false-positive and accepted findings.",
            },
            "limit": _LIMIT,
        }),
        handler=_search_findings,
        required_permission=Permission.VIEW_FINDINGS,
    ),
    AgentTool(
        name="get_finding",
        description=(
            "Full detail for one finding, including the verbatim scanner evidence "
            "and the recorded remediation guidance."
        ),
        parameters=_obj({"finding_id": {"type": "string"}}, ["finding_id"]),
        handler=_get_finding,
        required_permission=Permission.VIEW_FINDINGS,
    ),
    AgentTool(
        name="count_assets",
        description="Count assets in the inventory, grouped by type.",
        parameters=_obj({}),
        handler=_count_assets,
        required_permission=Permission.VIEW_ASSETS,
    ),
    AgentTool(
        name="search_assets",
        description="List assets matching filters, most exposed first.",
        parameters=_obj({
            "hostname_contains": {"type": "string"},
            "ip_address": {"type": "string"},
            "criticality": {"type": "string",
                            "enum": [member.value for member in Criticality]},
            "internet_facing_only": {"type": "boolean"},
            "order_by_exposure": {"type": "boolean"},
            "limit": _LIMIT,
        }),
        handler=_search_assets,
        required_permission=Permission.VIEW_ASSETS,
    ),
    AgentTool(
        name="get_asset",
        description=(
            "Full detail for one asset: services, installed software, how it was "
            "classified and how many open findings it carries."
        ),
        parameters=_obj({"asset_id": {"type": "string"}}, ["asset_id"]),
        handler=_get_asset,
        required_permission=Permission.VIEW_ASSETS,
    ),
    AgentTool(
        name="explain_asset_exposure",
        description=(
            "The contributor breakdown behind an asset's exposure score. Call this "
            "before explaining why any score is what it is."
        ),
        parameters=_obj({"asset_id": {"type": "string"}}, ["asset_id"]),
        handler=_explain_asset_exposure,
        required_permission=Permission.VIEW_ASSETS,
    ),
    AgentTool(
        name="list_remediation_tasks",
        description="List remediation tasks, soonest due first.",
        parameters=_obj({
            "status": {"type": "string",
                       "enum": [member.value for member in RemediationStatus]},
            "overdue_only": {"type": "boolean"},
            "limit": _LIMIT,
        }),
        handler=_list_remediation_tasks,
        required_permission=Permission.VIEW_FINDINGS,
    ),
    AgentTool(
        name="get_compliance_status",
        description=(
            "The latest assessment result for each compliance framework this "
            "organization has configured."
        ),
        parameters=_obj({}),
        handler=_get_compliance_status,
        required_permission=Permission.VIEW_COMPLIANCE,
    ),
    AgentTool(
        name="get_cve_intelligence",
        description=(
            "Look up one CVE in the locally synchronised intelligence store "
            "(NVD, EPSS, CISA KEV). Returns nothing if it has not been synced."
        ),
        parameters=_obj({"cve_id": {"type": "string"}}, ["cve_id"]),
        handler=_get_cve_intelligence,
        required_permission=Permission.VIEW_FINDINGS,
    ),
    AgentTool(
        name="list_recent_scans",
        description=(
            "Recent scan jobs and their outcomes. Use this to establish what has "
            "actually been assessed before commenting on coverage."
        ),
        parameters=_obj({"limit": _LIMIT}),
        handler=_list_recent_scans,
        required_permission=Permission.VIEW_FINDINGS,
    ),
)

TOOLS_BY_NAME: dict[str, AgentTool] = {tool.name: tool for tool in TOOLS}


def tools_for(ctx: ToolContext) -> list[AgentTool]:
    """
    The subset of retrievals this user is permitted to make.

    A user without VIEW_COMPLIANCE is not shown the compliance tool at all, so
    the model cannot reach data the operator could not reach themselves.
    """
    held = ctx.permissions
    return [tool for tool in TOOLS if tool.required_permission.value in held]


def run_tool(ctx: ToolContext, name: str, arguments: dict) -> ToolResult:
    tool = TOOLS_BY_NAME.get(name)
    if tool is None:
        raise ToolError(f"No such tool: {name}")
    if tool.required_permission.value not in ctx.permissions:
        raise ToolError(
            f"This account does not hold {tool.required_permission.value}, so "
            f"{name} is not available."
        )
    if not isinstance(arguments, dict):
        raise ToolError("Tool arguments must be an object.")
    return tool.handler(ctx, **arguments)
