"""
Compliance evaluation.

Every control result is derived from a query over data the platform holds. The
rule the engine is built around:

    **Absence of evidence is never a pass.**

A control the platform cannot evaluate — because the check needs data that has
not been collected, or because no asset is in scope — returns NOT_ASSESSED, with
a summary saying exactly what is missing. NOT_ASSESSED is excluded from the
compliance percentage rather than counted as compliant, and the assessment
reports separately what share of the framework could be assessed at all.

A 100% compliance figure over 10% coverage and one over 90% coverage are very
different claims, and both numbers are always shown.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, Criticality
from app.models.asset_detail import AssetService
from app.models.compliance import (
    CheckType, ComplianceAssessment, ComplianceControl, ComplianceException,
    ComplianceFramework, ComplianceRequirement, ComplianceResult, ControlAttestation,
    ControlResult,
)
from app.models.finding import CLOSED_STATUSES, Finding, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class Evaluation:
    """The outcome of one control check."""

    result: ControlResult
    summary: str
    evidence: dict = field(default_factory=dict)
    assets_in_scope: int = 0
    assets_failing: int = 0


def _at_or_above(severity: Severity) -> list[Severity]:
    return SEVERITY_ORDER[: SEVERITY_ORDER.index(severity) + 1]


def _scoped_assets(db: Session, organization_id: uuid.UUID, parameters: dict) -> list[Asset]:
    """
    Assets a control applies to.

    Scope narrows by criticality, internet exposure or tag where the control
    says so. Decommissioned assets are always excluded — a control cannot fail
    on a machine that no longer exists.
    """
    query = select(Asset).where(
        Asset.organization_id == organization_id,
        Asset.status != AssetStatus.DECOMMISSIONED,
    )

    if parameters.get("internet_facing_only"):
        query = query.where(Asset.is_internet_facing.is_(True))
    if parameters.get("production_only"):
        query = query.where(Asset.is_production.is_(True))

    minimum = parameters.get("minimum_criticality")
    if minimum:
        ranking = [Criticality.CRITICAL, Criticality.HIGH, Criticality.MEDIUM, Criticality.LOW]
        try:
            allowed = ranking[: ranking.index(Criticality(minimum)) + 1]
        except (ValueError, IndexError):
            allowed = ranking
        query = query.where(Asset.criticality.in_(allowed))

    return db.execute(query).scalars().all()


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_no_exposed_port(db, organization_id, control, assets) -> Evaluation:
    ports = [int(port) for port in control.check_parameters.get("ports", [])]
    if not ports:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            "This control lists no ports to check, so nothing was evaluated.",
        )
    if not assets:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            "No asset is in scope for this control. Run a discovery scan first.",
        )

    asset_ids = [asset.id for asset in assets]
    rows = db.execute(
        select(AssetService.asset_id, AssetService.port, AssetService.protocol)
        .where(
            AssetService.asset_id.in_(asset_ids),
            AssetService.port.in_(ports),
            AssetService.state == "open",
        )
    ).all()

    # A control cannot pass on assets nothing has ever looked at.
    scanned = db.execute(
        select(func.count(func.distinct(AssetService.asset_id)))
        .where(AssetService.asset_id.in_(asset_ids))
    ).scalar_one()
    if scanned == 0:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            f"No port data exists for the {len(assets)} asset(s) in scope. "
            f"Run a port and service scan to evaluate this control.",
            assets_in_scope=len(assets),
        )

    by_asset: dict[uuid.UUID, list[str]] = {}
    for asset_id, port, protocol in rows:
        by_asset.setdefault(asset_id, []).append(f"{protocol}/{port}")

    hostnames = {asset.id: asset.hostname for asset in assets}

    if by_asset:
        return Evaluation(
            ControlResult.FAIL,
            f"{len(by_asset)} of {scanned} scanned asset(s) expose "
            f"{', '.join(str(port) for port in sorted(ports))}.",
            evidence={
                "prohibited_ports": sorted(ports),
                "failing_assets": [
                    {"hostname": hostnames.get(asset_id, str(asset_id)), "open": sorted(found)}
                    for asset_id, found in list(by_asset.items())[:50]
                ],
                "assets_scanned": scanned,
            },
            assets_in_scope=len(assets),
            assets_failing=len(by_asset),
        )

    return Evaluation(
        ControlResult.PASS,
        f"None of the {scanned} scanned asset(s) expose "
        f"{', '.join(str(port) for port in sorted(ports))}.",
        evidence={"prohibited_ports": sorted(ports), "assets_scanned": scanned},
        assets_in_scope=len(assets),
    )


def _check_no_open_finding(db, organization_id, control, assets) -> Evaluation:
    parameters = control.check_parameters
    source = parameters.get("source")
    identifiers = parameters.get("check_ids") or []

    if not identifiers:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            "This control names no checks to look for, so nothing was evaluated.",
        )

    # The check identifier is embedded in the finding fingerprint, so match on
    # the source plus the title text the adapter produced.
    conditions = [
        Finding.organization_id == organization_id,
        Finding.status.notin_(list(CLOSED_STATUSES)),
    ]
    if source:
        conditions.append(Finding.source == source)

    matches = []
    for finding in db.execute(select(Finding).where(*conditions)).scalars():
        haystack = f"{finding.title} {finding.evidence}".lower()
        if any(identifier.lower() in haystack for identifier in identifiers):
            matches.append(finding)

    # Whether the producing source has run at all decides pass versus
    # not-assessed. Nothing found by a scanner that never ran is not a pass.
    source_ran = db.execute(
        select(func.count(Finding.id)).where(
            Finding.organization_id == organization_id,
            *( [Finding.source == source] if source else [] ),
        )
    ).scalar_one()

    if matches:
        return Evaluation(
            ControlResult.FAIL,
            f"{len(matches)} open finding(s) match this control.",
            evidence={
                "check_ids": identifiers,
                "source": source,
                "findings": [
                    {"id": str(f.id), "title": f.title, "severity": f.severity.value}
                    for f in matches[:25]
                ],
            },
            assets_in_scope=len(assets),
            assets_failing=len({f.asset_id for f in matches}),
        )

    if source_ran == 0:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            f"No findings from '{source or 'any source'}' exist yet, so this control cannot be "
            f"evaluated. Nothing found by a check that never ran is not a pass.",
            assets_in_scope=len(assets),
        )

    return Evaluation(
        ControlResult.PASS,
        f"No open findings match this control across {source_ran} recorded finding(s) "
        f"from '{source or 'any source'}'.",
        evidence={"check_ids": identifiers, "source": source},
        assets_in_scope=len(assets),
    )


def _check_remediation_within_sla(db, organization_id, control, assets) -> Evaluation:
    parameters = control.check_parameters
    try:
        severity = Severity(parameters.get("severity", "critical"))
    except ValueError:
        severity = Severity.CRITICAL
    max_age_days = int(parameters.get("max_age_days", 30))

    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    overdue = db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
            Finding.severity.in_(_at_or_above(severity)),
            Finding.first_seen < cutoff,
        )
    ).scalars().all()

    total_at_severity = db.execute(
        select(func.count(Finding.id)).where(
            Finding.organization_id == organization_id,
            Finding.severity.in_(_at_or_above(severity)),
        )
    ).scalar_one()

    if total_at_severity == 0:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            f"No {severity.value}-or-above findings have ever been recorded, so remediation "
            f"timeliness cannot be measured. This is not evidence of compliance.",
            assets_in_scope=len(assets),
        )

    if overdue:
        return Evaluation(
            ControlResult.FAIL,
            f"{len(overdue)} {severity.value}-or-above finding(s) have been open longer "
            f"than {max_age_days} days.",
            evidence={
                "max_age_days": max_age_days,
                "severity": severity.value,
                "overdue": [
                    {
                        "id": str(finding.id),
                        "title": finding.title,
                        "days_open": (datetime.now(timezone.utc) - finding.first_seen).days,
                    }
                    for finding in overdue[:25]
                ],
            },
            assets_in_scope=len(assets),
            assets_failing=len({finding.asset_id for finding in overdue}),
        )

    return Evaluation(
        ControlResult.PASS,
        f"No {severity.value}-or-above finding has been open longer than {max_age_days} days.",
        evidence={"max_age_days": max_age_days, "severity": severity.value},
        assets_in_scope=len(assets),
    )


def _check_asset_attribute_required(db, organization_id, control, assets) -> Evaluation:
    attribute = control.check_parameters.get("attribute", "criticality")

    if not assets:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            "No asset is in scope for this control.",
        )

    def is_missing(asset: Asset) -> bool:
        value = getattr(asset, attribute, None)
        if value is None:
            return True
        if hasattr(value, "value"):
            return value.value == "unassigned"
        return str(value).strip() == ""

    failing = [asset for asset in assets if is_missing(asset)]

    if failing:
        return Evaluation(
            ControlResult.FAIL,
            f"{len(failing)} of {len(assets)} asset(s) have no '{attribute}' recorded.",
            evidence={
                "attribute": attribute,
                "failing_assets": [asset.hostname for asset in failing[:50]],
            },
            assets_in_scope=len(assets),
            assets_failing=len(failing),
        )

    return Evaluation(
        ControlResult.PASS,
        f"All {len(assets)} asset(s) in scope have '{attribute}' recorded.",
        evidence={"attribute": attribute},
        assets_in_scope=len(assets),
    )


def _check_assessment_freshness(db, organization_id, control, assets) -> Evaluation:
    max_age_days = int(control.check_parameters.get("max_age_days", 30))
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

    if not assets:
        return Evaluation(ControlResult.NOT_ASSESSED, "No asset is in scope for this control.")

    stale = [asset for asset in assets if asset.last_seen is None or asset.last_seen < cutoff]

    if stale:
        return Evaluation(
            ControlResult.FAIL,
            f"{len(stale)} of {len(assets)} asset(s) have not been assessed in the last "
            f"{max_age_days} days.",
            evidence={
                "max_age_days": max_age_days,
                "stale_assets": [
                    {
                        "hostname": asset.hostname,
                        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
                    }
                    for asset in stale[:50]
                ],
            },
            assets_in_scope=len(assets),
            assets_failing=len(stale),
        )

    return Evaluation(
        ControlResult.PASS,
        f"All {len(assets)} asset(s) were assessed within the last {max_age_days} days.",
        evidence={"max_age_days": max_age_days},
        assets_in_scope=len(assets),
    )


def _check_no_exposed_severity(db, organization_id, control, assets) -> Evaluation:
    try:
        severity = Severity(control.check_parameters.get("severity", "high"))
    except ValueError:
        severity = Severity.HIGH

    exposed = [asset for asset in assets if asset.is_internet_facing]
    if not exposed:
        return Evaluation(
            ControlResult.NOT_APPLICABLE,
            "No asset is declared internet facing, so this control does not apply. "
            "Declare your internet-facing networks to make it assessable.",
            assets_in_scope=0,
        )

    findings = db.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.asset_id.in_([asset.id for asset in exposed]),
            Finding.status.notin_(list(CLOSED_STATUSES)),
            Finding.severity.in_(_at_or_above(severity)),
        )
    ).scalars().all()

    if findings:
        return Evaluation(
            ControlResult.FAIL,
            f"{len(findings)} open {severity.value}-or-above finding(s) on "
            f"{len({f.asset_id for f in findings})} internet-facing asset(s).",
            evidence={
                "severity": severity.value,
                "findings": [
                    {"id": str(f.id), "title": f.title, "severity": f.severity.value}
                    for f in findings[:25]
                ],
            },
            assets_in_scope=len(exposed),
            assets_failing=len({f.asset_id for f in findings}),
        )

    return Evaluation(
        ControlResult.PASS,
        f"No open {severity.value}-or-above findings on the {len(exposed)} internet-facing asset(s).",
        evidence={"severity": severity.value},
        assets_in_scope=len(exposed),
    )


def _check_manual(db, organization_id, control, assets) -> Evaluation:
    """
    A control only a person can answer.

    An attestation expires. A statement made two years ago about something
    nobody has looked at since is not evidence of current compliance.
    """
    attestation = db.execute(
        select(ControlAttestation)
        .where(
            ControlAttestation.organization_id == organization_id,
            ControlAttestation.control_id == control.id,
        )
        .order_by(ControlAttestation.attested_at.desc())
        .limit(1)
    ).scalar_one_or_none()

    if attestation is None:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            "This control cannot be evaluated automatically and has no attestation on record.",
        )

    now = datetime.now(timezone.utc)
    if attestation.valid_until < now:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            f"The attestation for this control expired on "
            f"{attestation.valid_until.date().isoformat()} and needs renewing.",
            evidence={"expired_attestation": attestation.statement[:500]},
        )

    return Evaluation(
        ControlResult.PASS if attestation.is_met else ControlResult.FAIL,
        f"Attested {attestation.attested_at.date().isoformat()}, valid until "
        f"{attestation.valid_until.date().isoformat()}.",
        evidence={
            "statement": attestation.statement[:1000],
            "evidence_reference": attestation.evidence_reference[:500],
        },
    )


CHECK_HANDLERS = {
    CheckType.NO_EXPOSED_PORT: _check_no_exposed_port,
    CheckType.NO_OPEN_FINDING: _check_no_open_finding,
    CheckType.REMEDIATION_WITHIN_SLA: _check_remediation_within_sla,
    CheckType.ASSET_ATTRIBUTE_REQUIRED: _check_asset_attribute_required,
    CheckType.ASSESSMENT_FRESHNESS: _check_assessment_freshness,
    CheckType.NO_EXPOSED_SEVERITY: _check_no_exposed_severity,
    CheckType.MANUAL: _check_manual,
}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def evaluate_control(
    db: Session, organization_id: uuid.UUID, control: ComplianceControl
) -> Evaluation:
    """Evaluate one control, honouring any active exception."""
    exception = db.execute(
        select(ComplianceException).where(
            ComplianceException.organization_id == organization_id,
            ComplianceException.control_id == control.id,
            ComplianceException.is_active.is_(True),
            ComplianceException.expires_at > datetime.now(timezone.utc),
        )
    ).scalar_one_or_none()

    if exception is not None:
        return Evaluation(
            ControlResult.EXCEPTION,
            f"An approved exception is in force until "
            f"{exception.expires_at.date().isoformat()}: {exception.reason[:200]}",
            evidence={
                "reason": exception.reason[:1000],
                "compensating_controls": exception.compensating_controls[:1000],
                "expires_at": exception.expires_at.isoformat(),
            },
        )

    handler = CHECK_HANDLERS.get(control.check_type)
    if handler is None:
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            f"No handler exists for check type '{control.check_type.value}'.",
        )

    assets = _scoped_assets(db, organization_id, control.check_parameters or {})
    try:
        return handler(db, organization_id, control, assets)
    except Exception as exc:  # noqa: BLE001
        # A check that errored has not passed. Reporting the error is the only
        # honest outcome.
        return Evaluation(
            ControlResult.NOT_ASSESSED,
            f"This control could not be evaluated: {type(exc).__name__}: {exc}",
        )


def assess_framework(
    db: Session, organization_id: uuid.UUID, framework: ComplianceFramework
) -> ComplianceAssessment:
    """
    Evaluate every control in a framework and record the results.

    Two percentages are produced, and both matter:

    * `compliance_percent` — passed / (passed + failed). NOT_ASSESSED is
      excluded, never counted as compliant.
    * `assessable_percent` — how much of the framework could be evaluated at
      all. 100% compliance over 10% coverage is a very different claim from
      100% over 90%.
    """
    started = datetime.now(timezone.utc)

    assessment = ComplianceAssessment(
        organization_id=organization_id,
        framework_id=framework.id,
        started_at=started,
    )
    db.add(assessment)
    db.flush()

    controls = db.execute(
        select(ComplianceControl)
        .join(ComplianceRequirement, ComplianceControl.requirement_id == ComplianceRequirement.id)
        .where(ComplianceRequirement.framework_id == framework.id)
    ).scalars().all()

    tally = {result: 0 for result in ControlResult}

    for control in controls:
        evaluation = evaluate_control(db, organization_id, control)
        tally[evaluation.result] += 1

        db.add(ComplianceResult(
            organization_id=organization_id,
            assessment_id=assessment.id,
            control_id=control.id,
            result=evaluation.result,
            summary=evaluation.summary,
            evidence=evaluation.evidence,
            assets_in_scope=evaluation.assets_in_scope,
            assets_failing=evaluation.assets_failing,
            assessed_at=started,
        ))

    passed = tally[ControlResult.PASS]
    failed = tally[ControlResult.FAIL]
    conclusive = passed + failed

    assessment.completed_at = datetime.now(timezone.utc)
    assessment.controls_total = len(controls)
    assessment.controls_passed = passed
    assessment.controls_failed = failed
    assessment.controls_not_assessed = tally[ControlResult.NOT_ASSESSED]
    assessment.controls_not_applicable = tally[ControlResult.NOT_APPLICABLE]
    assessment.controls_exception = tally[ControlResult.EXCEPTION]
    assessment.compliance_percent = round(passed / conclusive * 100, 1) if conclusive else None
    assessment.assessable_percent = (
        round(conclusive / len(controls) * 100, 1) if controls else 0.0
    )

    framework.last_assessed_at = assessment.completed_at
    db.add(framework)
    db.commit()

    return assessment
