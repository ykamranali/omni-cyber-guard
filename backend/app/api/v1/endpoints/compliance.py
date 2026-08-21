"""
Compliance API.

Two numbers are always returned together, and the pairing is the point:

* `compliance_percent` — passed / (passed + failed). Controls the platform could
  not evaluate are excluded, never counted as compliant.
* `assessable_percent` — how much of the framework could be evaluated at all.

100% compliance over 10% coverage and 100% over 90% are very different claims.
Publishing only the first would be the most consequential dishonesty this
module could commit.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.compliance import (
    ComplianceAssessment, ComplianceControl, ComplianceException, ComplianceFramework,
    ComplianceRequirement, ComplianceResult, ControlAttestation, ControlResult,
)
from app.models.user import User
from app.services.audit import log_action
from app.services.compliance.engine import assess_framework
from app.services.compliance.packs import available_packs, install_pack

router = APIRouter(prefix="/compliance", tags=["Compliance"])


class AttestationRequest(BaseModel):
    statement: str = Field(min_length=1, max_length=4000)
    evidence_reference: str = ""
    is_met: bool = True
    #: How long the attestation remains valid. A statement made two years ago
    #: about something nobody has looked at since is not current evidence.
    valid_for_days: int = Field(default=365, ge=1, le=1095)


class ExceptionRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=4000)
    compensating_controls: str = ""
    expires_in_days: int = Field(default=90, ge=1, le=1095)


@router.get("/packs")
def list_content_packs(
    current_user: User = Depends(require_permission(Permission.VIEW_COMPLIANCE)),
):
    """
    Installable control sets.

    `manual_control_count` is published so it is clear up front how much of a
    pack can be automated. A pack that is 40% manual will never report a high
    assessable percentage until attestations are recorded.
    """
    return {
        "packs": available_packs(),
        "note": (
            "These are original control sets mapped to signals this platform collects. "
            "They are inspired by the structure of published frameworks but are not those "
            "frameworks' control text, and installing one does not certify an organization "
            "against any standard."
        ),
    }


@router.post("/packs/{slug}/install")
def install_content_pack(
    slug: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
):
    try:
        framework = install_pack(db, current_user.organization_id, slug)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    log_action(
        db, "install_compliance_pack", "compliance_framework", current_user.organization_id,
        current_user.id, str(framework.id), metadata={"slug": slug},
    )
    return {"installed": True, "framework_id": str(framework.id), "name": framework.name}


@router.get("/frameworks")
def list_frameworks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_COMPLIANCE)),
):
    frameworks = db.execute(
        select(ComplianceFramework)
        .where(ComplianceFramework.organization_id == current_user.organization_id)
        .order_by(ComplianceFramework.name)
    ).scalars().all()

    payload = []
    for framework in frameworks:
        latest = _latest_assessment(db, framework.id)
        control_count = _control_count(db, framework.id)
        payload.append({
            "id": str(framework.id),
            "slug": framework.slug,
            "name": framework.name,
            "version": framework.version,
            "description": framework.description,
            "source": framework.source,
            "control_count": control_count,
            "last_assessed_at": framework.last_assessed_at.isoformat() if framework.last_assessed_at else None,
            "assessment": _serialize_assessment(latest) if latest else None,
            "note": (
                None if latest else
                "This framework has never been assessed. Run an assessment to produce results — "
                "an unassessed framework is not a compliant one."
            ),
        })
    return {"frameworks": payload}


@router.post("/frameworks/{framework_id}/assess")
def run_assessment(
    framework_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
):
    framework = _get_framework(db, framework_id, current_user)
    assessment = assess_framework(db, current_user.organization_id, framework)

    log_action(
        db, "run_compliance_assessment", "compliance_framework", current_user.organization_id,
        current_user.id, str(framework.id),
        metadata={
            "compliance_percent": assessment.compliance_percent,
            "assessable_percent": assessment.assessable_percent,
        },
    )
    return _serialize_assessment(assessment)


@router.get("/frameworks/{framework_id}/results")
def framework_results(
    framework_id: uuid.UUID,
    result: ControlResult | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_COMPLIANCE)),
):
    """The most recent assessment, control by control, with the evidence."""
    framework = _get_framework(db, framework_id, current_user)
    assessment = _latest_assessment(db, framework.id)

    if assessment is None:
        return {
            "framework": {"id": str(framework.id), "name": framework.name},
            "assessment": None,
            "requirements": [],
            "note": "This framework has not been assessed yet.",
        }

    requirements = db.execute(
        select(ComplianceRequirement)
        .where(ComplianceRequirement.framework_id == framework.id)
        .order_by(ComplianceRequirement.display_order, ComplianceRequirement.code)
    ).scalars().all()

    results_by_control = {
        row.control_id: row
        for row in db.execute(
            select(ComplianceResult).where(ComplianceResult.assessment_id == assessment.id)
        ).scalars()
    }

    payload = []
    for requirement in requirements:
        controls = db.execute(
            select(ComplianceControl)
            .where(ComplianceControl.requirement_id == requirement.id)
            .order_by(ComplianceControl.code)
        ).scalars().all()

        control_payload = []
        for control in controls:
            record = results_by_control.get(control.id)
            if result and (record is None or record.result != result):
                continue
            control_payload.append({
                "id": str(control.id),
                "code": control.code,
                "title": control.title,
                "description": control.description,
                "guidance": control.guidance,
                "check_type": control.check_type.value,
                "check_parameters": control.check_parameters or {},
                "result": record.result.value if record else "not_assessed",
                "summary": record.summary if record else "",
                "evidence": record.evidence if record else {},
                "assets_in_scope": record.assets_in_scope if record else 0,
                "assets_failing": record.assets_failing if record else 0,
            })

        if control_payload:
            payload.append({
                "id": str(requirement.id),
                "code": requirement.code,
                "title": requirement.title,
                "description": requirement.description,
                "controls": control_payload,
            })

    return {
        "framework": {
            "id": str(framework.id),
            "name": framework.name,
            "version": framework.version,
            "source": framework.source,
        },
        "assessment": _serialize_assessment(assessment),
        "requirements": payload,
    }


@router.post("/controls/{control_id}/attest")
def attest_control(
    control_id: uuid.UUID,
    payload: AttestationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
):
    """
    Record an operator's statement for a control the platform cannot evaluate.

    The attestation expires. Renewal is deliberate friction: the alternative is
    a checklist that stays green because somebody ticked it once.
    """
    control = _get_control(db, control_id, current_user)

    now = datetime.now(timezone.utc)
    attestation = ControlAttestation(
        organization_id=current_user.organization_id,
        control_id=control.id,
        statement=payload.statement,
        evidence_reference=payload.evidence_reference,
        attested_by_user_id=current_user.id,
        attested_at=now,
        valid_until=now + timedelta(days=payload.valid_for_days),
        is_met=payload.is_met,
    )
    db.add(attestation)
    db.commit()

    log_action(
        db, "attest_control", "compliance_control", current_user.organization_id,
        current_user.id, str(control.id),
        metadata={"is_met": payload.is_met, "valid_until": attestation.valid_until.isoformat()},
    )
    return {
        "recorded": True,
        "valid_until": attestation.valid_until.isoformat(),
        "note": "Re-run the assessment to see this reflected in the results.",
    }


@router.post("/controls/{control_id}/exception")
def create_exception(
    control_id: uuid.UUID,
    payload: ExceptionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_COMPLIANCE)),
):
    """Record an approved deviation from a control, with an expiry."""
    control = _get_control(db, control_id, current_user)

    now = datetime.now(timezone.utc)
    exception = ComplianceException(
        organization_id=current_user.organization_id,
        control_id=control.id,
        reason=payload.reason,
        compensating_controls=payload.compensating_controls,
        approved_by_user_id=current_user.id,
        approved_at=now,
        expires_at=now + timedelta(days=payload.expires_in_days),
    )
    db.add(exception)
    db.commit()

    log_action(
        db, "create_compliance_exception", "compliance_control", current_user.organization_id,
        current_user.id, str(control.id),
        metadata={"expires_at": exception.expires_at.isoformat(), "reason": payload.reason[:500]},
    )
    return {
        "recorded": True,
        "expires_at": exception.expires_at.isoformat(),
        # Named distinctly in every report; an exception is not a pass.
        "note": "This control will report as EXCEPTION until the expiry date, not as a pass.",
    }


# ---------------------------------------------------------------- helpers

def _get_framework(db: Session, framework_id: uuid.UUID, current_user: User) -> ComplianceFramework:
    framework = db.execute(
        select(ComplianceFramework).where(
            ComplianceFramework.id == framework_id,
            ComplianceFramework.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if framework is None:
        raise HTTPException(status_code=404, detail="Framework not found")
    return framework


def _get_control(db: Session, control_id: uuid.UUID, current_user: User) -> ComplianceControl:
    control = db.execute(
        select(ComplianceControl)
        .join(ComplianceRequirement, ComplianceControl.requirement_id == ComplianceRequirement.id)
        .join(ComplianceFramework, ComplianceRequirement.framework_id == ComplianceFramework.id)
        .where(
            ComplianceControl.id == control_id,
            ComplianceFramework.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if control is None:
        raise HTTPException(status_code=404, detail="Control not found")
    return control


def _latest_assessment(db: Session, framework_id: uuid.UUID) -> ComplianceAssessment | None:
    return db.execute(
        select(ComplianceAssessment)
        .where(ComplianceAssessment.framework_id == framework_id)
        .order_by(ComplianceAssessment.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _control_count(db: Session, framework_id: uuid.UUID) -> int:
    from sqlalchemy import func

    return db.execute(
        select(func.count(ComplianceControl.id))
        .join(ComplianceRequirement, ComplianceControl.requirement_id == ComplianceRequirement.id)
        .where(ComplianceRequirement.framework_id == framework_id)
    ).scalar_one()


def _serialize_assessment(assessment: ComplianceAssessment) -> dict:
    return {
        "id": str(assessment.id),
        "started_at": assessment.started_at.isoformat(),
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
        "controls_total": assessment.controls_total,
        "controls_passed": assessment.controls_passed,
        "controls_failed": assessment.controls_failed,
        "controls_not_assessed": assessment.controls_not_assessed,
        "controls_not_applicable": assessment.controls_not_applicable,
        "controls_exception": assessment.controls_exception,
        "compliance_percent": assessment.compliance_percent,
        "assessable_percent": assessment.assessable_percent,
        # Published alongside the percentage so it is never read alone.
        "interpretation": (
            f"{assessment.compliance_percent}% of the {assessment.controls_passed + assessment.controls_failed} "
            f"control(s) that could be evaluated are passing. "
            f"{assessment.controls_not_assessed} control(s) could not be evaluated and are "
            f"excluded from that figure — they are not counted as compliant."
            if assessment.compliance_percent is not None
            else "No control could be conclusively evaluated, so no compliance figure can be stated."
        ),
    }
