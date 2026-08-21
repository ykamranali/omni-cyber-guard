"""
Exposure API.

Every score served here can be interrogated. `/exposure/assets/{id}` returns the
contributors that produced the number and the factors the model could not
compute, so the UI can show both what counted and what is missing.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset, Criticality
from app.models.finding import CLOSED_STATUSES, Finding, FindingClass, Severity
from app.models.user import User
from app.services.exposure_engine import (
    ExposureModel, assess_asset, recompute_organization_exposure, top_exposed_assets,
)
from app.services.exposure_snapshots import capture_snapshot, get_trend

router = APIRouter(prefix="/exposure", tags=["Exposure"])


@router.get("/overview")
def exposure_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    """
    Organization-level exposure posture.

    Every number here is a query. Where there is nothing to report, the field is
    null and `assessed` is false — so an unscanned estate reads as unassessed
    rather than as a clean bill of health.
    """
    org_id = current_user.organization_id

    total_assets = db.execute(
        select(func.count(Asset.id)).where(Asset.organization_id == org_id)
    ).scalar_one()
    assessed_assets = db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id, Asset.exposure_calculated_at.isnot(None)
        )
    ).scalar_one()
    average = db.execute(
        select(func.avg(Asset.exposure_score)).where(
            Asset.organization_id == org_id, Asset.exposure_score > 0
        )
    ).scalar_one()

    open_filter = [
        Finding.organization_id == org_id,
        Finding.status.notin_(list(CLOSED_STATUSES)),
    ]

    critical = db.execute(
        select(func.count(Finding.id)).where(*open_filter, Finding.severity == Severity.CRITICAL)
    ).scalar_one()
    known_exploited = db.execute(
        select(func.count(Finding.id)).where(*open_filter, Finding.is_known_exploited.is_(True))
    ).scalar_one()
    vulnerabilities = db.execute(
        select(func.count(Finding.id)).where(
            *open_filter, Finding.finding_class == FindingClass.VULNERABILITY
        )
    ).scalar_one()
    exposures = db.execute(
        select(func.count(Finding.id)).where(
            *open_filter, Finding.finding_class == FindingClass.EXPOSURE
        )
    ).scalar_one()
    internet_exposed = db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id, Asset.is_internet_facing.is_(True)
        )
    ).scalar_one()
    unassigned_criticality = db.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id, Asset.criticality == Criticality.UNASSIGNED
        )
    ).scalar_one()

    return {
        "assessed": assessed_assets > 0,
        "exposure_score": round(float(average), 1) if average is not None else None,
        "assets_total": total_assets,
        "assets_assessed": assessed_assets,
        "critical_findings": critical,
        "known_exploited_findings": known_exploited,
        "vulnerability_findings": vulnerabilities,
        "exposure_findings": exposures,
        "internet_exposed_assets": internet_exposed,
        # Surfaced because it bounds how meaningful the score is: criticality is
        # a weighted contributor, and an estate with none assigned is being
        # scored on technical signal alone.
        "assets_without_criticality": unassigned_criticality,
        "note": (
            None if assessed_assets else
            "No asset has been assessed yet. Run a scan to produce exposure scores — an "
            "empty result here means 'not assessed', not 'no exposure'."
        ),
    }


@router.get("/assets/{asset_id}")
def asset_exposure(
    asset_id: uuid.UUID,
    recompute: bool = Query(default=False),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    """The score for one asset, with the full contributor breakdown."""
    asset = db.execute(
        select(Asset).where(
            Asset.id == asset_id, Asset.organization_id == current_user.organization_id
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    if recompute or not asset.exposure_breakdown:
        assessment = assess_asset(db, asset)
        asset.exposure_score = assessment.score
        asset.exposure_breakdown = assessment.as_dict()
        asset.exposure_calculated_at = assessment.computed_at
        db.commit()
        breakdown = assessment.as_dict()
    else:
        breakdown = asset.exposure_breakdown

    return {
        "asset_id": str(asset.id),
        "hostname": asset.hostname,
        "ip_address": asset.ip_address,
        **breakdown,
    }


@router.get("/top-assets")
def top_assets(
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    assets = top_exposed_assets(db, current_user.organization_id, limit)
    return [
        {
            "id": str(asset.id),
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "asset_type": asset.asset_type.value,
            "criticality": asset.criticality.value,
            "is_internet_facing": asset.is_internet_facing,
            "exposure_score": asset.exposure_score,
            "band": (asset.exposure_breakdown or {}).get("band", "none"),
            "top_contributor": next(
                iter((asset.exposure_breakdown or {}).get("contributors", [])), None
            ),
        }
        for asset in assets
    ]


@router.get("/trend")
def exposure_trend(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    """
    Recorded history only. Days with no snapshot are absent rather than
    interpolated, so a gap in the chart reflects a gap in observation.
    """
    points = get_trend(db, current_user.organization_id, days)
    return {
        "points": points,
        "note": (
            None if points else
            "No exposure history has been recorded yet. A snapshot is captured daily, and "
            "the first one appears after the first assessment."
        ),
    }


@router.post("/recompute")
def recompute(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_FINDINGS)),
):
    """Rescore every asset now, and record today's snapshot."""
    result = recompute_organization_exposure(db, current_user.organization_id)
    capture_snapshot(db, current_user.organization_id)
    return result


@router.get("/model")
def get_exposure_model(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_FINDINGS)),
):
    """
    The weights in force, and the factors the model cannot yet compute.

    Published so the scoring is auditable rather than a black box.
    """
    from dataclasses import asdict

    from app.models.organization import Organization
    from app.services.exposure_engine import UNAVAILABLE_FACTORS

    organization = db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    ).scalar_one_or_none()
    model = ExposureModel.from_organization(organization)

    return {
        "weights": asdict(model),
        "maximum_points": model.maximum,
        "using_defaults": not (organization.exposure_model if organization else {}),
        "unavailable_factors": [factor.as_dict() for factor in UNAVAILABLE_FACTORS],
    }


@router.put("/model")
def update_exposure_model(
    weights: dict[str, float],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORG_SETTINGS)),
):
    """Override the exposure weights for this organization."""
    from dataclasses import asdict

    from app.models.organization import Organization
    from app.services.audit import log_action

    valid_keys = set(asdict(ExposureModel()))
    unknown = set(weights) - valid_keys
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown exposure factors: {', '.join(sorted(unknown))}. "
                   f"Valid factors: {', '.join(sorted(valid_keys))}.",
        )
    for key, value in weights.items():
        if not isinstance(value, (int, float)) or value < 0:
            raise HTTPException(status_code=400, detail=f"Weight for '{key}' must be zero or greater.")

    organization = db.execute(
        select(Organization).where(Organization.id == current_user.organization_id)
    ).scalar_one()
    organization.exposure_model = {key: float(value) for key, value in weights.items()}
    db.commit()

    log_action(
        db, "update_exposure_model", "organization", current_user.organization_id,
        current_user.id, str(organization.id), metadata={"weights": organization.exposure_model},
    )

    # Rescore immediately: leaving old scores in place under new weights would
    # mean the published model and the displayed numbers disagreed.
    return recompute_organization_exposure(db, current_user.organization_id)
