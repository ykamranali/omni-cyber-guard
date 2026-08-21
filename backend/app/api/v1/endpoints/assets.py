import csv
import io
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from sqlalchemy import func, select

from app.models.asset import Asset, AssetStatus, AssetType, Criticality
from app.models.asset_tag import AssetTag
from app.models.finding import CLOSED_STATUSES, Finding, Severity
from app.models.user import User
from app.schemas.asset import (
    AssetCreate, AssetDetailOut, AssetOut, AssetTagAssignment, AssetTagCreate,
    AssetTagOut, AssetUpdate,
)
from app.services.audit import log_action

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(
    search: str | None = Query(default=None),
    asset_type: AssetType | None = Query(default=None),
    status_filter: AssetStatus | None = Query(default=None, alias="status"),
    site: str | None = Query(default=None),
    site_id: uuid.UUID | None = Query(default=None),
    network_id: uuid.UUID | None = Query(default=None),
    criticality: Criticality | None = Query(default=None),
    internet_facing: bool | None = Query(default=None),
    tag: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    query = db.query(Asset).filter(Asset.organization_id == current_user.organization_id)
    if search:
        like = f"%{search}%"
        query = query.filter(
            (Asset.hostname.ilike(like)) | (Asset.ip_address.ilike(like)) | (Asset.vendor.ilike(like))
        )
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if status_filter:
        query = query.filter(Asset.status == status_filter)
    if site:
        query = query.filter(Asset.site == site)
    if site_id:
        query = query.filter(Asset.site_id == site_id)
    if network_id:
        query = query.filter(Asset.network_id == network_id)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if internet_facing is not None:
        query = query.filter(Asset.is_internet_facing == internet_facing)
    if tag:
        query = query.join(Asset.tag_links).filter(AssetTag.name == tag)
    if scan_id:
        try:
            query = query.filter(Asset.scan_job_id == uuid.UUID(scan_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan_id format")

    # Paginated by default. An estate of 100,000 assets must not be serialised
    # into one response.
    return query.order_by(Asset.hostname).offset(offset).limit(limit).all()


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    asset = Asset(organization_id=current_user.organization_id, **payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    log_action(db, "create", "asset", current_user.organization_id, current_user.id, str(asset.id))
    return asset


@router.get("/tags", response_model=list[AssetTagOut])
def list_tags(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    return db.execute(
        select(AssetTag)
        .where(AssetTag.organization_id == current_user.organization_id)
        .order_by(AssetTag.name)
    ).scalars().all()


@router.post("/tags", response_model=AssetTagOut, status_code=201)
def create_tag(
    payload: AssetTagCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    existing = db.execute(
        select(AssetTag).where(
            AssetTag.organization_id == current_user.organization_id,
            AssetTag.name == payload.name,
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail=f"A tag named '{payload.name}' already exists.")

    tag = AssetTag(organization_id=current_user.organization_id, **payload.model_dump())
    db.add(tag)
    db.commit()
    db.refresh(tag)
    log_action(db, "create", "asset_tag", current_user.organization_id, current_user.id, str(tag.id))
    return tag


@router.delete("/tags/{tag_id}", status_code=204)
def delete_tag(
    tag_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    tag = db.execute(
        select(AssetTag).where(
            AssetTag.id == tag_id, AssetTag.organization_id == current_user.organization_id
        )
    ).scalar_one_or_none()
    if tag is None:
        raise HTTPException(status_code=404, detail="Tag not found")
    db.delete(tag)
    db.commit()
    log_action(db, "delete", "asset_tag", current_user.organization_id, current_user.id, str(tag_id))


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.organization_id == current_user.organization_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.organization_id == current_user.organization_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    db.commit()
    db.refresh(asset)
    log_action(db, "update", "asset", current_user.organization_id, current_user.id, str(asset.id))
    return asset


@router.delete("/bulk", status_code=204)
def delete_assets_bulk(
    asset_ids: list[uuid.UUID],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    assets = (
        db.query(Asset)
        .filter(Asset.id.in_(asset_ids), Asset.organization_id == current_user.organization_id)
        .all()
    )
    for asset in assets:
        db.delete(asset)
        log_action(db, "delete", "asset", current_user.organization_id, current_user.id, str(asset.id))
    db.commit()

@router.delete("/{asset_id}", status_code=204)
def delete_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.organization_id == current_user.organization_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    log_action(db, "delete", "asset", current_user.organization_id, current_user.id, str(asset_id))


@router.get("/{asset_id}/detail", response_model=AssetDetailOut)
def get_asset_detail(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    """
    The full asset record: interfaces, services, software, tags and finding
    counts, all read from the database rather than reconstructed in the UI.
    """
    asset = _get_asset(db, asset_id, current_user)

    open_count = db.execute(
        select(func.count(Finding.id)).where(
            Finding.asset_id == asset.id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
        )
    ).scalar_one()
    critical_count = db.execute(
        select(func.count(Finding.id)).where(
            Finding.asset_id == asset.id,
            Finding.status.notin_(list(CLOSED_STATUSES)),
            Finding.severity == Severity.CRITICAL,
        )
    ).scalar_one()

    detail = AssetDetailOut.model_validate(asset)
    detail.open_finding_count = open_count
    detail.critical_finding_count = critical_count
    return detail


@router.put("/{asset_id}/tags", response_model=AssetDetailOut)
def set_asset_tags(
    asset_id: uuid.UUID,
    payload: AssetTagAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    asset = _get_asset(db, asset_id, current_user)
    tags = db.execute(
        select(AssetTag).where(
            AssetTag.id.in_(payload.tag_ids),
            AssetTag.organization_id == current_user.organization_id,
        )
    ).scalars().all()

    if len(tags) != len(set(payload.tag_ids)):
        raise HTTPException(status_code=400, detail="One or more tags do not exist in this organization.")

    asset.tag_links = list(tags)
    db.commit()
    db.refresh(asset)
    log_action(
        db, "set_tags", "asset", current_user.organization_id, current_user.id, str(asset.id),
        metadata={"tags": [tag.name for tag in tags]},
    )
    return AssetDetailOut.model_validate(asset)


def _get_asset(db: Session, asset_id: uuid.UUID, current_user: User) -> Asset:
    asset = db.execute(
        select(Asset).where(
            Asset.id == asset_id, Asset.organization_id == current_user.organization_id
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/export/csv")
def export_assets_csv(
    scan_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    query = db.query(Asset).filter(Asset.organization_id == current_user.organization_id)
    if scan_id:
        try:
            query = query.filter(Asset.scan_job_id == uuid.UUID(scan_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan_id format")
    assets = query.all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "hostname", "ip_address", "mac_address", "asset_type", "classification_confidence",
        "status", "operating_system", "vendor", "criticality", "data_sensitivity",
        "internet_facing", "production", "site", "department", "risk_score",
        "first_seen", "last_seen",
    ])
    for a in assets:
        writer.writerow([
            a.hostname, a.ip_address, a.mac_address, a.asset_type.value,
            a.fingerprint_confidence, a.status.value, a.operating_system, a.vendor,
            a.criticality.value, a.data_sensitivity.value,
            a.is_internet_facing, a.is_production, a.site, a.department, a.risk_score,
            a.first_seen.isoformat() if a.first_seen else "",
            a.last_seen.isoformat() if a.last_seen else "",
        ])
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=omni_cyber_guard_assets.csv"},
    )


@router.post("/import/csv", response_model=list[AssetOut])
def import_assets_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    content = file.file.read().decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    created: list[Asset] = []
    for row in reader:
        asset = Asset(
            organization_id=current_user.organization_id,
            hostname=row.get("hostname", "unknown"),
            ip_address=row.get("ip_address") or None,
            mac_address=row.get("mac_address") or None,
            asset_type=row.get("asset_type", "other") if row.get("asset_type") in AssetType._value2member_map_ else AssetType.OTHER,
            operating_system=row.get("operating_system") or None,
            vendor=row.get("vendor") or None,
            site=row.get("site") or None,
            department=row.get("department") or None,
        )
        db.add(asset)
        created.append(asset)
    db.commit()
    for a in created:
        db.refresh(a)
    log_action(db, "import_csv", "asset", current_user.organization_id, current_user.id, metadata={"count": len(created)})
    return created
