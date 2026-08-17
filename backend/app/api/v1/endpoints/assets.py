import csv
import io
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.user import User
from app.schemas.asset import AssetOut, AssetCreate, AssetUpdate
from app.services.audit import log_action

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(
    search: str | None = Query(default=None),
    asset_type: AssetType | None = Query(default=None),
    status_filter: AssetStatus | None = Query(default=None, alias="status"),
    site: str | None = Query(default=None),
    scan_id: str | None = Query(default=None),
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
    if scan_id:
        try:
            query = query.filter(Asset.scan_job_id == uuid.UUID(scan_id))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scan_id format")
    return query.order_by(Asset.hostname).all()


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
    writer.writerow(["hostname", "ip_address", "mac_address", "asset_type", "status", "operating_system", "vendor", "site", "department"])
    for a in assets:
        writer.writerow([a.hostname, a.ip_address, a.mac_address, a.asset_type.value, a.status.value, a.operating_system, a.vendor, a.site, a.department])
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
