"""
Sites and networks — the containment hierarchy discovery is organised around.

`Network.is_authorized_scope` is the record of consent for active scanning.
A scan target must fall inside a range an operator has explicitly marked as
authorized; recording who authorised it, and when, is what makes that
defensible after the fact.
"""
import ipaddress
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.asset import Asset
from app.models.network import Network
from app.models.site import Site
from app.models.user import User
from app.schemas.site import (
    NetworkCreate, NetworkOut, NetworkUpdate, SiteCreate, SiteOut, SiteUpdate,
)
from app.services.audit import log_action

router = APIRouter(tags=["Sites & Networks"])


def _site_out(db: Session, site: Site) -> SiteOut:
    network_count = db.execute(
        select(func.count(Network.id)).where(Network.site_id == site.id)
    ).scalar_one()
    asset_count = db.execute(
        select(func.count(Asset.id)).where(Asset.site_id == site.id)
    ).scalar_one()
    return SiteOut(
        **{field: getattr(site, field) for field in
           ("id", "name", "description", "location", "latitude", "longitude", "created_at")},
        network_count=network_count,
        asset_count=asset_count,
    )


def _network_out(db: Session, network: Network) -> NetworkOut:
    asset_count = db.execute(
        select(func.count(Asset.id)).where(Asset.network_id == network.id)
    ).scalar_one()
    return NetworkOut(
        **{field: getattr(network, field) for field in
           ("id", "site_id", "name", "cidr", "vlan_id", "description",
            "is_internet_facing", "is_authorized_scope", "authorization_note", "created_at")},
        asset_count=asset_count,
    )


# --------------------------------------------------------------------- sites

@router.get("/sites", response_model=list[SiteOut])
def list_sites(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    sites = db.execute(
        select(Site)
        .where(Site.organization_id == current_user.organization_id)
        .order_by(Site.name)
    ).scalars().all()
    return [_site_out(db, site) for site in sites]


@router.post("/sites", response_model=SiteOut, status_code=201)
def create_site(
    payload: SiteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    if db.execute(
        select(Site).where(
            Site.organization_id == current_user.organization_id, Site.name == payload.name
        )
    ).scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"A site named '{payload.name}' already exists.")

    site = Site(organization_id=current_user.organization_id, **payload.model_dump())
    db.add(site)
    db.commit()
    db.refresh(site)
    log_action(db, "create", "site", current_user.organization_id, current_user.id, str(site.id))
    return _site_out(db, site)


@router.patch("/sites/{site_id}", response_model=SiteOut)
def update_site(
    site_id: uuid.UUID,
    payload: SiteUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    site = _get_site(db, site_id, current_user)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(site, field, value)
    db.commit()
    db.refresh(site)
    log_action(db, "update", "site", current_user.organization_id, current_user.id, str(site.id))
    return _site_out(db, site)


@router.delete("/sites/{site_id}", status_code=204)
def delete_site(
    site_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    site = _get_site(db, site_id, current_user)
    # Networks and assets survive; they simply lose their site association.
    db.delete(site)
    db.commit()
    log_action(db, "delete", "site", current_user.organization_id, current_user.id, str(site_id))


# ------------------------------------------------------------------ networks

@router.get("/networks", response_model=list[NetworkOut])
def list_networks(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    networks = db.execute(
        select(Network)
        .where(Network.organization_id == current_user.organization_id)
        .order_by(Network.name)
    ).scalars().all()
    return [_network_out(db, network) for network in networks]


@router.post("/networks", response_model=NetworkOut, status_code=201)
def create_network(
    payload: NetworkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    if db.execute(
        select(Network).where(
            Network.organization_id == current_user.organization_id,
            Network.cidr == payload.cidr,
        )
    ).scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"{payload.cidr} is already registered.")

    if payload.site_id is not None:
        _get_site(db, payload.site_id, current_user)

    network = Network(organization_id=current_user.organization_id, **payload.model_dump())
    if payload.is_authorized_scope:
        network.authorized_by_user_id = current_user.id

    db.add(network)
    db.commit()
    db.refresh(network)

    log_action(
        db, "create", "network", current_user.organization_id, current_user.id, str(network.id),
        metadata={"cidr": network.cidr, "authorized_scope": network.is_authorized_scope},
    )
    return _network_out(db, network)


@router.patch("/networks/{network_id}", response_model=NetworkOut)
def update_network(
    network_id: uuid.UUID,
    payload: NetworkUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    network = _get_network(db, network_id, current_user)
    changes = payload.model_dump(exclude_unset=True)

    # Granting scan authorization is a decision worth attributing.
    if changes.get("is_authorized_scope") and not network.is_authorized_scope:
        network.authorized_by_user_id = current_user.id

    for field, value in changes.items():
        setattr(network, field, value)

    db.commit()
    db.refresh(network)
    log_action(
        db, "update", "network", current_user.organization_id, current_user.id, str(network.id),
        metadata={k: str(v) for k, v in changes.items()},
    )
    return _network_out(db, network)


@router.delete("/networks/{network_id}", status_code=204)
def delete_network(
    network_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ASSETS)),
):
    network = _get_network(db, network_id, current_user)
    db.delete(network)
    db.commit()
    log_action(db, "delete", "network", current_user.organization_id, current_user.id, str(network_id))


@router.get("/networks/authorization-check")
def check_scan_authorization(
    target: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VIEW_ASSETS)),
):
    """
    Report whether a target falls inside a declared authorized range.

    The Scan Center calls this before offering to start a scan, so the operator
    is told what the platform knows about their authorization rather than being
    asked to tick a box with no basis.
    """
    try:
        requested = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{target}' is not a valid IP or CIDR range.")

    networks = db.execute(
        select(Network).where(Network.organization_id == current_user.organization_id)
    ).scalars().all()

    for network in networks:
        try:
            declared = ipaddress.ip_network(network.cidr, strict=False)
        except ValueError:
            continue
        if requested.subnet_of(declared) and network.is_authorized_scope:
            return {
                "authorized": True,
                "matched_network": {"id": str(network.id), "name": network.name, "cidr": network.cidr},
                "message": f"{target} falls inside '{network.name}' ({network.cidr}), "
                           f"which is marked as authorized scope.",
            }

    return {
        "authorized": False,
        "matched_network": None,
        "message": (
            f"{target} is not inside any network marked as authorized scope. "
            f"Register the range under Discovery → Networks and mark it authorized "
            f"before scanning it."
        ),
    }


# ------------------------------------------------------------------- helpers

def _get_site(db: Session, site_id: uuid.UUID, current_user: User) -> Site:
    site = db.execute(
        select(Site).where(
            Site.id == site_id, Site.organization_id == current_user.organization_id
        )
    ).scalar_one_or_none()
    if site is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return site


def _get_network(db: Session, network_id: uuid.UUID, current_user: User) -> Network:
    network = db.execute(
        select(Network).where(
            Network.id == network_id, Network.organization_id == current_user.organization_id
        )
    ).scalar_one_or_none()
    if network is None:
        raise HTTPException(status_code=404, detail="Network not found")
    return network
