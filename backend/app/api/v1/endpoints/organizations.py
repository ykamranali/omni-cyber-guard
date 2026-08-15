import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission, get_current_active_user, require_super_admin
from app.core.rbac import Permission
from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User
from app.schemas.organization import OrganizationOut, OrganizationBrandingUpdate, OrganizationCreate
from app.services.org_provisioning import provision_new_organization
from app.services.audit import log_action

router = APIRouter(prefix="/organizations", tags=["Organizations"])


@router.get("/current", response_model=OrganizationOut)
def get_current_organization(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)
):
    org = db.query(Organization).filter(Organization.id == current_user.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


@router.patch("/current/branding", response_model=OrganizationOut)
def update_branding(
    payload: OrganizationBrandingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_BRANDING)),
):
    org = db.query(Organization).filter(Organization.id == current_user.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(org, field, value)
    db.commit()
    db.refresh(org)
    return org


# --- Platform-level (super admin only): manage every organization on the platform ---

@router.get("", response_model=list[OrganizationOut])
def list_organizations(
    db: Session = Depends(get_db),
    _: User = Depends(require_super_admin),
):
    return db.query(Organization).order_by(Organization.name).all()


@router.post("", response_model=OrganizationOut, status_code=201)
def create_organization(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    if db.query(Organization).filter(Organization.slug == payload.slug).first():
        raise HTTPException(status_code=400, detail="An organization with this slug already exists")
    if db.query(User).filter(User.email == payload.admin_email).first():
        raise HTTPException(status_code=400, detail="A user with this admin email already exists")

    org = Organization(
        name=payload.name, slug=payload.slug,
        subscription_plan=payload.subscription_plan, license_seats=payload.license_seats,
    )
    db.add(org)
    db.flush()

    role_objs = provision_new_organization(db, org)

    admin_user = User(
        organization_id=org.id, email=payload.admin_email, full_name=payload.admin_full_name,
        hashed_password=hash_password(payload.admin_password),
    )
    admin_user.roles = [role_objs["organization_administrator"]]
    db.add(admin_user)
    db.commit()
    db.refresh(org)

    log_action(db, "create_organization", "organization", org.id, current_user.id, str(org.id))
    return org


@router.get("/{organization_id}", response_model=OrganizationOut)
def get_organization(
    organization_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: User = Depends(require_super_admin),
):
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org
