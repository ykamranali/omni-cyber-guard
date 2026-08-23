import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, require_permission, get_current_active_user, require_super_admin
from app.core.rbac import Permission
from app.core.security import hash_password
from app.models.organization import Organization
from app.models.user import User
from app.schemas.organization import (
    OrganizationBrandingUpdate, OrganizationCreate, OrganizationLicenseUpdate,
    OrganizationOut, OrganizationSettingsUpdate, OrganizationUpdate,
)
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

@router.patch("/current/settings", response_model=OrganizationOut)
def update_current_organization_settings(
    org_update: OrganizationSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORGANIZATIONS)),
):
    """
    Update enterprise settings for the current user's organization.
    """
    org = current_user.organization
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    update_data = org_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(org, field, value)

    db.commit()
    db.refresh(org)
    return org

@router.post("/current/webhooks/test", response_model=dict)
def test_webhook(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_ORGANIZATIONS)),
):
    from app.services.notifications import NotificationService
    
    org = db.query(Organization).filter(Organization.id == current_user.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    if not org.slack_webhook_url and not org.teams_webhook_url:
        raise HTTPException(status_code=400, detail="No webhooks configured.")
        
    title = "Omni Cyber Guard - Test Alert"
    message = "This is a test notification from your Omni Cyber Guard platform to verify webhook connectivity."
    
    if org.slack_webhook_url:
        NotificationService.send_webhook_notification(org.slack_webhook_url, title, message, provider="slack")
    if org.teams_webhook_url:
        NotificationService.send_webhook_notification(org.teams_webhook_url, title, message, provider="teams")
        
    return {"status": "success", "message": "Test alerts dispatched."}


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


@router.patch("/{organization_id}", response_model=OrganizationOut)
def update_organization(
    organization_id: uuid.UUID,
    payload: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """Rename an organization, or activate/deactivate it."""
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes were supplied.")

    # Deactivating the organization the caller is signed in to would lock them
    # out of the platform they are administering.
    if changes.get("is_active") is False and org.id == current_user.organization_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot deactivate the organization you are signed in to.",
        )

    for field, value in changes.items():
        setattr(org, field, value)
    db.commit()
    db.refresh(org)

    log_action(
        db, "update_organization", "organization", org.id, current_user.id,
        str(org.id), metadata=changes,
    )
    return org


@router.patch("/{organization_id}/license", response_model=OrganizationOut)
def update_organization_license(
    organization_id: uuid.UUID,
    payload: OrganizationLicenseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Change an organization's plan or seat count.

    Super administrators only, on purpose: an organization administrator
    raising their own seat limit is a billing decision, not a setting.
    """
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No changes were supplied.")

    new_seats = changes.get("license_seats")
    if new_seats is not None:
        active_users = db.query(User).filter(
            User.organization_id == org.id, User.is_active.is_(True)
        ).count()
        if new_seats < active_users:
            # Silently allowing this would put the organization over its own
            # limit with no way to see how it happened.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"{org.name} has {active_users} active account(s). Deactivate "
                    f"accounts before reducing the limit to {new_seats}."
                ),
            )

    for field, value in changes.items():
        setattr(org, field, value)
    db.commit()
    db.refresh(org)

    log_action(
        db, "update_license", "organization", org.id, current_user.id,
        str(org.id), metadata=changes,
    )
    return org


@router.delete("/{organization_id}", status_code=204)
def delete_organization(
    organization_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Permanently remove an organization and everything in it.

    Every tenant-scoped table cascades from `organizations.id`, so this deletes
    the assets, findings, scans, credentials and audit trail as well. There is
    no undo, which is why deactivation exists as the reversible alternative.
    """
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if org.id == current_user.organization_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete the organization you are signed in to.",
        )

    name = org.name
    # Recorded against the platform, not the organization, because the
    # organization's own audit rows are about to be cascaded away with it.
    log_action(
        db, "delete_organization", "organization", None, current_user.id,
        str(organization_id), metadata={"name": name},
    )
    db.delete(org)
    db.commit()
