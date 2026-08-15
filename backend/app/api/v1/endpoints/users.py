import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user, get_db, require_permission
from app.core.rbac import Permission
from app.core.security import hash_password
from app.models.role import Role
from app.models.user import User
from app.schemas.role import RoleOut
from app.schemas.user import UserOut, UserCreate, UserUpdate
from app.services.audit import log_action

router = APIRouter(prefix="/users", tags=["Users"])


def _to_out(u: User) -> UserOut:
    return UserOut(
        id=u.id, email=u.email, full_name=u.full_name, is_active=u.is_active,
        is_super_admin=u.is_super_admin, organization_id=u.organization_id,
        roles=[r.name for r in u.roles],
    )


@router.get("/me", response_model=UserOut)
def read_current_user(current_user: User = Depends(get_current_active_user)):
    return _to_out(current_user)


@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
):
    users = db.query(User).filter(User.organization_id == current_user.organization_id).all()
    return [_to_out(u) for u in users]


@router.get("/roles/available", response_model=list[RoleOut])
def list_available_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
):
    roles = db.query(Role).filter(Role.organization_id == current_user.organization_id).order_by(Role.name).all()
    return roles


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="A user with this email already exists")

    roles = (
        db.query(Role)
        .filter(Role.organization_id == current_user.organization_id, Role.name.in_(payload.role_names))
        .all()
        if payload.role_names else []
    )

    new_user = User(
        organization_id=current_user.organization_id,
        email=payload.email, full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
    )
    new_user.roles = roles
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_action(db, "create", "user", current_user.organization_id, current_user.id, str(new_user.id))
    return _to_out(new_user)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
):
    target = (
        db.query(User)
        .filter(User.id == user_id, User.organization_id == current_user.organization_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    data = payload.model_dump(exclude_unset=True)
    role_names = data.pop("role_names", None)
    for field, value in data.items():
        setattr(target, field, value)
    if role_names is not None:
        target.roles = (
            db.query(Role)
            .filter(Role.organization_id == current_user.organization_id, Role.name.in_(role_names))
            .all()
        )

    db.commit()
    db.refresh(target)
    log_action(db, "update", "user", current_user.organization_id, current_user.id, str(target.id))
    return _to_out(target)


@router.delete("/{user_id}", status_code=204)
def deactivate_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_USERS)),
):
    """Deactivates rather than hard-deletes, preserving audit trail integrity."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot deactivate your own account")

    target = (
        db.query(User)
        .filter(User.id == user_id, User.organization_id == current_user.organization_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    target.is_active = False
    db.commit()
    log_action(db, "deactivate", "user", current_user.organization_id, current_user.id, str(target.id))
