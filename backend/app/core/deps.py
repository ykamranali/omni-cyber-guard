"""
Shared FastAPI dependencies: DB session, current user resolution, and
permission-based route guards for RBAC enforcement.
"""
import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import Permission
from app.core.security import decode_token
from app.db.session import get_db
from app.db.tenancy import bypass_tenant, set_tenant
from app.models.user import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise credentials_exception
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    try:
        user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    except ValueError:
        raise credentials_exception

    if user is None or not user.is_active:
        raise credentials_exception

    # Narrow the database session to this user's tenant for the rest of the
    # request. Row-level security then enforces isolation independently of
    # whether an individual query remembered to filter on organization_id.
    #
    # Super administrators legitimately operate across organizations, so their
    # sessions stay in bypass — their access is constrained by RBAC and
    # recorded in the audit log instead.
    if settings.ENABLE_ROW_LEVEL_SECURITY:
        if user.is_super_admin:
            bypass_tenant(db)
        else:
            set_tenant(db, user.organization_id)

    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def require_permission(permission: Permission):
    """Dependency factory: enforces the current user's role(s) grant `permission`."""

    def checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.is_super_admin:
            return current_user
        user_permission_codes = {
            perm.code for role in current_user.roles for perm in role.permissions
        }
        if permission.value not in user_permission_codes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission.value}",
            )
        return current_user

    return checker


def require_super_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """Platform-level actions (managing other organizations) require the super admin flag,
    not just an org-scoped permission — no organization role can grant this."""
    if not current_user.is_super_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Super administrator access required")
    return current_user
