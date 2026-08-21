"""
Authentication.

Login is protected two ways: a per-IP request rate limit (slowapi) and a
per-account lockout after repeated failures. Neither existed previously —
`RATE_LIMIT_PER_MINUTE` was defined in config and never referenced, leaving
the endpoint open to unbounded credential stuffing.

Failures return an identical message and take a comparable amount of work
whether or not the email exists, so the endpoint does not confirm which
accounts are real.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rate_limit import limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshRequest, TokenResponse
from app.services.audit import log_action

router = APIRouter(prefix="/auth", tags=["Authentication"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
)

# Hashing a throwaway password when the account does not exist keeps the
# timing of a miss close to the timing of a hit.
_DUMMY_HASH = hash_password("omni-cyber-guard-timing-equaliser")


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("/login", response_model=TokenResponse)
@limiter.limit(f"{settings.LOGIN_RATE_LIMIT_PER_MINUTE}/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    ip_address = _client_ip(request)
    user = db.query(User).filter(User.email == payload.email).first()

    if user is None:
        verify_password(payload.password, _DUMMY_HASH)
        raise _INVALID_CREDENTIALS

    now = datetime.now(timezone.utc)

    if user.locked_until is not None and user.locked_until > now:
        remaining = int((user.locked_until - now).total_seconds() // 60) + 1
        log_action(
            db, action="login_blocked_locked_account", resource_type="user",
            organization_id=user.organization_id, actor_user_id=user.id,
            resource_id=str(user.id), ip_address=ip_address,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked after repeated failed sign-ins. "
                   f"Try again in about {remaining} minute(s).",
        )

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        locked = user.failed_login_attempts >= MAX_FAILED_ATTEMPTS
        if locked:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_attempts = 0
            
        user_id = str(user.id)
        org_id = str(user.organization_id)
        db.commit()

        log_action(
            db, action="login_failed", resource_type="user",
            organization_id=org_id, actor_user_id=user_id,
            resource_id=user_id, ip_address=ip_address,
            metadata={"locked": locked},
        )
        raise _INVALID_CREDENTIALS

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    
    user_id = str(user.id)
    org_id = str(user.organization_id)
    
    db.commit()

    log_action(
        db, action="login", resource_type="user",
        organization_id=org_id, actor_user_id=user_id,
        resource_id=user_id, ip_address=ip_address,
    )

    return TokenResponse(
        access_token=create_access_token(user_id, {"org_id": org_id}),
        refresh_token=create_refresh_token(user_id),
    )


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit(f"{settings.LOGIN_RATE_LIMIT_PER_MINUTE}/minute")
def refresh(request: Request, payload: RefreshRequest, db: Session = Depends(get_db)):
    import uuid as _uuid

    try:
        data = decode_token(payload.refresh_token)
        if data.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        subject = data.get("sub")
        if not subject:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        user_id = _uuid.UUID(subject)
    except (JWTError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    return TokenResponse(
        access_token=create_access_token(str(user.id), {"org_id": str(user.organization_id)}),
        refresh_token=create_refresh_token(str(user.id)),
    )
