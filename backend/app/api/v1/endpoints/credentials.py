"""
Credential vault API.

Three rules are enforced here rather than left to convention:

1. No response ever carries a secret, in plaintext or ciphertext. The response
   schema has no field for one, so it cannot leak by accident.
2. Every read of a decrypted secret is audited with the actor and the purpose.
   The only caller that decrypts is the scanner about to authenticate with it.
3. Managing credentials requires MANAGE_API_KEYS, which by default only
   organization administrators hold — an analyst who can run scans cannot
   enumerate the credentials those scans use.
"""
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import encrypt_secret
from app.core.deps import get_db, require_permission
from app.core.rbac import Permission
from app.models.credential import CredentialProfile
from app.models.user import User
from app.schemas.credential import (
    CredentialProfileCreate, CredentialProfileOut, CredentialProfileUpdate,
)
from app.services.audit import log_action

router = APIRouter(prefix="/credentials", tags=["Credentials"])


@router.get("", response_model=list[CredentialProfileOut])
def list_credentials(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_API_KEYS)),
):
    return db.execute(
        select(CredentialProfile)
        .where(CredentialProfile.organization_id == current_user.organization_id)
        .order_by(CredentialProfile.name)
    ).scalars().all()


@router.post("", response_model=CredentialProfileOut, status_code=201)
def create_credential(
    payload: CredentialProfileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_API_KEYS)),
):
    if db.execute(
        select(CredentialProfile).where(
            CredentialProfile.organization_id == current_user.organization_id,
            CredentialProfile.name == payload.name,
        )
    ).scalar_one_or_none():
        raise HTTPException(
            status_code=409, detail=f"A credential named '{payload.name}' already exists."
        )

    profile = CredentialProfile(
        organization_id=current_user.organization_id,
        created_by_user_id=current_user.id,
        name=payload.name,
        description=payload.description,
        credential_type=payload.credential_type,
        username=payload.username,
        domain=payload.domain,
        secret_encrypted=encrypt_secret(payload.secret),
        extra_encrypted=encrypt_secret(json.dumps(payload.extra)) if payload.extra else None,
        rotated_at=datetime.now(timezone.utc),
    )
    db.add(profile)
    db.commit()
    db.refresh(profile)

    # The secret itself is never written to the audit log — only the fact that
    # a credential of this type was created.
    log_action(
        db, "create", "credential_profile", current_user.organization_id, current_user.id,
        str(profile.id),
        metadata={"name": profile.name, "type": profile.credential_type.value},
    )
    return profile


@router.patch("/{credential_id}", response_model=CredentialProfileOut)
def update_credential(
    credential_id: uuid.UUID,
    payload: CredentialProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_API_KEYS)),
):
    profile = _get_credential(db, credential_id, current_user)
    changes = payload.model_dump(exclude_unset=True)

    rotated = False
    if changes.pop("secret", None) is not None:
        profile.secret_encrypted = encrypt_secret(payload.secret)
        profile.rotated_at = datetime.now(timezone.utc)
        rotated = True

    extra = changes.pop("extra", None)
    if extra is not None:
        profile.extra_encrypted = encrypt_secret(json.dumps(extra)) if extra else None

    for field, value in changes.items():
        setattr(profile, field, value)

    db.commit()
    db.refresh(profile)

    log_action(
        db, "update", "credential_profile", current_user.organization_id, current_user.id,
        str(profile.id), metadata={"rotated": rotated},
    )
    return profile


@router.delete("/{credential_id}", status_code=204)
def delete_credential(
    credential_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.MANAGE_API_KEYS)),
):
    profile = _get_credential(db, credential_id, current_user)
    name = profile.name
    db.delete(profile)
    db.commit()
    log_action(
        db, "delete", "credential_profile", current_user.organization_id, current_user.id,
        str(credential_id), metadata={"name": name},
    )


def _get_credential(db: Session, credential_id: uuid.UUID, current_user: User) -> CredentialProfile:
    profile = db.execute(
        select(CredentialProfile).where(
            CredentialProfile.id == credential_id,
            CredentialProfile.organization_id == current_user.organization_id,
        )
    ).scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Credential profile not found")
    return profile
