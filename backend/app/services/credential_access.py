"""
The one place a stored credential is decrypted.

Keeping decryption behind a single audited function is what makes "who used
which credential, when, and for what" answerable. Nothing else in the codebase
calls `decrypt_secret` on a credential row.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_secret
from app.models.credential import CredentialProfile
from app.services.audit import log_action


@dataclass
class ResolvedCredential:
    """A credential ready to authenticate with.

    Deliberately not a Pydantic model: it must never be returned from an API
    handler, and keeping it out of the schema layer makes that harder to do by
    accident.
    """

    id: uuid.UUID
    name: str
    credential_type: str
    username: str
    domain: str
    secret: str
    extra: dict[str, str]

    def __repr__(self) -> str:  # pragma: no cover - defensive
        # Stops the secret reaching a log line, a traceback or an error report.
        return f"<ResolvedCredential {self.name} ({self.credential_type}) secret=***>"

    __str__ = __repr__


def resolve_credential(
    db: Session,
    organization_id: uuid.UUID,
    credential_id: uuid.UUID,
    purpose: str,
    actor_user_id: uuid.UUID | None = None,
) -> ResolvedCredential:
    """
    Decrypt a credential for immediate use, recording that it happened.

    Args:
        purpose: why it is being used, e.g. "windows_audit scan of 10.0.0.5".
            This goes into the audit record, so it should name the target.
    """
    profile = db.execute(
        select(CredentialProfile).where(
            CredentialProfile.id == credential_id,
            CredentialProfile.organization_id == organization_id,
        )
    ).scalar_one_or_none()

    if profile is None:
        raise LookupError("Credential profile not found for this organization.")

    secret = decrypt_secret(profile.secret_encrypted)
    extra: dict[str, str] = {}
    if profile.extra_encrypted:
        try:
            extra = json.loads(decrypt_secret(profile.extra_encrypted))
        except (ValueError, TypeError):
            extra = {}

    profile.last_used_at = datetime.now(timezone.utc)
    db.add(profile)

    log_action(
        db, "credential_accessed", "credential_profile", organization_id, actor_user_id,
        str(profile.id),
        metadata={"name": profile.name, "type": profile.credential_type.value, "purpose": purpose},
    )

    return ResolvedCredential(
        id=profile.id,
        name=profile.name,
        credential_type=profile.credential_type.value,
        username=profile.username,
        domain=profile.domain,
        secret=secret,
        extra=extra,
    )
