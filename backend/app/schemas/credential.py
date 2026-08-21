import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.credential import CredentialType


class CredentialProfileOut(BaseModel):
    """
    The safe view of a credential.

    There is deliberately no field here that carries the secret, in either
    plaintext or ciphertext. Adding one would make the secret reachable through
    ordinary API access, which is the failure this vault exists to prevent —
    `secret_set` reports only that a secret is present.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str
    credential_type: CredentialType
    username: str
    domain: str
    last_used_at: datetime | None
    rotated_at: datetime | None
    created_at: datetime
    secret_set: bool = True


class CredentialProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    credential_type: CredentialType
    description: str = ""
    username: str = ""
    domain: str = ""
    #: Write-only. Encrypted immediately and never returned.
    secret: str = Field(min_length=1)
    #: Optional additional secret material (an SSH passphrase, an SNMPv3
    #: privacy key, a cloud secret access key).
    extra: dict[str, str] | None = None


class CredentialProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    username: str | None = None
    domain: str | None = None
    #: Supplying a value rotates the secret and stamps rotated_at.
    secret: str | None = Field(default=None, min_length=1)
    extra: dict[str, str] | None = None
