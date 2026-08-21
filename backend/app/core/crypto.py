"""
Symmetric encryption for secrets held at rest.

Used by the credential vault. Scanning a Windows host or an LDAP directory
needs a real credential; storing that credential in plaintext would make the
platform's own database the most valuable target on the network.

Key management
--------------
The key comes from CREDENTIAL_ENCRYPTION_KEY (a urlsafe-base64 32-byte Fernet
key). It is deliberately separate from SECRET_KEY: rotating session signing
keys should not render every stored credential unreadable, and a leaked JWT
secret should not also decrypt the vault.

In development, if no key is configured, one is derived from SECRET_KEY so the
application still runs — and a loud warning is logged. In production a missing
or derived key is a hard startup failure: see Settings.assert_production_ready.
"""
from __future__ import annotations

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

logger = logging.getLogger(__name__)


class SecretDecryptionError(RuntimeError):
    """Raised when stored ciphertext cannot be decrypted with the current key.

    Almost always means the encryption key changed. The correct response is to
    restore the previous key or re-enter the credential — never to silently
    return an empty secret, which would make an authenticated scan fail in a
    way that looks like a permissions problem on the target.
    """


def _derive_development_key() -> bytes:
    digest = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _load_key() -> bytes:
    configured = (settings.CREDENTIAL_ENCRYPTION_KEY or "").strip()
    if configured:
        key = configured.encode("utf-8")
        # Fail now, with a clear message, rather than on first credential use.
        Fernet(key)
        return key

    logger.warning(
        "CREDENTIAL_ENCRYPTION_KEY is not set. Deriving a key from SECRET_KEY for "
        "development use. Generate a real key with: "
        "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )
    return _derive_development_key()


_fernet: Fernet | None = None


def _cipher() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt_secret(plaintext: str) -> bytes:
    """Encrypt a secret for storage. Returns ciphertext bytes."""
    if plaintext is None:
        raise ValueError("Cannot encrypt None.")
    return _cipher().encrypt(plaintext.encode("utf-8"))


def decrypt_secret(ciphertext: bytes) -> str:
    """Decrypt a stored secret. Raises SecretDecryptionError on key mismatch."""
    try:
        return _cipher().decrypt(bytes(ciphertext)).decode("utf-8")
    except InvalidToken as exc:
        raise SecretDecryptionError(
            "Stored credential could not be decrypted. The encryption key has "
            "most likely changed since it was saved. Restore the previous "
            "CREDENTIAL_ENCRYPTION_KEY or re-enter the credential."
        ) from exc


def generate_key() -> str:
    """Convenience for operators generating a key for their .env."""
    return Fernet.generate_key().decode("utf-8")


def reset_cipher_cache() -> None:
    """Test hook: forces the key to be re-read on next use."""
    global _fernet
    _fernet = None
