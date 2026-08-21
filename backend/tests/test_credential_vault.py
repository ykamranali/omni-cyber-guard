"""
Credential vault.

Authenticated assessment needs real credentials, which makes this table the
most valuable thing in the database. The properties asserted here are the ones
that keep a database compromise from becoming a domain compromise.
"""
import pytest

from app.core.crypto import (
    SecretDecryptionError, decrypt_secret, encrypt_secret, generate_key, reset_cipher_cache,
)
from app.models.credential import CredentialProfile, CredentialType


def test_round_trip():
    ciphertext = encrypt_secret("hunter2")
    assert decrypt_secret(ciphertext) == "hunter2"


def test_ciphertext_does_not_contain_the_plaintext():
    ciphertext = encrypt_secret("SuperSecretPassword123")
    assert b"SuperSecretPassword123" not in ciphertext


def test_encryption_is_non_deterministic():
    """Identical passwords must not produce identical ciphertext, or the table
    itself reveals which accounts share a password."""
    assert encrypt_secret("same") != encrypt_secret("same")


def test_unicode_and_long_secrets_survive():
    secret = "pässwörd-🔐-" + "x" * 4000
    assert decrypt_secret(encrypt_secret(secret)) == secret


def test_a_wrong_key_raises_rather_than_returning_garbage(monkeypatch):
    """Silently returning an empty secret would surface as a confusing
    permission error against the target host instead of a key problem."""
    ciphertext = encrypt_secret("hunter2")

    from app.core import crypto
    monkeypatch.setattr(crypto.settings, "CREDENTIAL_ENCRYPTION_KEY", generate_key())
    reset_cipher_cache()
    try:
        with pytest.raises(SecretDecryptionError) as exc:
            decrypt_secret(ciphertext)
        assert "encryption key" in str(exc.value).lower()
    finally:
        reset_cipher_cache()


def test_stored_credentials_are_ciphertext_in_the_database(db, organization):
    profile = CredentialProfile(
        organization_id=organization.id,
        name="Domain scan account",
        credential_type=CredentialType.WINDOWS,
        username="svc_scan",
        domain="CORP",
        secret_encrypted=encrypt_secret("D0ntL3akMe!"),
    )
    db.add(profile)
    db.flush()

    from sqlalchemy import text
    raw = db.execute(
        text("SELECT secret_encrypted FROM credential_profiles WHERE id = :id"),
        {"id": profile.id},
    ).scalar_one()

    assert b"D0ntL3akMe!" not in bytes(raw)
    assert decrypt_secret(raw) == "D0ntL3akMe!"


def test_the_model_has_no_plaintext_secret_column():
    columns = {column.name for column in CredentialProfile.__table__.columns}
    assert "secret" not in columns
    assert "password" not in columns
    assert "secret_encrypted" in columns


def test_generated_keys_are_usable(monkeypatch):
    from app.core import crypto
    monkeypatch.setattr(crypto.settings, "CREDENTIAL_ENCRYPTION_KEY", generate_key())
    reset_cipher_cache()
    try:
        assert decrypt_secret(encrypt_secret("value")) == "value"
    finally:
        reset_cipher_cache()
