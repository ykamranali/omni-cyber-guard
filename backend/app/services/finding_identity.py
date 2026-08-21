"""
Stable finding identity.

Deduplication used to be a `Finding.title LIKE '%...%'` query, which was both
fragile (a wording change created a duplicate) and wrong (two different ports
running the same service collided). This module derives a deterministic
fingerprint instead.

What goes into a fingerprint is deliberately minimal: the things that make two
observations *the same finding*, and nothing that legitimately changes between
scans. Severity, description wording, CVSS and evidence text are all excluded —
they can be updated in place on the existing row.
"""
from __future__ import annotations

import hashlib

from app.models.finding import FindingClass

#: Field delimiter used when building the fingerprint input. Must stay in sync
#: with the SQL backfill in migration b7e4d1a90c35 (chr(31)).
FIELD_SEPARATOR = "\x1f"


def compute_fingerprint(
    *,
    asset_id,
    finding_class: FindingClass | str,
    source: str,
    identifier: str,
    location: str = "",
) -> str:
    """
    Build the stable identity for a finding.

    Args:
        asset_id: the asset the finding belongs to.
        finding_class: what kind of claim it is.
        source: which integration produced it ("nmap", "nuclei", "manual", ...).
        identifier: what the finding is about — a CVE ID where one exists,
            otherwise a stable check identifier such as an nmap script ID or a
            nuclei template ID. Free-text titles are a last resort because they
            change when wording changes.
        location: where on the asset it was observed — "tcp/3389", a URL path.
            Two instances of the same defect on different ports are different
            findings and must not collapse into one.

    Returns:
        A 64-character hex digest.
    """
    class_value = finding_class.value if isinstance(finding_class, FindingClass) else str(finding_class)

    parts = [
        str(asset_id),
        class_value.strip().lower(),
        (source or "").strip().lower(),
        (identifier or "").strip().lower(),
        (location or "").strip().lower(),
    ]
    # Unit Separator (0x1F) is the field delimiter. It is a control character
    # that cannot occur in a hostname, a CVE ID, a source name or a scanner
    # title, so distinct component tuples can never collide by joining to the
    # same string. NUL would be the natural choice but PostgreSQL text columns
    # cannot hold it, and the migration that backfills this value has to
    # reproduce the digest in SQL.
    return hashlib.sha256(FIELD_SEPARATOR.join(parts).encode("utf-8")).hexdigest()


def service_location(port: int | None, protocol: str | None) -> str:
    """Canonical location string for a network service."""
    if port is None:
        return ""
    return f"{(protocol or 'tcp').strip().lower()}/{port}"
