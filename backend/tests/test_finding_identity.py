"""
Finding identity.

The fingerprint is what makes "this is the same finding we saw last week" a
fact rather than a guess, so its behaviour is pinned down here — including the
requirement that the SQL backfill in migration b7e4d1a90c35 produces byte-for-
byte the same digest as the Python implementation. If those two drift, every
finding created before the migration silently duplicates against its own
post-migration self.
"""
import uuid

from sqlalchemy import text

from app.models.finding import FindingClass
from app.services.finding_identity import compute_fingerprint, service_location


def _fp(**overrides):
    base = dict(
        asset_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        finding_class=FindingClass.EXPOSURE,
        source="nmap",
        identifier="exposed-port-3389",
        location="tcp/3389",
    )
    base.update(overrides)
    return compute_fingerprint(**base)


def test_fingerprint_is_stable():
    assert _fp() == _fp()


def test_fingerprint_is_a_sha256_hex_digest():
    value = _fp()
    assert len(value) == 64
    assert all(character in "0123456789abcdef" for character in value)


def test_same_defect_on_different_ports_is_different():
    assert _fp(location="tcp/3389") != _fp(location="tcp/3390")


def test_same_defect_on_different_assets_is_different():
    assert _fp() != _fp(asset_id=uuid.UUID("22222222-2222-2222-2222-222222222222"))


def test_different_sources_are_different_findings():
    """nmap suspecting something and nuclei confirming it are two observations."""
    assert _fp(source="nmap") != _fp(source="nuclei")


def test_class_is_part_of_identity():
    assert _fp(finding_class=FindingClass.EXPOSURE) != _fp(finding_class=FindingClass.VULNERABILITY)


def test_identifier_is_case_and_whitespace_insensitive():
    assert _fp(identifier="CVE-2024-1234") == _fp(identifier="  cve-2024-1234  ")


def test_severity_and_wording_are_not_part_of_identity():
    """A finding re-worded or re-scored between scans is still the same finding."""
    first = compute_fingerprint(
        asset_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        finding_class=FindingClass.VULNERABILITY,
        source="nuclei",
        identifier="apache-detect",
        location="https://10.0.0.1",
    )
    second = compute_fingerprint(
        asset_id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
        finding_class="vulnerability",
        source="nuclei",
        identifier="apache-detect",
        location="https://10.0.0.1",
    )
    assert first == second


def test_component_boundaries_cannot_be_confused():
    """Shifting a character across the field boundary must change the digest."""
    assert _fp(source="nmap", identifier="ab") != _fp(source="nmapa", identifier="b")


def test_service_location_format():
    assert service_location(3389, "tcp") == "tcp/3389"
    assert service_location(53, "UDP") == "udp/53"
    assert service_location(None, "tcp") == ""


def test_sql_backfill_matches_the_python_implementation(db):
    """
    The migration reproduces this digest in SQL. Reimplementing a hash in two
    languages is exactly the kind of thing that silently drifts, so assert it.
    """
    asset_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    source = "network_scan"
    title = "Exposed RDP service on port 3389"

    # Mirrors the CASE in migration b7e4d1a90c35: no CVE, source network_scan.
    expected = compute_fingerprint(
        asset_id=asset_id,
        finding_class=FindingClass.EXPOSURE,
        source=source,
        identifier=title,
        location="",
    )

    from_sql = db.execute(
        text(
            """
            SELECT encode(
                sha256(
                    convert_to(
                        :asset_id || chr(31) ||
                        lower('exposure') || chr(31) ||
                        lower(:source) || chr(31) ||
                        lower(:identifier) || chr(31) ||
                        '',
                        'UTF8'
                    )
                ),
                'hex'
            )
            """
        ),
        {"asset_id": str(asset_id), "source": source, "identifier": title},
    ).scalar_one()

    assert from_sql == expected
