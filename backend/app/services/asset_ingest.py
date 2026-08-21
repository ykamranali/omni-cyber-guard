"""
Asset inventory ingestion.

Turns parsed scanner output into asset, interface, service and software rows.
The previous implementation stored open ports as a JSON blob on the asset,
which meant the platform could not answer "which hosts expose RDP" without
loading every asset into Python. Services and software are now rows.

Everything here is derived from observation. Where a value cannot be
established — a CPE for an unrecognised banner, a vendor for an unknown MAC
prefix — the field is left empty rather than guessed, because a wrong CPE
silently mis-correlates CVEs and a wrong vendor misleads an engineer.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.asset_detail import AssetInterface, AssetService, AssetSoftware
from app.models.network import Network

MAX_BANNER_CHARS = 4000


# ---------------------------------------------------------------------------
# Device classification
# ---------------------------------------------------------------------------

@dataclass
class Classification:
    """A device-type decision, with the evidence that produced it."""
    asset_type: AssetType
    confidence: int
    evidence: list[str]


# Ordered most-specific first. Each entry is
# (asset_type, confidence, matcher-description, regex over the combined signal).
_OS_SIGNATURES: list[tuple[AssetType, int, str]] = [
    (AssetType.FIREWALL, 90, r"fortios|pfsense|palo alto|pan-os|sonicwall|checkpoint|asa\b"),
    (AssetType.ROUTER, 85, r"cisco ios|mikrotik|routeros|junos|edgeos"),
    (AssetType.SWITCH, 85, r"catalyst|procurve|switch|nx-os"),
    (AssetType.ACCESS_POINT, 85, r"aironet|unifi ap|access point|airos"),
    (AssetType.PRINTER, 90, r"jetdirect|printer|laserjet|officejet|kyocera|ricoh|lexmark"),
    (AssetType.CAMERA, 85, r"hikvision|dahua|axis communications|ip camera|onvif"),
    (AssetType.NAS, 80, r"synology|qnap|truenas|freenas|netapp"),
    (AssetType.HYPERVISOR, 90, r"vmware esxi|proxmox|xenserver|hyper-v server"),
    (AssetType.PBX, 85, r"asterisk|freepbx|3cx"),
    (AssetType.SERVER, 70, r"windows server|ubuntu server|red hat enterprise|centos|debian|freebsd"),
    (AssetType.WORKSTATION, 70, r"windows 1[01]|windows 7|windows 8|macos|mac os x"),
    (AssetType.MOBILE_DEVICE, 70, r"android|ios \d|iphone|ipad"),
    (AssetType.SERVER, 50, r"linux"),
]

# Service fingerprints, used when the OS signal is absent or generic.
_SERVICE_SIGNATURES: list[tuple[AssetType, int, str]] = [
    (AssetType.DATABASE, 75, r"\b(mysql|postgresql|mssql|oracle-tns|mongodb|redis)\b"),
    (AssetType.WEB_SERVER, 60, r"\b(http|https|nginx|apache|iis)\b"),
    (AssetType.PRINTER, 80, r"\b(ipp|printer|jetdirect)\b"),
    (AssetType.VOIP, 75, r"\b(sip|h323|iax)\b"),
]


def classify_device(
    os_match: str | None,
    services: list[str],
    mac_vendor: str | None = None,
) -> Classification:
    """
    Decide what kind of device this is, and say how sure the decision is.

    A classification is only as good as its evidence, so the evidence travels
    with it and is stored on the asset. "Network Switch (94%, from SNMP
    sysObjectID and MAC OUI)" is actionable; a bare "Network Switch" that turns
    out to be a misread banner is worse than "Unknown".
    """
    evidence: list[str] = []
    haystack_os = (os_match or "").lower()
    haystack_services = " ".join(services).lower()
    haystack_vendor = (mac_vendor or "").lower()

    best: tuple[AssetType, int] = (AssetType.OTHER, 0)

    for asset_type, confidence, pattern in _OS_SIGNATURES:
        if haystack_os and re.search(pattern, haystack_os):
            evidence.append(f"OS fingerprint matched '{pattern}' in {os_match!r}")
            best = (asset_type, confidence)
            break

    if best[1] == 0:
        for asset_type, confidence, pattern in _SERVICE_SIGNATURES:
            if haystack_services and re.search(pattern, haystack_services):
                evidence.append(f"Service signature matched '{pattern}'")
                best = (asset_type, confidence)
                break

    # A vendor that agrees with the decision raises confidence a little; a
    # vendor on its own is never enough to classify.
    if haystack_vendor:
        evidence.append(f"MAC OUI vendor: {mac_vendor}")
        if best[1] > 0:
            best = (best[0], min(95, best[1] + 5))

    if best[1] == 0:
        evidence.append("No conclusive signal; left unclassified rather than guessed")

    return Classification(asset_type=best[0], confidence=best[1], evidence=evidence)


# ---------------------------------------------------------------------------
# Network placement
# ---------------------------------------------------------------------------

def find_network_for_ip(db: Session, organization_id: uuid.UUID, ip_address: str) -> Network | None:
    """Place an IP into a declared network, if one contains it."""
    import ipaddress

    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return None

    networks = db.execute(
        select(Network).where(Network.organization_id == organization_id)
    ).scalars().all()

    best: Network | None = None
    best_prefix = -1
    for network in networks:
        try:
            candidate = ipaddress.ip_network(network.cidr, strict=False)
        except ValueError:
            continue
        if address in candidate and candidate.prefixlen > best_prefix:
            best, best_prefix = network, candidate.prefixlen
    return best


# ---------------------------------------------------------------------------
# Upserts
# ---------------------------------------------------------------------------

def upsert_asset(
    db: Session,
    organization_id: uuid.UUID,
    ip_address: str,
    hostname: str | None = None,
    mac_address: str | None = None,
    vendor: str | None = None,
    os_match: str | None = None,
    service_names: list[str] | None = None,
    scan_job_id: uuid.UUID | None = None,
    observed_at: datetime | None = None,
) -> tuple[Asset, bool]:
    """Create or refresh the asset for an observed host. Returns (asset, created)."""
    observed_at = observed_at or datetime.now(timezone.utc)

    asset = db.execute(
        select(Asset).where(
            Asset.organization_id == organization_id,
            Asset.ip_address == ip_address,
        )
    ).scalar_one_or_none()

    classification = classify_device(os_match, service_names or [], vendor)
    created = asset is None

    if created:
        asset = Asset(
            organization_id=organization_id,
            hostname=hostname or ip_address,
            ip_address=ip_address,
            status=AssetStatus.ACTIVE,
            first_seen=observed_at,
        )
        db.add(asset)

    if hostname:
        asset.hostname = hostname
    if mac_address:
        asset.mac_address = mac_address
    if vendor:
        asset.vendor = vendor
    if os_match:
        asset.operating_system = os_match

    # Only overwrite an existing classification when the new evidence is at
    # least as strong. A quick discovery sweep must not downgrade a device that
    # a credentialed scan previously identified with high confidence.
    if classification.confidence >= (asset.fingerprint_confidence or 0):
        asset.asset_type = classification.asset_type
        asset.fingerprint_confidence = classification.confidence
        asset.fingerprint_evidence = classification.evidence

    asset.last_seen = observed_at
    if scan_job_id:
        asset.scan_job_id = scan_job_id

    network = find_network_for_ip(db, organization_id, ip_address)
    if network is not None:
        asset.network_id = network.id
        if network.site_id:
            asset.site_id = network.site_id
        # Internet exposure is a property an operator declared on the network.
        # It is never inferred from the address itself.
        asset.is_internet_facing = network.is_internet_facing

    db.flush()
    return asset, created


def upsert_interface(
    db: Session,
    asset: Asset,
    ip_address: str,
    mac_address: str | None = None,
    mac_vendor: str | None = None,
    is_primary: bool = False,
    observed_at: datetime | None = None,
) -> AssetInterface:
    observed_at = observed_at or datetime.now(timezone.utc)

    interface = db.execute(
        select(AssetInterface).where(
            AssetInterface.asset_id == asset.id,
            AssetInterface.ip_address == ip_address,
        )
    ).scalar_one_or_none()

    if interface is None:
        interface = AssetInterface(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            ip_address=ip_address,
            first_seen=observed_at,
        )
        db.add(interface)

    if mac_address:
        interface.mac_address = mac_address
    if mac_vendor:
        interface.mac_vendor = mac_vendor
    interface.is_primary = is_primary or interface.is_primary
    interface.last_seen = observed_at
    db.flush()
    return interface


def upsert_service(
    db: Session,
    asset: Asset,
    port: int,
    protocol: str = "tcp",
    service_name: str = "",
    product: str = "",
    version: str = "",
    banner: str = "",
    observed_at: datetime | None = None,
) -> AssetService:
    observed_at = observed_at or datetime.now(timezone.utc)

    service = db.execute(
        select(AssetService).where(
            AssetService.asset_id == asset.id,
            AssetService.port == port,
            AssetService.protocol == protocol,
        )
    ).scalar_one_or_none()

    if service is None:
        service = AssetService(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            port=port,
            protocol=protocol,
            first_seen=observed_at,
        )
        db.add(service)

    service.service_name = service_name or service.service_name
    service.product = product or service.product
    service.version = version or service.version
    if banner:
        service.banner = banner[:MAX_BANNER_CHARS]
    service.is_tls = _looks_like_tls(port, service_name)
    service.state = "open"
    service.last_seen = observed_at
    db.flush()
    return service


def upsert_software(
    db: Session,
    asset: Asset,
    name: str,
    version: str = "",
    vendor: str = "",
    cpe: str | None = None,
    detection_method: str = "service_banner",
    evidence: str = "",
    asset_service_id: uuid.UUID | None = None,
    observed_at: datetime | None = None,
) -> AssetSoftware | None:
    """
    Record a software component.

    Returns None for an unnamed component rather than creating a row that
    cannot be correlated or acted on.
    """
    if not name:
        return None

    observed_at = observed_at or datetime.now(timezone.utc)

    software = db.execute(
        select(AssetSoftware).where(
            AssetSoftware.asset_id == asset.id,
            AssetSoftware.name == name,
            AssetSoftware.version == version,
        )
    ).scalar_one_or_none()

    if software is None:
        software = AssetSoftware(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            name=name,
            version=version,
            first_seen=observed_at,
        )
        db.add(software)

    software.vendor = vendor or software.vendor
    # A CPE is only stored when the scanner supplied one. Constructing a
    # plausible-looking CPE from a product name would produce confident,
    # incorrect CVE matches.
    if cpe:
        software.cpe = cpe
    software.detection_method = detection_method
    if evidence:
        software.evidence = evidence[:MAX_BANNER_CHARS]
    software.asset_service_id = asset_service_id or software.asset_service_id
    software.last_seen = observed_at
    db.flush()
    return software


def mark_services_closed(
    db: Session, asset: Asset, seen_ports: set[tuple[int, str]], observed_at: datetime | None = None
) -> int:
    """
    Mark services a rescan no longer observed as closed.

    The rows are kept rather than deleted: "port 3389 was open until Tuesday"
    is exactly the history change detection and reporting need.
    """
    observed_at = observed_at or datetime.now(timezone.utc)

    services = db.execute(
        select(AssetService).where(
            AssetService.asset_id == asset.id,
            AssetService.state == "open",
        )
    ).scalars().all()

    closed = 0
    for service in services:
        if (service.port, service.protocol) in seen_ports:
            continue
        service.state = "closed"
        service.last_seen = observed_at
        db.add(service)
        closed += 1
    return closed


def _looks_like_tls(port: int, service_name: str) -> bool:
    if port in (443, 465, 636, 993, 995, 8443, 5986):
        return True
    name = (service_name or "").lower()
    return "https" in name or "ssl" in name or "tls" in name
