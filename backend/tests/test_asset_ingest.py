"""
Asset inventory ingestion: classification honesty, service history and
network placement.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.models.asset import AssetType
from app.models.asset_detail import AssetService, AssetSoftware
from app.models.network import Network
from app.models.site import Site
from app.services.asset_ingest import (
    classify_device, find_network_for_ip, mark_services_closed, upsert_asset,
    upsert_interface, upsert_service, upsert_software,
)

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=1)


# --- classification ------------------------------------------------------

@pytest.mark.parametrize("os_string,expected", [
    ("FortiOS 7.4", AssetType.FIREWALL),
    ("Cisco IOS 15.2", AssetType.ROUTER),
    ("VMware ESXi 7.0", AssetType.HYPERVISOR),
    ("HP LaserJet printer", AssetType.PRINTER),
    ("Windows Server 2019", AssetType.SERVER),
    ("Windows 11 Pro", AssetType.WORKSTATION),
    ("Synology DSM", AssetType.NAS),
])
def test_os_fingerprints_classify_devices(os_string, expected):
    result = classify_device(os_string, [], None)
    assert result.asset_type == expected
    assert result.confidence > 0
    assert result.evidence, "a classification must carry the evidence behind it"


def test_unrecognised_signals_stay_unclassified():
    """A guess presented as a fact is worse than an honest 'unknown'."""
    result = classify_device("Frobnicator OS 3", [], None)
    assert result.asset_type == AssetType.OTHER
    assert result.confidence == 0
    assert "left unclassified rather than guessed" in " ".join(result.evidence)


def test_services_classify_when_the_os_is_unknown():
    result = classify_device(None, ["mysql", "ssh"], None)
    assert result.asset_type == AssetType.DATABASE
    assert result.confidence > 0


def test_a_mac_vendor_alone_never_classifies():
    result = classify_device(None, [], "Dell Inc.")
    assert result.asset_type == AssetType.OTHER
    assert result.confidence == 0


def test_a_corroborating_vendor_raises_confidence():
    without = classify_device("Windows Server 2019", [], None)
    with_vendor = classify_device("Windows Server 2019", [], "Dell Inc.")
    assert with_vendor.confidence > without.confidence
    assert with_vendor.confidence <= 95


# --- asset upsert --------------------------------------------------------

def test_asset_is_created_from_observed_values(db, organization):
    asset, created = upsert_asset(
        db, organization.id, "192.168.1.77",
        hostname="dc01.corp.local", mac_address="00:11:22:33:44:55",
        vendor="Dell Inc.", os_match="Windows Server 2019",
        service_names=["ldap", "kerberos"], observed_at=NOW,
    )
    assert created
    assert asset.hostname == "dc01.corp.local"
    assert asset.asset_type == AssetType.SERVER
    assert asset.first_seen == NOW
    assert asset.last_seen == NOW
    assert asset.fingerprint_evidence


def test_rescan_updates_last_seen_but_not_first_seen(db, organization):
    upsert_asset(db, organization.id, "192.168.1.77", hostname="a", observed_at=NOW)
    asset, created = upsert_asset(db, organization.id, "192.168.1.77", hostname="b", observed_at=LATER)
    assert not created
    assert asset.first_seen == NOW
    assert asset.last_seen == LATER
    assert asset.hostname == "b"


def test_a_weaker_scan_does_not_downgrade_a_confident_classification(db, organization):
    """A quick sweep must not undo what a detailed scan established."""
    upsert_asset(db, organization.id, "192.168.1.5", os_match="FortiOS 7.4", observed_at=NOW)
    asset, _ = upsert_asset(db, organization.id, "192.168.1.5", os_match=None, observed_at=LATER)
    assert asset.asset_type == AssetType.FIREWALL


# --- network placement ---------------------------------------------------

def test_asset_is_placed_into_its_declared_network(db, organization):
    site = Site(organization_id=organization.id, name="HQ")
    db.add(site)
    db.flush()
    network = Network(
        organization_id=organization.id, site_id=site.id, name="Server VLAN",
        cidr="192.168.10.0/24", is_internet_facing=False, is_authorized_scope=True,
    )
    db.add(network)
    db.flush()

    asset, _ = upsert_asset(db, organization.id, "192.168.10.20", observed_at=NOW)
    assert asset.network_id == network.id
    assert asset.site_id == site.id


def test_the_most_specific_network_wins(db, organization):
    db.add(Network(organization_id=organization.id, name="Wide", cidr="10.0.0.0/8"))
    specific = Network(organization_id=organization.id, name="Narrow", cidr="10.1.2.0/24")
    db.add(specific)
    db.flush()

    assert find_network_for_ip(db, organization.id, "10.1.2.3").id == specific.id


def test_internet_exposure_comes_from_the_declared_network_not_the_address(db, organization):
    """Exposure is a fact an operator asserts, never inferred from an IP."""
    db.add(Network(
        organization_id=organization.id, name="DMZ", cidr="192.168.99.0/24",
        is_internet_facing=True,
    ))
    db.flush()
    asset, _ = upsert_asset(db, organization.id, "192.168.99.10", observed_at=NOW)
    assert asset.is_internet_facing is True


def test_an_asset_outside_every_declared_network_is_not_marked_exposed(db, organization):
    asset, _ = upsert_asset(db, organization.id, "172.16.4.4", observed_at=NOW)
    assert asset.network_id is None
    assert asset.is_internet_facing is False


# --- services and software ----------------------------------------------

def test_services_are_rows_not_a_json_blob(db, organization, asset):
    upsert_service(db, asset, port=22, service_name="ssh", product="OpenSSH", version="8.9p1", observed_at=NOW)
    upsert_service(db, asset, port=443, service_name="https", product="nginx", version="1.24.0", observed_at=NOW)
    db.flush()

    services = db.query(AssetService).filter(AssetService.asset_id == asset.id).all()
    assert {service.port for service in services} == {22, 443}
    assert next(s for s in services if s.port == 443).is_tls is True


def test_rescanning_a_service_updates_it_in_place(db, organization, asset):
    upsert_service(db, asset, port=22, product="OpenSSH", version="8.9p1", observed_at=NOW)
    upsert_service(db, asset, port=22, product="OpenSSH", version="9.6p1", observed_at=LATER)
    db.flush()

    service = db.query(AssetService).filter(AssetService.asset_id == asset.id).one()
    assert service.version == "9.6p1"
    assert service.first_seen == NOW
    assert service.last_seen == LATER


def test_a_service_that_disappears_is_closed_not_deleted(db, organization, asset):
    """'Port 3389 was open until Tuesday' is exactly what change detection needs."""
    upsert_service(db, asset, port=3389, service_name="ms-wbt-server", observed_at=NOW)
    upsert_service(db, asset, port=22, service_name="ssh", observed_at=NOW)
    db.flush()

    closed = mark_services_closed(db, asset, seen_ports={(22, "tcp")}, observed_at=LATER)
    db.flush()

    assert closed == 1
    rdp = db.query(AssetService).filter(AssetService.port == 3389).one()
    assert rdp.state == "closed"
    assert db.query(AssetService).filter(AssetService.asset_id == asset.id).count() == 2


def test_software_without_a_cpe_is_recorded_but_left_uncorrelatable(db, organization, asset):
    """A fabricated CPE would produce confident, wrong CVE matches."""
    software = upsert_software(db, asset, name="OpenSSH", version="8.9p1", observed_at=NOW)
    db.flush()
    assert software.cpe is None
    assert software.name == "OpenSSH"


def test_a_supplied_cpe_is_kept(db, organization, asset):
    software = upsert_software(
        db, asset, name="nginx", version="1.24.0",
        cpe="cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", observed_at=NOW,
    )
    db.flush()
    assert software.cpe.startswith("cpe:2.3:a:f5:nginx")


def test_unnamed_software_is_not_recorded(db, organization, asset):
    assert upsert_software(db, asset, name="", version="1.0", observed_at=NOW) is None
    db.flush()
    assert db.query(AssetSoftware).filter(AssetSoftware.asset_id == asset.id).count() == 0


def test_interfaces_are_tracked_per_ip(db, organization, asset):
    upsert_interface(db, asset, "192.168.1.50", mac_address="AA:BB:CC:DD:EE:FF", is_primary=True, observed_at=NOW)
    upsert_interface(db, asset, "10.0.0.50", mac_address="AA:BB:CC:DD:EE:00", observed_at=NOW)
    db.flush()
    assert len(asset.interfaces) == 2
