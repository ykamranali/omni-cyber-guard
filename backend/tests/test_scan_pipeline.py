"""
End of the scan pipeline: parsed scanner output becomes inventory and findings.

This is the join between `persist_host` and the ingest services, exercised with
the dataclasses the nmap parser actually produces.
"""
from datetime import datetime, timedelta, timezone

from app.models.asset import Asset, AssetType
from app.models.asset_detail import AssetService, AssetSoftware
from app.models.finding import Confidence, Finding, FindingClass, FindingStatus, Severity
from app.services.finding_ingest import close_unseen_findings, ingest_findings
from app.services.network_scanner import ScannedHost, ScannedPort, ScannedScript
from app.tasks.scan_tasks import persist_host

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
LATER = NOW + timedelta(days=2)


def _host(**overrides):
    defaults = dict(
        ip_address="192.168.1.77",
        hostname="dc01.corp.local",
        mac_address="00:11:22:33:44:55",
        vendor="Dell Inc.",
        os_match="Windows Server 2019",
        ports=[
            ScannedPort(port=3389, protocol="tcp", service="ms-wbt-server",
                        product="Microsoft Terminal Services", version="", scripts=[]),
            ScannedPort(port=22, protocol="tcp", service="ssh",
                        product="OpenSSH", version="8.9p1", scripts=[]),
            ScannedPort(port=8443, protocol="tcp", service="https",
                        product="nginx", version="1.24.0", scripts=[]),
        ],
        scripts=[],
    )
    defaults.update(overrides)
    return ScannedHost(**defaults)


def _run(db, job, host, observed_at=NOW):
    asset, payloads = persist_host(db, job, host, observed_at)
    result = ingest_findings(db, job.organization_id, payloads, job.id, observed_at)
    db.flush()
    return asset, result


# --- inventory -----------------------------------------------------------

def test_host_becomes_an_asset_with_services_and_software(db, organization, scan_job):
    asset, _ = _run(db, scan_job, _host())

    assert asset.ip_address == "192.168.1.77"
    assert asset.hostname == "dc01.corp.local"
    assert asset.asset_type == AssetType.SERVER
    assert asset.mac_address == "00:11:22:33:44:55"

    ports = {service.port for service in db.query(AssetService).filter(AssetService.asset_id == asset.id)}
    assert ports == {22, 3389, 8443}

    software = {row.name for row in db.query(AssetSoftware).filter(AssetSoftware.asset_id == asset.id)}
    assert "OpenSSH" in software
    assert "nginx" in software


def test_a_primary_interface_is_recorded(db, organization, scan_job):
    asset, _ = _run(db, scan_job, _host())
    assert len(asset.interfaces) == 1
    interface = asset.interfaces[0]
    assert interface.ip_address == "192.168.1.77"
    assert interface.mac_vendor == "Dell Inc."
    assert interface.is_primary is True


def test_rescanning_does_not_duplicate_the_asset(db, organization, scan_job):
    _run(db, scan_job, _host())
    _run(db, scan_job, _host(hostname="dc01-renamed.corp.local"), LATER)

    assets = db.query(Asset).filter(Asset.ip_address == "192.168.1.77").all()
    assert len(assets) == 1
    assert assets[0].hostname == "dc01-renamed.corp.local"


def test_a_port_that_closes_between_scans_is_marked_closed(db, organization, scan_job):
    _run(db, scan_job, _host())
    remaining = [port for port in _host().ports if port.port != 3389]
    _run(db, scan_job, _host(ports=remaining), LATER)

    rdp = db.query(AssetService).filter(AssetService.port == 3389).one()
    assert rdp.state == "closed"


# --- findings ------------------------------------------------------------

def test_a_risky_port_produces_an_exposure_finding_with_evidence(db, organization, scan_job):
    asset, result = _run(db, scan_job, _host())

    rdp = db.query(Finding).filter(
        Finding.asset_id == asset.id, Finding.title.like("%3389%")
    ).one()

    assert rdp.finding_class == FindingClass.EXPOSURE
    assert rdp.confidence == Confidence.CONFIRMED
    assert rdp.severity == Severity.HIGH
    assert "tcp/3389 open" in rdp.evidence
    assert rdp.asset_service_id is not None
    assert result.created >= 1


def test_an_ordinary_port_produces_no_finding(db, organization, scan_job):
    asset, _ = _run(db, scan_job, _host(ports=[
        ScannedPort(port=8443, protocol="tcp", service="https", product="nginx",
                    version="1.24.0", scripts=[]),
    ]))
    assert db.query(Finding).filter(Finding.asset_id == asset.id).count() == 0


def test_rescanning_updates_findings_instead_of_duplicating(db, organization, scan_job):
    asset, first = _run(db, scan_job, _host())
    _, second = _run(db, scan_job, _host(), LATER)

    assert first.created > 0
    assert second.created == 0
    assert second.updated == first.created

    finding = db.query(Finding).filter(Finding.title.like("%3389%")).one()
    assert finding.occurrence_count == 2
    assert finding.first_seen == NOW
    assert finding.last_seen == LATER


def test_a_finding_that_disappears_is_resolved_by_the_rescan(db, organization, scan_job):
    asset, _ = _run(db, scan_job, _host())
    remaining = [port for port in _host().ports if port.port != 3389]
    _, result = _run(db, scan_job, _host(ports=remaining), LATER)

    closed = close_unseen_findings(
        db, organization.id, asset.id, "nmap", result.fingerprints, scan_job.id, LATER
    )
    db.flush()

    assert len(closed) == 1
    rdp = db.query(Finding).filter(Finding.title.like("%3389%")).one()
    assert rdp.status == FindingStatus.REMEDIATED
    assert rdp.resolved_by_scan_job_id == scan_job.id


# --- script results ------------------------------------------------------

def test_a_vulnerable_script_result_is_probable_not_confirmed(db, organization, scan_job):
    """NSE often decides from a version banner, which can be wrong both ways."""
    host = _host(ports=[ScannedPort(
        port=445, protocol="tcp", service="microsoft-ds", product="", version="",
        scripts=[ScannedScript(id="smb-vuln-ms17-010",
                               output="VULNERABLE: Remote Code Execution (CVE-2017-0143)")],
    )])
    asset, _ = _run(db, scan_job, host)

    finding = db.query(Finding).filter(Finding.title.like("%smb-vuln-ms17-010%")).one()
    assert finding.finding_class == FindingClass.VULNERABILITY
    assert finding.confidence == Confidence.PROBABLE
    assert finding.severity == Severity.HIGH
    assert finding.cve_id == "CVE-2017-0143"
    assert "VULNERABLE" in finding.evidence


def test_a_benign_script_result_is_informational(db, organization, scan_job):
    host = _host(ports=[], scripts=[ScannedScript(id="smb2-time", output="date: 2026-08-21")])
    asset, _ = _run(db, scan_job, host)

    finding = db.query(Finding).filter(Finding.asset_id == asset.id).one()
    assert finding.finding_class == FindingClass.INFORMATIONAL
    assert finding.severity == Severity.INFO
    # A recorded fact observed directly is confirmed; it is simply not a defect.
    assert finding.confidence == Confidence.CONFIRMED


def test_the_same_script_on_two_ports_is_two_findings(db, organization, scan_job):
    script = ScannedScript(id="ssl-cert", output="Subject: CN=example")
    host = _host(ports=[
        ScannedPort(port=443, protocol="tcp", service="https", product="", version="", scripts=[script]),
        ScannedPort(port=8443, protocol="tcp", service="https", product="", version="", scripts=[script]),
    ])
    asset, _ = _run(db, scan_job, host)
    assert db.query(Finding).filter(Finding.title.like("%ssl-cert%")).count() == 2
