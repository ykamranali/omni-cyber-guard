"""
Celery task that executes an authorized network scan and turns the real
results into asset inventory updates and findings. No fabricated data is
ever written: every asset field and every finding comes directly from a
parsed nmap result.
"""
import uuid

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.finding import Finding, Severity, FindingStatus
from app.models.scan_job import ScanJob, ScanStatus
from app.services.network_scanner import (
    run_discovery_and_service_scan, ScanAuthorizationError, RISKY_PORTS,
)
from app.services.risk_scoring import recompute_asset_risk_score


@celery_app.task(name="scan_tasks.run_network_scan")
def run_network_scan(scan_job_id: str) -> None:
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_job_id)).first()
        if not job:
            return

        job.status = ScanStatus.RUNNING
        db.commit()

        try:
            hosts = run_discovery_and_service_scan(job.target_cidr)
        except (ScanAuthorizationError, RuntimeError) as exc:
            job.status = ScanStatus.FAILED
            job.error_message = str(exc)
            db.commit()
            return

        findings_generated = 0
        touched_assets: list[Asset] = []

        for host in hosts:
            asset = (
                db.query(Asset)
                .filter(Asset.organization_id == job.organization_id, Asset.ip_address == host.ip_address)
                .first()
            )
            if not asset:
                asset = Asset(
                    organization_id=job.organization_id,
                    hostname=host.hostname or host.ip_address,
                    ip_address=host.ip_address,
                    asset_type=AssetType.OTHER,
                    status=AssetStatus.ACTIVE,
                    tags=["discovered-by-scan"],
                )
                db.add(asset)
                db.flush()
            else:
                if host.hostname:
                    asset.hostname = host.hostname

            if host.mac_address:
                asset.mac_address = host.mac_address
            if host.vendor:
                asset.vendor = host.vendor

            open_ports_summary = [
                {"port": p.port, "protocol": p.protocol, "service": p.service, "product": p.product, "version": p.version}
                for p in host.ports
            ]
            asset.custom_fields = {**(asset.custom_fields or {}), "open_ports": open_ports_summary, "last_scanned_by": str(job.id)}
            db.add(asset)
            db.flush()
            touched_assets.append(asset)

            for scanned_port in host.ports:
                if scanned_port.port not in RISKY_PORTS:
                    continue
                service_label, guidance = RISKY_PORTS[scanned_port.port]

                existing = (
                    db.query(Finding)
                    .filter(
                        Finding.asset_id == asset.id,
                        Finding.source == "network_scan",
                        Finding.title.like(f"%{service_label}%port {scanned_port.port}%"),
                        Finding.status == FindingStatus.OPEN,
                    )
                    .first()
                )
                if existing:
                    continue

                severity = Severity.HIGH if scanned_port.port in (3389, 23, 445, 5900) else Severity.MEDIUM
                finding = Finding(
                    organization_id=job.organization_id,
                    asset_id=asset.id,
                    title=f"Exposed {service_label} service on port {scanned_port.port}",
                    description=(
                        f"Network scan detected an open {service_label} port ({scanned_port.port}/{scanned_port.protocol}) "
                        f"on {asset.hostname} ({host.ip_address})."
                        + (f" Detected service: {scanned_port.product} {scanned_port.version}.".strip() if scanned_port.product else "")
                    ),
                    severity=severity,
                    status=FindingStatus.OPEN,
                    remediation_guidance=guidance,
                    source="network_scan",
                )
                db.add(finding)
                findings_generated += 1

        db.commit()

        for asset in touched_assets:
            recompute_asset_risk_score(db, asset)

        job.status = ScanStatus.COMPLETED
        job.hosts_discovered = len(hosts)
        job.findings_generated = findings_generated
        job.raw_summary = f"Discovered {len(hosts)} live host(s); generated {findings_generated} new finding(s)."
        db.commit()

    except Exception as exc:  # noqa: BLE001 - surface any unexpected failure to the job record
        db.rollback()
        job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_job_id)).first()
        if job:
            job.status = ScanStatus.FAILED
            job.error_message = f"Unexpected error: {exc}"
            db.commit()
        raise
    finally:
        db.close()
