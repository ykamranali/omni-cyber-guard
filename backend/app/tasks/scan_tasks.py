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
import concurrent.futures
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
            from app.scanners.manager import ScannerManager
            nmap_scanner = ScannerManager.get_scanner("nmap")
            
            if not nmap_scanner:
                raise RuntimeError("Nmap scanner plugin not registered.")
                
            def log_progress(line: str):
                db_session = SessionLocal()
                try:
                    active_job = db_session.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_job_id)).first()
                    if active_job:
                        if active_job.status == ScanStatus.FAILED:
                            raise RuntimeError("Scan manually canceled by user.")
                        active_job.raw_summary = (active_job.raw_summary or "") + line + "\n"
                        db_session.commit()
                finally:
                    db_session.close()
                
            nmap_result = nmap_scanner.execute(job.target_cidr, progress_callback=log_progress)
            hosts = nmap_result.raw_data
            
        except (RuntimeError, Exception) as exc: # catching ScanAuthorizationError via Exception for now since it's wrapped
            from app.services.network_scanner import ScanAuthorizationError
            if isinstance(exc, ScanAuthorizationError) or isinstance(exc, RuntimeError):
                job.status = ScanStatus.FAILED
                job.error_message = str(exc)
                db.commit()
                return
            raise

        findings_generated = 0
        touched_assets: list[Asset] = []
        nuclei_scanner = None
        try:
            from app.scanners.manager import ScannerManager
            nuclei_scanner = ScannerManager.get_scanner("nuclei")
        except Exception:
            pass

        for host in hosts:
            asset = (
                db.query(Asset)
                .filter(Asset.organization_id == job.organization_id, Asset.ip_address == host.ip_address)
                .first()
            )
            if not asset:
                derived_type = AssetType.OTHER
                if host.os_match:
                    os_lower = host.os_match.lower()
                    if "server" in os_lower or "linux" in os_lower or "bsd" in os_lower:
                        derived_type = AssetType.SERVER
                    elif "windows" in os_lower or "macos" in os_lower or "mac os" in os_lower:
                        derived_type = AssetType.WORKSTATION
                    elif "cisco" in os_lower or "router" in os_lower or "switch" in os_lower:
                        derived_type = AssetType.NETWORK_DEVICE

                asset = Asset(
                    organization_id=job.organization_id,
                    hostname=host.hostname or host.ip_address,
                    ip_address=host.ip_address,
                    asset_type=derived_type,
                    status=AssetStatus.ACTIVE,
                    operating_system=host.os_match,
                    tags=["discovered-by-scan"],
                    scan_job_id=job.id,
                )
                db.add(asset)
                db.flush()
            else:
                asset.scan_job_id = job.id
                if host.hostname:
                    asset.hostname = host.hostname
                if host.os_match:
                    asset.operating_system = host.os_match
                    os_lower = host.os_match.lower()
                    if "server" in os_lower or "linux" in os_lower or "bsd" in os_lower:
                        asset.asset_type = AssetType.SERVER
                    elif "windows" in os_lower or "macos" in os_lower or "mac os" in os_lower:
                        asset.asset_type = AssetType.WORKSTATION
                    elif "cisco" in os_lower or "router" in os_lower or "switch" in os_lower:
                        asset.asset_type = AssetType.NETWORK_DEVICE

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
                    existing.scan_job_id = job.id
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
                    scan_job_id=job.id,
                )
                db.add(finding)
                findings_generated += 1

                for script in scanned_port.scripts:
                    existing_script = db.query(Finding).filter(Finding.asset_id == asset.id, Finding.source == "nmap_script", Finding.title == f"Nmap Script ({scanned_port.port}): {script.id}").first()
                    if existing_script:
                        existing_script.scan_job_id = job.id
                    if not existing_script:
                        script_severity = Severity.HIGH if "VULNERABLE" in script.output or "vuln" in script.id else Severity.INFO
                        if script_severity == Severity.HIGH and "critical" in script.output.lower():
                            script_severity = Severity.CRITICAL
                            
                        script_finding = Finding(
                            organization_id=job.organization_id,
                            asset_id=asset.id,
                            title=f"Nmap Script ({scanned_port.port}): {script.id}",
                            description=f"Nmap script '{script.id}' executed on port {scanned_port.port}/{scanned_port.protocol}. This often indicates an outdated application version or misconfiguration.\n\nEvidence:\n{script.output[:2000]}",
                            severity=script_severity,
                            status=FindingStatus.OPEN,
                            remediation_guidance="Review script evidence and apply necessary software updates or patches.",
                            source="nmap_script",
                            scan_job_id=job.id,
                        )
                        db.add(script_finding)
                        findings_generated += 1
                        
            for script in host.scripts:
                existing_script = db.query(Finding).filter(Finding.asset_id == asset.id, Finding.source == "nmap_script", Finding.title == f"Nmap Script (Host): {script.id}").first()
                if existing_script:
                    existing_script.scan_job_id = job.id
                if not existing_script:
                    script_severity = Severity.HIGH if "VULNERABLE" in script.output or "vuln" in script.id else Severity.INFO
                    script_finding = Finding(
                        organization_id=job.organization_id,
                        asset_id=asset.id,
                        title=f"Nmap Script (Host): {script.id}",
                        description=f"Nmap script '{script.id}' executed on host {host.ip_address}.\n\nEvidence:\n{script.output[:2000]}",
                        severity=script_severity,
                        status=FindingStatus.OPEN,
                        remediation_guidance="Review script evidence and apply necessary updates.",
                        source="nmap_script",
                        scan_job_id=job.id,
                    )
                    db.add(script_finding)
                    findings_generated += 1

            if nuclei_scanner and nuclei_scanner.is_available():
                def scan_target(target_url, asset):
                    generated = 0
                    try:
                        n_result = nuclei_scanner.execute(target_url)
                        for nf in n_result.findings:
                            severity_str = nf.get("severity", "info").lower()
                            db_severity = Severity.INFO
                            if severity_str == "critical": db_severity = Severity.CRITICAL
                            elif severity_str == "high": db_severity = Severity.HIGH
                            elif severity_str == "medium": db_severity = Severity.MEDIUM
                            elif severity_str == "low": db_severity = Severity.LOW

                            nuclei_finding = Finding(
                                organization_id=job.organization_id,
                                asset_id=asset.id,
                                title=nf.get("title", "Nuclei Finding"),
                                description=f'{nf.get("description", "")}\n\nEvidence:\n{nf.get("evidence", "")}',
                                severity=db_severity,
                                status=FindingStatus.OPEN,
                                remediation_guidance=nf.get("remediation_guidance", ""),
                                source="nuclei"
                            )
                            db.add(nuclei_finding)
                            generated += 1
                    except Exception:
                        pass
                    return generated

                targets = []
                for scanned_port in host.ports:
                    if scanned_port.service in ("http", "https") or scanned_port.port in (80, 443, 8080, 8443):
                        protocol = "https" if scanned_port.port in (443, 8443) else "http"
                        targets.append(f"{protocol}://{host.ip_address}:{scanned_port.port}")
                
                if targets:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                        futures = [executor.submit(scan_target, t, asset) for t in targets]
                        for future in concurrent.futures.as_completed(futures):
                            findings_generated += future.result()

        db.commit()

        for asset in touched_assets:
            recompute_asset_risk_score(db, asset)

        job.status = ScanStatus.COMPLETED
        job.hosts_discovered = len(hosts)
        job.findings_generated = findings_generated
        job.raw_summary = (job.raw_summary or "") + f"\nScan Complete: Discovered {len(hosts)} live host(s); generated {findings_generated} new finding(s)."
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
