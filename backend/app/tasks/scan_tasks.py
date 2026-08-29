"""
Celery task that executes an authorized scan and turns the real results into
asset inventory and findings.

Nothing here fabricates data. Every asset field and every finding is derived
from parsed scanner output, and every finding carries the verbatim evidence
that produced it.

The persistence pipeline is:

    scanner output
      -> asset upsert            (app/services/asset_ingest.py)
      -> interfaces / services / software
      -> normalized findings     (app/services/finding_ingest.py)
      -> findings the scan no longer sees are closed by evidence
      -> risk recomputed

Deduplication and lifecycle live in those services, not here, so every source
of findings gets the same treatment.
"""
from __future__ import annotations

import concurrent.futures
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_ as sa_and, or_ as sa_or

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant, set_tenant
from app.models.asset import Asset
from app.models.finding import Confidence, FindingClass, Severity
from app.models.scan_job import ScanJob, ScanStatus
from app.services.asset_ingest import (
    mark_services_closed, upsert_asset, upsert_interface, upsert_service, upsert_software,
)
from app.services.finding_identity import compute_fingerprint, service_location
from app.services.finding_ingest import (
    FindingInput, close_unseen_findings, ingest_findings,
)
from app.scanners.contract import (
    ScanCredential, ScanRequest, ScannerAdapter, SessionState,
)
from app.services.credential_access import resolve_credential
from app.services.events import publish_event
from app.services.network_scanner import RISKY_PORTS, ScanAuthorizationError
from app.services.exposure_engine import recompute_asset_exposure
from app.services.remediation_engine import reopen_from_scan, verify_from_scan
from app.services.risk_scoring import recompute_asset_risk_score
from app.services.vulnerability_correlation import correlate_asset

logger = logging.getLogger(__name__)

PROGRESS_FLUSH_SECONDS = 2.0
PROGRESS_FLUSH_LINES = 40
MAX_RAW_SUMMARY_CHARS = 200_000
CANCEL_POLL_SECONDS = 3.0

#: How often a running scan proves it is still alive. Frequent enough that an
#: orphan is noticed quickly, rare enough to be one small UPDATE a minute.
HEARTBEAT_SECONDS = 30.0

#: A RUNNING job whose heartbeat is older than this has no worker behind it.
#: Comfortably more than HEARTBEAT_SECONDS so that a busy worker, a slow write
#: or a brief database hiccup is never mistaken for a dead one.
ORPHAN_AFTER_SECONDS = 300.0
# A /24 at top-1000 ports with OS detection and the vuln script set takes
# well over half an hour. The previous 30-minute budget terminated such a
# scan partway and recorded it as a timeout, which reads as a fault in the
# scanner rather than a budget that was too small for what was asked.
SCAN_TIMEOUT_SECONDS = 3600
SESSION_POLL_SECONDS = 1.0

#: Sentinel returned by _run_session when an operator cancelled the scan.
CANCELED = object()

SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Ports whose exposure warrants HIGH rather than MEDIUM on hygiene grounds.
HIGH_RISK_PORTS = frozenset({23, 445, 3389, 5900})


def _severity_from_name(name: str | None) -> Severity:
    return SEVERITY_BY_NAME.get((name or "info").strip().lower(), Severity.INFO)


class ScanProgressReporter:
    """Buffers scanner stdout and flushes it to the job record on an interval.

    Also serves as the cancellation probe, so the running scan and the progress
    log share a single throttled database round-trip pattern instead of opening
    a session per output line.
    """

    def __init__(self, scan_job_id: uuid.UUID):
        self.scan_job_id = scan_job_id
        self._buffer: list[str] = []
        self._last_flush = time.monotonic()
        self._last_cancel_check = 0.0
        self._cancel_cached = False
        self._truncated = False
        self._stored_chars = 0

    def __call__(self, line: str) -> None:
        self._buffer.append(line.rstrip("\n"))
        if (
            len(self._buffer) >= PROGRESS_FLUSH_LINES
            or time.monotonic() - self._last_flush >= PROGRESS_FLUSH_SECONDS
        ):
            self.flush()

    def flush(self) -> None:
        if not self._buffer:
            self._last_flush = time.monotonic()
            return

        chunk = "\n".join(self._buffer) + "\n"
        self._buffer.clear()
        self._last_flush = time.monotonic()

        if self._stored_chars >= MAX_RAW_SUMMARY_CHARS:
            if self._truncated:
                return
            self._truncated = True
            chunk = "\n[output truncated — scan log exceeded the stored size limit]\n"

        db = SessionLocal()
        try:
            bypass_tenant(db)
            job = db.query(ScanJob).filter(ScanJob.id == self.scan_job_id).first()
            if job is None:
                return
            job.raw_summary = (job.raw_summary or "") + chunk
            self._stored_chars = len(job.raw_summary)
            db.commit()
            # Already rate-limited: flush runs at most every PROGRESS_FLUSH_SECONDS
            # or every PROGRESS_FLUSH_LINES lines, so this cannot flood the
            # channel with one message per line of nmap output.
            publish_event(
                job.organization_id, "scan_progress",
                scan_job_id=str(job.id),
                last_line=chunk.rstrip("\n").rsplit("\n", 1)[-1][:200],
            )
        except Exception:
            db.rollback()
            logger.exception("scan %s: failed to persist progress output", self.scan_job_id)
        finally:
            db.close()

    def cancel_requested(self) -> bool:
        now = time.monotonic()
        if now - self._last_cancel_check < CANCEL_POLL_SECONDS:
            return self._cancel_cached
        self._last_cancel_check = now

        db = SessionLocal()
        try:
            bypass_tenant(db)
            self._cancel_cached = bool(
                db.query(ScanJob.cancel_requested).filter(ScanJob.id == self.scan_job_id).scalar()
            )
        except Exception:
            logger.exception("scan %s: failed to read cancel flag", self.scan_job_id)
        finally:
            db.close()
        return self._cancel_cached


# ---------------------------------------------------------------------------
# Adapter session driver
# ---------------------------------------------------------------------------

def _touch_heartbeat(scan_job_id: uuid.UUID) -> None:
    """
    Record that this scan is still alive.

    Deliberately its own short-lived session: the scan's main session is busy
    for the whole run, and a heartbeat that shares it would be invisible until
    that transaction ended — which is exactly when it stops mattering.
    """
    db = SessionLocal()
    try:
        bypass_tenant(db)
        db.query(ScanJob).filter(ScanJob.id == scan_job_id).update(
            {"heartbeat_at": datetime.now(timezone.utc)}, synchronize_session=False
        )
        db.commit()
    except Exception:
        db.rollback()
        # A missed heartbeat is not worth failing a working scan over. Several
        # missed in a row is what the reaper acts on.
        logger.warning("scan %s: heartbeat could not be recorded", scan_job_id, exc_info=True)
    finally:
        db.close()


def _run_session(scanner: ScannerAdapter, request: ScanRequest, reporter: "ScanProgressReporter"):
    """
    Drive one adapter session to completion.

    Polls rather than blocking so a cancel request reaches the scanner while it
    is still running. Cancellation terminates the actual process; the sentinel
    is only returned once the adapter confirms it stopped something.
    """
    try:
        session = scanner.start_scan(request, on_output=reporter)
    except (ValueError, RuntimeError) as exc:
        from app.scanners.contract import ScannerResult

        return ScannerResult(target=request.target, scanner_name=scanner.name, error=str(exc))

    last_heartbeat = 0.0
    while True:
        progress = scanner.get_status(session)
        if progress.finished:
            break
        if reporter.cancel_requested():
            scanner.cancel_scan(session)
            return CANCELED

        now = time.monotonic()
        if now - last_heartbeat >= HEARTBEAT_SECONDS:
            last_heartbeat = now
            _touch_heartbeat(reporter.scan_job_id)

        time.sleep(SESSION_POLL_SECONDS)

    if progress.state is SessionState.CANCELED:
        return CANCELED

    return scanner.get_results(session)


def _resolve_scan_credential(db, job: ScanJob, scanner: ScannerAdapter) -> ScanCredential | None:
    """
    Fetch the scan's credential from the vault, if one was selected.

    Decryption happens here, immediately before use, and is written to the audit
    log naming the scan and the target. The plaintext exists only for the life
    of this scan and is never stored, echoed or logged.
    """
    if not getattr(job, "credential_profile_id", None):
        return None

    try:
        resolved = resolve_credential(
            db,
            organization_id=job.organization_id,
            credential_id=job.credential_profile_id,
            purpose=f"{job.engine} scan of {job.target_cidr}",
            actor_user_id=job.initiated_by_user_id,
        )
    except LookupError:
        raise RuntimeError(
            "The credential profile selected for this scan no longer exists."
        )

    return ScanCredential(
        credential_type=resolved.credential_type,
        username=resolved.username,
        domain=resolved.domain,
        secret=resolved.secret,
        extra=resolved.extra,
    )


# ---------------------------------------------------------------------------
# Host persistence
# ---------------------------------------------------------------------------

def persist_host(db, job: ScanJob, host, observed_at: datetime) -> tuple[Asset, list[FindingInput]]:
    """
    Turn one scanned host into inventory rows and normalized finding inputs.

    Returns the asset and the findings this host produced, so the caller can
    ingest them and then close whatever the scan no longer sees.
    """
    service_names = [port.service for port in host.ports if port.service]

    asset, _ = upsert_asset(
        db,
        organization_id=job.organization_id,
        ip_address=host.ip_address,
        hostname=host.hostname,
        mac_address=host.mac_address,
        vendor=host.vendor,
        os_match=host.os_match,
        service_names=service_names,
        scan_job_id=job.id,
        observed_at=observed_at,
    )

    upsert_interface(
        db, asset,
        ip_address=host.ip_address,
        mac_address=host.mac_address,
        mac_vendor=host.vendor,
        is_primary=True,
        observed_at=observed_at,
    )

    payloads: list[FindingInput] = []
    seen_ports: set[tuple[int, str]] = set()

    for scanned_port in host.ports:
        seen_ports.add((scanned_port.port, scanned_port.protocol))
        banner = " ".join(part for part in (scanned_port.product, scanned_port.version) if part).strip()

        service = upsert_service(
            db, asset,
            port=scanned_port.port,
            protocol=scanned_port.protocol,
            service_name=scanned_port.service,
            product=scanned_port.product,
            version=scanned_port.version,
            banner=banner,
            observed_at=observed_at,
        )

        # A product name from a banner is inventory, not a vulnerability claim.
        if scanned_port.product:
            upsert_software(
                db, asset,
                name=scanned_port.product,
                version=scanned_port.version,
                detection_method="service_banner",
                evidence=f"nmap service detection on {service_location(scanned_port.port, scanned_port.protocol)}: {banner}",
                asset_service_id=service.id,
                observed_at=observed_at,
            )

        if scanned_port.port in RISKY_PORTS:
            label, guidance = RISKY_PORTS[scanned_port.port]
            location = service_location(scanned_port.port, scanned_port.protocol)
            payloads.append(FindingInput(
                asset_id=asset.id,
                title=f"Exposed {label} service on port {scanned_port.port}",
                # An open port is an observed exposure, not a vulnerability.
                # Classifying it otherwise would inflate every vulnerability
                # count in the platform.
                finding_class=FindingClass.EXPOSURE,
                confidence=Confidence.CONFIRMED,
                severity=Severity.HIGH if scanned_port.port in HIGH_RISK_PORTS else Severity.MEDIUM,
                source="nmap",
                identifier=f"exposed-port-{scanned_port.port}",
                location=location,
                description=(
                    f"An open {label} port ({location}) was observed on "
                    f"{asset.hostname} ({host.ip_address}). This is an exposure "
                    f"observation from service discovery — it is not a CVE-backed "
                    f"vulnerability."
                ),
                evidence=(
                    f"nmap: {location} open, service={scanned_port.service or 'unknown'}"
                    + (f", banner={banner}" if banner else "")
                ),
                remediation_guidance=guidance,
                affected_product=scanned_port.product or None,
                affected_version=scanned_port.version or None,
                asset_service_id=service.id,
            ))

        for script in scanned_port.scripts:
            payloads.append(_script_finding(
                asset.id, script, location=service_location(scanned_port.port, scanned_port.protocol),
                asset_service_id=service.id,
            ))

    for script in host.scripts:
        payloads.append(_script_finding(asset.id, script, location="host"))

    mark_services_closed(db, asset, seen_ports, observed_at=observed_at)
    return asset, payloads


def _script_finding(asset_id, script, location: str, asset_service_id=None) -> FindingInput:
    """
    Normalize an nmap script result.

    Script output is treated as PROBABLE at best. NSE vulnerability scripts
    frequently decide from a version banner, which can be wrong in both
    directions — a backported patch leaves the banner unchanged, and banners
    can be edited. Calling that CONFIRMED would misrepresent the evidence.
    """
    output = script.output or ""
    lowered = output.lower()

    if "vulnerable" in lowered:
        severity = Severity.CRITICAL if "critical" in lowered else Severity.HIGH
        finding_class = FindingClass.VULNERABILITY
        confidence = Confidence.PROBABLE
    elif "vuln" in script.id:
        severity = Severity.MEDIUM
        finding_class = FindingClass.VULNERABILITY
        confidence = Confidence.POSSIBLE
    else:
        severity = Severity.INFO
        finding_class = FindingClass.INFORMATIONAL
        confidence = Confidence.CONFIRMED

    # NSE scripts name the CVE in their output when they know one.
    cve_id = None
    import re
    match = re.search(r"CVE-\d{4}-\d{4,7}", output, re.IGNORECASE)
    if match:
        cve_id = match.group(0).upper()

    return FindingInput(
        asset_id=asset_id,
        title=f"Nmap script {script.id} ({location})",
        finding_class=finding_class,
        confidence=confidence,
        severity=severity,
        source="nmap",
        identifier=script.id,
        location=location,
        description=(
            f"The nmap script '{script.id}' produced output for {location}. "
            f"Review the evidence before treating this as confirmed."
        ),
        evidence=output,
        remediation_guidance="Review the script evidence, then apply the relevant update or configuration change.",
        cve_id=cve_id,
        asset_service_id=asset_service_id,
    )


def _direct_findings(asset_id, raw: list[dict], source: str) -> list[FindingInput]:
    """Normalize findings from a scanner that assesses a target directly."""
    payloads = []
    for item in raw:
        title = item.get("title") or f"{source} finding"
        payloads.append(FindingInput(
            asset_id=asset_id,
            title=title,
            finding_class=FindingClass(item["finding_class"]) if item.get("finding_class") else FindingClass.VULNERABILITY,
            confidence=Confidence(item["confidence"]) if item.get("confidence") else Confidence.PROBABLE,
            severity=_severity_from_name(item.get("severity")),
            source=source,
            identifier=item.get("template_id") or item.get("check_id") or title,
            location=str(item.get("location") or ""),
            description=item.get("description", ""),
            evidence=str(item.get("evidence", "")),
            remediation_guidance=item.get("remediation_guidance", ""),
            cve_id=item.get("cve_id"),
        ))
    return payloads


def _asset_for_direct_target(db, job: ScanJob, observed_at: datetime) -> Asset:
    """Find or create the asset representing a single-target scan."""
    asset, _ = upsert_asset(
        db,
        organization_id=job.organization_id,
        ip_address=job.target_cidr,
        hostname=job.target_cidr,
        scan_job_id=job.id,
        observed_at=observed_at,
    )
    return asset


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

@celery_app.task(name="scan_tasks.run_network_scan")
def run_network_scan(scan_job_id: str) -> None:
    job_uuid = uuid.UUID(scan_job_id)
    db = SessionLocal()
    reporter = ScanProgressReporter(job_uuid)
    observed_at = datetime.now(timezone.utc)

    try:
        # The worker has no request context, so it starts unscoped and narrows
        # to the job's tenant as soon as it knows which one that is.
        bypass_tenant(db)
        job = db.query(ScanJob).filter(ScanJob.id == job_uuid).first()
        if job is None:
            logger.warning("scan %s: job record not found", scan_job_id)
            return
        set_tenant(db, job.organization_id)

        if job.cancel_requested:
            job.status = ScanStatus.CANCELED
            job.error_message = "Cancelled before the scan started."
            db.commit()
            return

        job.status = ScanStatus.RUNNING
        job.heartbeat_at = datetime.now(timezone.utc)
        db.commit()
        publish_event(
            job.organization_id, "scan_started",
            message=f"Scan of {job.target_cidr} started.",
            scan_job_id=str(job.id), engine=job.engine, target=job.target_cidr,
        )

        from app.scanners.manager import ScannerManager

        scanner = ScannerManager.get_scanner(job.engine)
        if scanner is None:
            raise RuntimeError(
                f"Scan engine '{job.engine}' is not registered on this worker. "
                f"Available engines: {', '.join(sorted(ScannerManager.get_all_scanners())) or 'none'}."
            )

        # The adapter probes for its own tool. A missing binary or library is
        # reported with the command that installs it, never as an empty result.
        configuration = scanner.validate_configuration()
        if not configuration.available:
            job.status = ScanStatus.FAILED
            job.error_message = f"{configuration.summary} {configuration.remediation}".strip()
            db.commit()
            return

        validation = scanner.validate_target(job.target_cidr)
        if not validation.valid:
            job.status = ScanStatus.FAILED
            job.error_message = validation.reason
            db.commit()
            return

        credential = _resolve_scan_credential(db, job, scanner)
        if scanner.requires_credential and credential is None:
            job.status = ScanStatus.FAILED
            job.error_message = (
                f"The '{job.engine}' engine performs a credentialed assessment and needs a "
                f"credential profile. Select one when starting the scan, or add one under "
                f"Administration → Credentials."
            )
            db.commit()
            return

        request = ScanRequest(
            target=validation.normalized_target or job.target_cidr,
            credential=credential,
            timeout_seconds=SCAN_TIMEOUT_SECONDS,
        )

        result = _run_session(scanner, request, reporter)
        reporter.flush()

        if result is CANCELED:
            job.status = ScanStatus.CANCELED
            job.error_message = "Cancelled by an operator; the scanner process was terminated."
            db.commit()
            return

        if result.error:
            job.status = ScanStatus.FAILED
            job.error_message = result.error[:4000]
            db.commit()
            return

        hosts = result.raw_data or []
        direct_findings = result.findings or []

        created_total = 0
        resolved_total = 0
        verified_total = 0
        reopened_total = 0
        touched: list[Asset] = []

        nuclei_scanner = ScannerManager.get_scanner("nuclei")
        nuclei_enabled = (
            job.engine == "nmap"
            and nuclei_scanner is not None
            and nuclei_scanner.validate_configuration().available
        )

        for host in hosts:
            asset, payloads = persist_host(db, job, host, observed_at)
            touched.append(asset)

            ingest = ingest_findings(db, job.organization_id, payloads, job.id, observed_at)
            created_total += ingest.created

            # Anything nmap previously reported on this asset and no longer
            # sees is resolved by evidence, not by assertion. The remediation
            # tasks attached to those findings are what "verified" means.
            resolved_ids = close_unseen_findings(
                db, job.organization_id, asset.id, "nmap", ingest.fingerprints, job.id, observed_at
            )
            resolved_total += len(resolved_ids)
            verified_total += verify_from_scan(db, job.organization_id, job.id, resolved_ids)
            reopened_total += reopen_from_scan(db, job.organization_id, ingest.reopened_finding_ids)

            if nuclei_enabled:
                created_total += _run_nuclei(db, job, asset, host, nuclei_scanner, observed_at)

        if direct_findings:
            asset = _asset_for_direct_target(db, job, observed_at)
            touched.append(asset)
            payloads = _direct_findings(asset.id, direct_findings, result.scanner_name)
            ingest = ingest_findings(db, job.organization_id, payloads, job.id, observed_at)
            created_total += ingest.created
            resolved_ids = close_unseen_findings(
                db, job.organization_id, asset.id, result.scanner_name,
                ingest.fingerprints, job.id, observed_at,
            )
            resolved_total += len(resolved_ids)
            verified_total += verify_from_scan(db, job.organization_id, job.id, resolved_ids)
            reopened_total += reopen_from_scan(db, job.organization_id, ingest.reopened_finding_ids)

        db.commit()

        # Correlate the software this scan identified against the CVE
        # catalogue. Done per asset immediately after the scan so newly
        # discovered software is assessed without waiting for the nightly pass.
        correlated = 0
        for asset in touched:
            try:
                outcome = correlate_asset(db, asset, job.id)
                correlated += outcome.findings_created
            except Exception:
                # Correlation is enrichment. A failure here must not discard the
                # scan results that have already been persisted.
                db.rollback()
                logger.exception("scan %s: CVE correlation failed for asset %s", job.id, asset.id)
        db.commit()
        created_total += correlated

        for asset in touched:
            recompute_asset_risk_score(db, asset)
            recompute_asset_exposure(db, asset)
        db.commit()

        job = db.query(ScanJob).filter(ScanJob.id == job_uuid).first()
        if job.cancel_requested:
            job.status = ScanStatus.CANCELED
            job.error_message = "Cancelled after the scan completed; results were kept."
        else:
            job.status = ScanStatus.COMPLETED
        job.hosts_discovered = len(hosts)
        job.findings_generated = created_total
        job.raw_summary = (job.raw_summary or "") + (
            f"\nScan finished: {len(hosts)} live host(s); {created_total} new finding(s); "
            f"{resolved_total} finding(s) no longer observed and marked resolved"
            + (f"; {verified_total} remediation task(s) verified" if verified_total else "")
            + (f"; {reopened_total} finding(s) reappeared and were reopened" if reopened_total else "")
            + ".\n"
        )
        db.commit()

        publish_event(
            job.organization_id,
            "scan_completed" if job.status is ScanStatus.COMPLETED else "scan_failed",
            message=(
                f"Scan of {job.target_cidr} finished: {len(hosts)} live host(s), "
                f"{created_total} new finding(s)."
                if job.status is ScanStatus.COMPLETED
                else f"Scan of {job.target_cidr} was cancelled; results were kept."
            ),
            scan_job_id=str(job.id),
            status=job.status.value,
            hosts_discovered=len(hosts),
            findings_generated=created_total,
            findings_resolved=resolved_total,
        )

        # The inventory just changed, so the exposure graph and the attack
        # paths derived from it are stale. Dispatched rather than computed
        # inline so a slow rebuild cannot make a finished scan look unfinished,
        # and swallowed on failure for the same reason — the scan itself
        # succeeded, and its record must not be rewritten by a downstream
        # problem.
        try:
            from app.tasks.graph_tasks import rebuild_exposure_graph

            rebuild_exposure_graph.delay(str(job.organization_id))
        except Exception:  # noqa: BLE001
            logger.exception(
                "scan %s: completed, but the exposure graph rebuild could not "
                "be queued", scan_job_id,
            )

    except Exception as exc:
        logger.exception("scan %s: unexpected failure", scan_job_id)
        db.rollback()
        try:
            bypass_tenant(db)
            job = db.query(ScanJob).filter(ScanJob.id == job_uuid).first()
            if job is not None:
                job.status = ScanStatus.FAILED
                job.error_message = f"Unexpected error: {exc}"
                db.commit()
                publish_event(
                    job.organization_id, "scan_failed",
                    message=f"Scan of {job.target_cidr} failed: {exc}",
                    scan_job_id=str(job.id), error=str(exc),
                )
        except Exception:
            logger.exception("scan %s: could not record the failure", scan_job_id)
        raise
    finally:
        reporter.flush()
        db.close()


def _run_nuclei(db, job: ScanJob, asset: Asset, host, nuclei_scanner, observed_at) -> int:
    """Fan nuclei out across the HTTP(S) services discovered on one host."""
    targets = []
    for scanned_port in host.ports:
        if scanned_port.service in ("http", "https") or scanned_port.port in (80, 443, 8080, 8443):
            scheme = "https" if scanned_port.port in (443, 8443) else "http"
            targets.append(f"{scheme}://{host.ip_address}:{scanned_port.port}")

    if not targets:
        return 0

    def assess(target: str):
        return nuclei_scanner.run_to_completion(
            ScanRequest(target=target, timeout_seconds=SCAN_TIMEOUT_SECONDS)
        )

    collected: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(targets))) as executor:
        futures = {executor.submit(assess, target): target for target in targets}
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                outcome = future.result()
                if outcome.error:
                    raise RuntimeError(outcome.error)
                collected.extend(outcome.findings)
            except Exception as exc:
                # Never let a failed assessment look like a clean one.
                logger.warning("scan %s: nuclei failed against %s: %s", job.id, target, exc)
                collected.append({
                    "title": f"Nuclei assessment failed for {target}",
                    "description": "The nuclei scan of this service did not complete, so this "
                                   "service has not been assessed.",
                    "evidence": str(exc)[:2000],
                    "severity": "info",
                    "finding_class": "informational",
                    "confidence": "confirmed",
                    "check_id": f"nuclei-failed-{target}",
                    "location": target,
                    "remediation_guidance": "Re-run the scan, or check the worker's nuclei installation.",
                })

    if not collected:
        return 0

    payloads = _direct_findings(asset.id, collected, "nuclei")
    ingest = ingest_findings(db, job.organization_id, payloads, job.id, observed_at)
    close_unseen_findings(
        db, job.organization_id, asset.id, "nuclei", ingest.fingerprints, job.id, observed_at
    )
    return ingest.created


@celery_app.task(name="scan_tasks.reap_orphaned_scans")
def reap_orphaned_scans() -> dict:
    """
    Close out scans whose worker is gone.

    Cancellation is cooperative: the API sets cancel_requested and the worker,
    polling, stops the scanner. Nothing in that design covers the worker itself
    disappearing — a restart, a deploy, an out-of-memory kill. The scanner
    process dies with it, the row stays at RUNNING, and because the time budget
    is enforced inside the task, nothing enforces it either. The operator sees a
    scan running for hours and a Stop button that appears to do nothing, because
    the flag it sets has no reader.

    A running scan touches heartbeat_at every half minute. A RUNNING row whose
    heartbeat stopped is therefore not a slow scan — it is an abandoned one, and
    it is recorded as failed with the reason rather than left to look busy.

    Whatever partial results the scan wrote before it died are kept. They were
    really observed; it is the completeness of the scan that is in doubt, and
    that is what the message says.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=ORPHAN_AFTER_SECONDS)

    db = SessionLocal()
    try:
        bypass_tenant(db)
        stranded = (
            db.query(ScanJob)
            .filter(
                ScanJob.status == ScanStatus.RUNNING,
                # A job that never recorded a first heartbeat is only stranded
                # once it is older than the window too; otherwise a scan caught
                # in the second between starting and its first beat is reaped.
                sa_or(
                    ScanJob.heartbeat_at < cutoff,
                    sa_and(ScanJob.heartbeat_at.is_(None), ScanJob.created_at < cutoff),
                ),
            )
            .all()
        )

        reaped = []
        for job in stranded:
            job.status = ScanStatus.FAILED
            job.error_message = (
                "The worker running this scan stopped before it finished — most often a "
                "restart or a deploy. Anything already recorded was really observed, but "
                "the scan did not cover its whole target, so treat the result as partial. "
                "Start it again when the worker is back."
            )
            job.raw_summary = (job.raw_summary or "") + (
                "\n[orphaned] No heartbeat from the worker for over "
                f"{int(ORPHAN_AFTER_SECONDS // 60)} minutes; the scan was marked failed.\n"
            )
            reaped.append(str(job.id))
            publish_event(
                job.organization_id, "scan_failed",
                message=f"Scan of {job.target_cidr} was abandoned when its worker stopped.",
                scan_job_id=str(job.id), reason="orphaned",
            )

        if reaped:
            db.commit()
            logger.warning("reaped %d orphaned scan(s): %s", len(reaped), ", ".join(reaped))

        return {"reaped": reaped}
    except Exception:
        db.rollback()
        logger.exception("orphaned-scan sweep failed")
        raise
    finally:
        db.close()
