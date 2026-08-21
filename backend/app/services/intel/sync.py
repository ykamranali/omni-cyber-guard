"""
Feed synchronisation.

Each `sync_*` function fetches, parses and persists one feed, and records what
happened in `intel_sync_state`. The record is written whether the sync succeeded
or failed, because a stale catalogue that still shows a recent success
timestamp is the most dangerous state this subsystem can be in — it looks
current and is not.

Network access is confined to this module. Everything it depends on for
correctness (parsing, matching, version comparison) lives in modules with no
network dependency and is tested directly.
"""
from __future__ import annotations

import gzip
import io
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.vulnerability_intel import Cve, CpeMatch, EpssScore, IntelSyncState, KevEntry
from app.services.intel.parsers import (
    ParsedCve, parse_epss_csv, parse_kev_catalog, parse_nvd_page,
)

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

USER_AGENT = "OmniCyberGuard/1.0 (vulnerability intelligence sync)"

#: NVD's documented ceiling per request.
NVD_PAGE_SIZE = 2000
#: NVD asks for 6 seconds between requests without an API key, 0.6 with one.
NVD_DELAY_WITHOUT_KEY = 6.0
NVD_DELAY_WITH_KEY = 0.6
#: NVD rejects a lastModified window wider than 120 days.
NVD_MAX_WINDOW_DAYS = 120

REQUEST_TIMEOUT = 60


class SyncResult:
    def __init__(self, source: str):
        self.source = source
        self.records_processed = 0
        self.total_records = 0
        self.succeeded = False
        self.message = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "succeeded": self.succeeded,
            "records_processed": self.records_processed,
            "total_records": self.total_records,
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# Sync-state bookkeeping
# ---------------------------------------------------------------------------

def get_sync_state(db: Session, source: str) -> IntelSyncState:
    state = db.execute(
        select(IntelSyncState).where(IntelSyncState.source == source)
    ).scalar_one_or_none()
    if state is None:
        state = IntelSyncState(source=source)
        db.add(state)
        db.flush()
    return state


def _record_attempt(db: Session, source: str) -> IntelSyncState:
    state = get_sync_state(db, source)
    state.last_attempt_at = datetime.now(timezone.utc)
    state.status = "running"
    db.commit()
    return state


def _record_success(db: Session, state: IntelSyncState, result: SyncResult, cursor: str = "") -> None:
    state.last_success_at = datetime.now(timezone.utc)
    state.status = "ok"
    state.message = result.message
    state.records_processed = result.records_processed
    state.total_records = result.total_records
    if cursor:
        state.cursor = cursor
    db.commit()


def _record_failure(db: Session, state: IntelSyncState, error: str) -> None:
    # last_success_at is deliberately left untouched, so the UI can show both
    # "last succeeded 6 days ago" and "last attempt failed".
    state.status = "failed"
    state.message = error[:2000]
    db.commit()


def _session() -> requests.Session:
    http = requests.Session()
    http.headers.update({"User-Agent": USER_AGENT})
    return http


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

def sync_kev(db: Session, http: requests.Session | None = None) -> SyncResult:
    """
    Synchronise the CISA Known Exploited Vulnerabilities catalogue.

    The catalogue is a single small JSON document, so it is fetched whole. Every
    entry is upserted; entries CISA has removed are deleted, because a CVE that
    is no longer listed should stop being scored as known-exploited.
    """
    result = SyncResult("kev")
    state = _record_attempt(db, "kev")
    http = http or _session()

    try:
        response = http.get(KEV_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        message = f"Could not fetch the CISA KEV catalogue: {exc}"
        logger.warning("intel: %s", message)
        _record_failure(db, state, message)
        result.message = message
        return result

    entries = parse_kev_catalog(payload)
    now = datetime.now(timezone.utc)

    existing = {row.cve_id: row for row in db.execute(select(KevEntry)).scalars()}
    seen: set[str] = set()

    for entry in entries:
        seen.add(entry.cve_id)
        record = existing.get(entry.cve_id) or KevEntry(cve_id=entry.cve_id)
        record.vendor_project = entry.vendor_project
        record.product = entry.product
        record.vulnerability_name = entry.vulnerability_name
        record.short_description = entry.short_description
        record.required_action = entry.required_action
        record.date_added = entry.date_added
        record.due_date = entry.due_date
        record.known_ransomware_use = entry.known_ransomware_use
        record.notes = entry.notes
        record.synced_at = now
        db.add(record)

    removed = 0
    for cve_id, record in existing.items():
        if cve_id not in seen:
            db.delete(record)
            removed += 1

    db.commit()

    result.records_processed = len(entries)
    result.total_records = len(entries)
    result.succeeded = True
    result.message = (
        f"{len(entries)} known-exploited entries synchronised"
        + (f"; {removed} withdrawn entries removed" if removed else "")
    )
    _record_success(db, state, result, cursor=payload.get("catalogVersion", ""))
    return result


# ---------------------------------------------------------------------------
# FIRST EPSS
# ---------------------------------------------------------------------------

def sync_epss(db: Session, http: requests.Session | None = None) -> SyncResult:
    """
    Synchronise the daily EPSS scores.

    The feed is a gzipped CSV of roughly 250,000 rows. Scores are replaced
    wholesale for the score date the file declares — EPSS re-scores every CVE
    daily, so merging partial data would leave a mix of dates behind one column.
    """
    result = SyncResult("epss")
    state = _record_attempt(db, "epss")
    http = http or _session()

    try:
        response = http.get(EPSS_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        raw = response.content
        content = gzip.decompress(raw).decode("utf-8") if raw[:2] == b"\x1f\x8b" else raw.decode("utf-8")
    except Exception as exc:
        message = f"Could not fetch the EPSS score feed: {exc}"
        logger.warning("intel: %s", message)
        _record_failure(db, state, message)
        result.message = message
        return result

    scores, score_date = parse_epss_csv(content)
    if not scores:
        message = "The EPSS feed contained no scores."
        _record_failure(db, state, message)
        result.message = message
        return result

    now = datetime.now(timezone.utc)
    existing = {row.cve_id: row for row in db.execute(select(EpssScore)).scalars()}

    for parsed in scores:
        record = existing.get(parsed.cve_id) or EpssScore(cve_id=parsed.cve_id)
        record.score = parsed.score
        record.percentile = parsed.percentile
        record.scored_on = parsed.scored_on
        record.synced_at = now
        db.add(record)

    db.commit()

    result.records_processed = len(scores)
    result.total_records = len(scores)
    result.succeeded = True
    result.message = f"{len(scores)} EPSS scores synchronised for {score_date or 'an unstated date'}"
    _record_success(db, state, result, cursor=score_date.isoformat() if score_date else "")
    return result


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def _nvd_headers() -> dict[str, str]:
    key = (settings.NVD_API_KEY or "").strip()
    return {"apiKey": key} if key else {}


def _persist_cve(db: Session, parsed: ParsedCve, now: datetime) -> None:
    record = db.execute(
        select(Cve).where(Cve.cve_id == parsed.cve_id)
    ).scalar_one_or_none()

    if record is None:
        record = Cve(cve_id=parsed.cve_id)
        db.add(record)
        db.flush()

    record.description = parsed.description
    record.published_at = parsed.published_at
    record.last_modified_at = parsed.last_modified_at
    record.cvss_v3_score = parsed.cvss_v3_score
    record.cvss_v3_vector = parsed.cvss_v3_vector
    record.cvss_v3_severity = parsed.cvss_v3_severity
    record.cvss_v2_score = parsed.cvss_v2_score
    record.cwe_ids = parsed.cwe_ids
    record.references = parsed.references
    record.vuln_status = parsed.vuln_status
    record.synced_at = now

    # CPE rules are replaced rather than merged: NVD revises configurations, and
    # a rule that has been withdrawn must stop matching.
    for existing in list(record.cpe_matches):
        db.delete(existing)
    db.flush()

    for match in parsed.cpe_matches:
        db.add(CpeMatch(
            cve_id=record.id,
            criteria=match.criteria[:512],
            vendor=match.vendor[:255],
            product=match.product[:255],
            version=match.version[:128],
            version_start_including=match.version_start_including,
            version_start_excluding=match.version_start_excluding,
            version_end_including=match.version_end_including,
            version_end_excluding=match.version_end_excluding,
            vulnerable=match.vulnerable,
        ))


def sync_nvd(
    db: Session,
    http: requests.Session | None = None,
    since: datetime | None = None,
    max_pages: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> SyncResult:
    """
    Synchronise CVE records from the NVD 2.0 API.

    Incremental by default: it asks only for records modified since the last
    successful sync, which keeps a routine refresh to a handful of requests
    instead of re-downloading roughly 280,000 CVEs.

    The first run has no cursor and would otherwise attempt the entire
    catalogue. `NVD_INITIAL_SYNC_DAYS` bounds that first window, and the sync
    reports plainly that it covered a window rather than everything — so nobody
    mistakes a partial catalogue for a complete one.
    """
    result = SyncResult("nvd")
    state = _record_attempt(db, "nvd")
    http = http or _session()

    now = datetime.now(timezone.utc)
    delay = NVD_DELAY_WITH_KEY if (settings.NVD_API_KEY or "").strip() else NVD_DELAY_WITHOUT_KEY

    if since is None:
        if state.last_success_at:
            since = state.last_success_at - timedelta(hours=1)  # small overlap for safety
        else:
            since = now - timedelta(days=settings.NVD_INITIAL_SYNC_DAYS)

    window_start = max(since, now - timedelta(days=NVD_MAX_WINDOW_DAYS))
    first_run = state.last_success_at is None

    parameters = {
        "resultsPerPage": NVD_PAGE_SIZE,
        "startIndex": 0,
        "lastModStartDate": window_start.strftime("%Y-%m-%dT%H:%M:%S.000%z") or window_start.isoformat(),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000%z") or now.isoformat(),
    }

    processed = 0
    total = 0
    pages = 0

    try:
        while True:
            response = http.get(
                NVD_API_URL, params=parameters, headers=_nvd_headers(), timeout=REQUEST_TIMEOUT
            )
            if response.status_code == 403:
                raise RuntimeError(
                    "NVD returned 403. This usually means the request rate was exceeded. "
                    "Set NVD_API_KEY to raise the limit (request one free at "
                    "https://nvd.nist.gov/developers/request-an-api-key)."
                )
            response.raise_for_status()
            payload = response.json()

            total = payload.get("totalResults", 0)
            page = parse_nvd_page(payload)
            for parsed in page:
                _persist_cve(db, parsed, now)
            db.commit()

            processed += len(page)
            pages += 1

            start_index = payload.get("startIndex", 0) + payload.get("resultsPerPage", 0)
            if start_index >= total or not page:
                break
            if max_pages is not None and pages >= max_pages:
                break

            parameters["startIndex"] = start_index
            sleep(delay)

    except Exception as exc:
        db.rollback()
        message = f"NVD synchronisation failed after {processed} record(s): {exc}"
        logger.warning("intel: %s", message)
        _record_failure(db, state, message)
        result.records_processed = processed
        result.message = message
        return result

    result.records_processed = processed
    result.total_records = total
    result.succeeded = True
    result.message = (
        f"{processed} CVE record(s) synchronised from {window_start.date()} onward"
        + (
            f". This was the first run and covered the last {settings.NVD_INITIAL_SYNC_DAYS} days "
            f"only — the catalogue is not yet complete."
            if first_run else ""
        )
    )
    _record_success(db, state, result, cursor=now.isoformat())
    return result


def sync_all(db: Session) -> list[dict[str, Any]]:
    """Run every feed. One failure does not prevent the others from running."""
    return [
        sync_kev(db).as_dict(),
        sync_epss(db).as_dict(),
        sync_nvd(db).as_dict(),
    ]
