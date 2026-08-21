"""
Scheduled vulnerability-intelligence work.

Synchronisation and correlation are separate tasks on purpose. Synchronisation
touches the network and updates public reference data; correlation touches only
the database and re-evaluates every tenant's estate against whatever the
catalogue currently holds. Keeping them apart means a network outage delays
fresh CVE data without also stopping the platform from correlating what it
already has.
"""
from __future__ import annotations

import logging

from app.core.celery_app import celery_app
from app.core.config import settings
from app.db.session import SessionLocal
from app.db.tenancy import bypass_tenant, set_tenant
from app.models.organization import Organization
from app.services.intel.sync import sync_all, sync_epss, sync_kev, sync_nvd
from app.services.vulnerability_correlation import correlate_organization

logger = logging.getLogger(__name__)


@celery_app.task(name="intel_tasks.sync_intelligence_feeds")
def sync_intelligence_feeds() -> list[dict]:
    """Refresh KEV, EPSS and NVD. Reference data is global, so this runs unscoped."""
    if not settings.ENABLE_INTEL_SYNC:
        logger.info("intel sync is disabled by configuration")
        return []

    db = SessionLocal()
    try:
        bypass_tenant(db)
        results = sync_all(db)
        for result in results:
            level = logger.info if result["succeeded"] else logger.warning
            level("intel sync %s: %s", result["source"], result["message"])
        return results
    finally:
        db.close()


@celery_app.task(name="intel_tasks.sync_kev_feed")
def sync_kev_feed() -> dict:
    db = SessionLocal()
    try:
        bypass_tenant(db)
        return sync_kev(db).as_dict()
    finally:
        db.close()


@celery_app.task(name="intel_tasks.sync_epss_feed")
def sync_epss_feed() -> dict:
    db = SessionLocal()
    try:
        bypass_tenant(db)
        return sync_epss(db).as_dict()
    finally:
        db.close()


@celery_app.task(name="intel_tasks.sync_nvd_feed")
def sync_nvd_feed() -> dict:
    db = SessionLocal()
    try:
        bypass_tenant(db)
        return sync_nvd(db).as_dict()
    finally:
        db.close()


@celery_app.task(name="intel_tasks.correlate_all_organizations")
def correlate_all_organizations() -> list[dict]:
    """
    Re-correlate every tenant's software inventory against the catalogue.

    Worth running after a sync as well as after a scan: a CVE published today
    can affect software that was inventoried weeks ago, and nothing about that
    asset has changed to trigger a re-scan.
    """
    db = SessionLocal()
    outcomes: list[dict] = []
    try:
        bypass_tenant(db)
        organization_ids = [row.id for row in db.query(Organization.id).all()]

        for organization_id in organization_ids:
            try:
                set_tenant(db, organization_id)
                result = correlate_organization(db, organization_id)
                outcomes.append({"organization_id": str(organization_id), **result.as_dict()})
            except Exception as exc:
                # One tenant's failure must not stop the rest.
                db.rollback()
                logger.exception("correlation failed for organization %s", organization_id)
                outcomes.append({"organization_id": str(organization_id), "error": str(exc)})
            finally:
                bypass_tenant(db)

        return outcomes
    finally:
        db.close()


@celery_app.task(name="intel_tasks.correlate_organization")
def correlate_single_organization(organization_id: str) -> dict:
    """Correlate one organization, e.g. immediately after a scan completes."""
    import uuid as _uuid

    db = SessionLocal()
    try:
        org_uuid = _uuid.UUID(organization_id)
        set_tenant(db, org_uuid)
        return correlate_organization(db, org_uuid).as_dict()
    finally:
        db.close()


@celery_app.task(name="intel_tasks.capture_exposure_snapshots")
def capture_exposure_snapshots() -> list[dict]:
    """
    Record one exposure snapshot per organization, per day.

    This is what makes the trend line a record rather than a drawing. It runs
    after the nightly correlation pass so the day's figure reflects the freshest
    intelligence.
    """
    from app.services.exposure_snapshots import capture_snapshot

    db = SessionLocal()
    captured: list[dict] = []
    try:
        bypass_tenant(db)
        organization_ids = [row.id for row in db.query(Organization.id).all()]

        for organization_id in organization_ids:
            try:
                set_tenant(db, organization_id)
                snapshot = capture_snapshot(db, organization_id)
                captured.append({
                    "organization_id": str(organization_id),
                    "date": snapshot.snapshot_date.isoformat(),
                    "exposure_score": snapshot.exposure_score,
                    "open_findings": snapshot.open_findings,
                })
            except Exception as exc:
                db.rollback()
                logger.exception("snapshot failed for organization %s", organization_id)
                captured.append({"organization_id": str(organization_id), "error": str(exc)})
            finally:
                bypass_tenant(db)

        return captured
    finally:
        db.close()


@celery_app.task(name="intel_tasks.expire_risk_acceptances")
def expire_risk_acceptances() -> dict:
    """
    Reopen findings whose risk acceptance has lapsed.

    Without this, "accepted until March" silently becomes "accepted forever",
    and the expiry date on the record means nothing.
    """
    from app.services.remediation_engine import expire_lapsed_acceptances

    db = SessionLocal()
    try:
        bypass_tenant(db)
        expired = expire_lapsed_acceptances(db)
        db.commit()
        if expired:
            logger.info("expired %s lapsed risk acceptance(s)", expired)
        return {"expired": expired}
    finally:
        db.close()
