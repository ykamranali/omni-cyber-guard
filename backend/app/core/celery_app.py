"""
Celery application for background jobs: network scans, scheduled report
generation, and future async work. Uses Redis as both broker and result
backend, matching docker-compose's `redis` service.
"""
from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "omni_cyber_guard",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.tasks.scan_tasks", "app.tasks.scheduler_tasks", "app.tasks.intel_tasks", "app.tasks.discovery_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
)

from celery.schedules import crontab
from celery.signals import worker_ready

celery_app.conf.beat_schedule = {
    "check-scan-schedules-every-minute": {
        "task": "scheduler_tasks.check_schedules",
        "schedule": crontab(minute="*"),
    },
    # KEV is small and changes on CISA's schedule; checking twice a day keeps
    # newly-listed exploited vulnerabilities from sitting unnoticed.
    "sync-kev-twice-daily": {
        "task": "intel_tasks.sync_kev_feed",
        "schedule": crontab(hour="3,15", minute="10"),
    },
    # EPSS is re-scored once a day.
    "sync-epss-daily": {
        "task": "intel_tasks.sync_epss_feed",
        "schedule": crontab(hour="3", minute="30"),
    },
    # NVD is incremental after the first run, so this is a handful of requests.
    "sync-nvd-daily": {
        "task": "intel_tasks.sync_nvd_feed",
        "schedule": crontab(hour="4", minute="0"),
    },
    # Re-correlate after the feeds have refreshed: a CVE published today can
    # affect software inventoried weeks ago, with nothing about the asset
    # having changed to trigger a re-scan.
    "correlate-after-sync": {
        "task": "intel_tasks.correlate_all_organizations",
        "schedule": crontab(hour="5", minute="0"),
    },
    # Recorded after correlation, so the day's figure reflects the freshest
    # intelligence rather than yesterday's.
    "capture-exposure-snapshot-daily": {
        "task": "intel_tasks.capture_exposure_snapshots",
        "schedule": crontab(hour="6", minute="0"),
    },
    # Run before the snapshot so a finding whose acceptance lapsed today is
    # counted as open in the day's figures.
    "expire-risk-acceptances-daily": {
        "task": "intel_tasks.expire_risk_acceptances",
        "schedule": crontab(hour="5", minute="45"),
    },
}



@worker_ready.connect
def _start_passive_monitor(**_kwargs) -> None:
    """
    Start passive packet capture when a worker comes up.

    The monitor lives here rather than in the API process because capture needs
    CAP_NET_RAW, which only the worker container is granted. Events go to Redis,
    so the API can serve them without capturing anything itself.
    """
    if not settings.ENABLE_PASSIVE_MONITOR:
        return
    from app.services.threat_monitor import start_sniffer

    start_sniffer()
