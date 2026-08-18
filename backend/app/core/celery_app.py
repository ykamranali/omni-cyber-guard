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
    include=["app.tasks.scan_tasks", "app.tasks.scheduler_tasks"],
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

celery_app.conf.beat_schedule = {
    "check-scan-schedules-every-minute": {
        "task": "scheduler_tasks.check_schedules",
        "schedule": crontab(minute="*"),  # Run every minute
    },
}

