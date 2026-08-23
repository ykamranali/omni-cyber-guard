"""
Is anything actually going to run this job?

A queued scan that never starts is the platform's most misleading state: the
row says QUEUED, the UI says "queued for scanning", and both are true — a
worker simply never arrives to take it. Nothing anywhere said so.

Two separate questions get answered here, because they have two different
failure modes and two different fixes.

*Is a worker online?* Asked of Celery directly. `inspect().ping()` round-trips
through the broker to every live worker, so a reply proves a worker exists, is
connected to the same broker, and is responsive right now.

*Is the scheduler running?* There is no ping for Celery beat, and guessing from
worker introspection produces a confident wrong answer. So this is inferred
from evidence instead: the intelligence feeds are scheduled daily and record
`last_attempt_at` whether they succeed or fail. If nothing has been attempted
in two days, nothing is driving the timetable — which also explains an empty
CVE intelligence store, a flat exposure trend and scheduled scans that never
fire. When there is no evidence either way, that is reported as unknown rather
than as a verdict.

The check is deliberately short-timeout and never raises: a health probe that
can hang or 500 is worse than no probe.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.vulnerability_intel import IntelSyncState

logger = logging.getLogger(__name__)

PING_TIMEOUT_SECONDS = 2.0
# The feeds run daily. Two days of silence is past any reasonable jitter.
SCHEDULER_SILENCE_THRESHOLD = timedelta(days=2)

NO_WORKER_REMEDIATION = (
    "No Celery worker replied. Scans, scheduled jobs and intelligence "
    "synchronisation will stay queued until one is running. Start it with "
    "`docker compose up -d worker`, and check `docker compose logs worker` if "
    "it exits."
)

NO_SCHEDULER_REMEDIATION = (
    "Nothing on a timetable has run recently. That stops CVE/EPSS/KEV "
    "synchronisation, scheduled scans, nightly exposure snapshots, graph "
    "rebuilds and risk-acceptance expiry. Start the scheduler with "
    "`docker compose up -d beat`."
)


@dataclass
class WorkerHealth:
    broker_url: str
    workers: list[str] = field(default_factory=list)
    # None means "no evidence either way" — a fresh deployment where nothing
    # has been scheduled yet looks identical to a broken scheduler, and saying
    # "broken" would be a claim the data does not support.
    scheduler_running: bool | None = None
    scheduler_evidence: str = ""
    error: str = ""

    @property
    def healthy(self) -> bool:
        return bool(self.workers)

    def as_dict(self) -> dict:
        return {
            "broker": _redact(self.broker_url),
            "workers_online": len(self.workers),
            "worker_names": self.workers,
            "healthy": self.healthy,
            "scheduler_running": self.scheduler_running,
            "scheduler_evidence": self.scheduler_evidence,
            "error": self.error,
            "remediation": "" if self.healthy else NO_WORKER_REMEDIATION,
            "scheduler_remediation": (
                NO_SCHEDULER_REMEDIATION if self.scheduler_running is False else ""
            ),
        }


def _redact(url: str) -> str:
    """Broker URLs carry a password. Only the scheme and host help diagnosis."""
    if "@" not in url:
        return url
    scheme, _, rest = url.partition("://")
    return f"{scheme}://***@{rest.rpartition('@')[2]}"


def check(db: Session | None = None) -> WorkerHealth:
    health = WorkerHealth(broker_url=settings.REDIS_URL)

    try:
        from app.core.celery_app import celery_app

        inspector = celery_app.control.inspect(timeout=PING_TIMEOUT_SECONDS)
        health.workers = sorted((inspector.ping() or {}).keys())
    except Exception as exc:  # noqa: BLE001
        logger.warning("Worker health check could not reach the broker: %s", exc)
        health.error = str(exc)

    if db is not None:
        health.scheduler_running, health.scheduler_evidence = _scheduler_evidence(db)

    return health


def _scheduler_evidence(db: Session) -> tuple[bool | None, str]:
    attempts = [
        state.last_attempt_at
        for state in db.execute(select(IntelSyncState)).scalars().all()
        if state.last_attempt_at is not None
    ]
    if not attempts:
        return None, (
            "No scheduled job has ever recorded an attempt. On a new "
            "deployment that is expected; if the platform has been running for "
            "more than a day it means the scheduler has never run."
        )

    latest = max(attempts)
    if latest.tzinfo is None:
        latest = latest.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - latest

    if age <= SCHEDULER_SILENCE_THRESHOLD:
        return True, f"A scheduled job last ran {latest.isoformat()}."
    return False, (
        f"The most recent scheduled job ran {latest.isoformat()}, which is "
        f"{age.days} days ago. The daily timetable is not firing."
    )
