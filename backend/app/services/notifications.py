"""
Notification delivery.

Every send returns a NotificationResult saying what actually happened. Callers
must not assume delivery: the email and in-app channels are not implemented
yet, and they report `delivered=False` with a reason rather than logging a line
and letting the caller believe a message went out.

The webhook channel is real — it performs an HTTP POST and reports the outcome.

Full delivery (SMTP/SES for email, a persisted `notifications` table plus
WebSocket push for in-app) is Phase 13 of the roadmap.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class NotificationResult:
    channel: str
    delivered: bool
    detail: str = ""

    def __bool__(self) -> bool:
        return self.delivered


class NotificationService:
    @staticmethod
    def send_email(to_email: str, subject: str, body: str) -> NotificationResult:
        """Not implemented. No SMTP or transactional-email provider is
        configured, so nothing is sent."""
        logger.info("email channel not configured; would have sent %r to %s", subject, to_email)
        return NotificationResult(
            channel="email",
            delivered=False,
            detail="Email delivery is not configured. Configure an SMTP or transactional "
                   "email provider to enable this channel.",
        )

    @staticmethod
    def send_in_app_notification(
        user_id: uuid.UUID,
        title: str,
        message: str,
        org_id: Optional[uuid.UUID] = None,
    ) -> NotificationResult:
        """Not implemented. There is no notifications table yet, so nothing is
        persisted and nothing reaches the user's session."""
        logger.info("in-app channel not implemented; would have notified %s: %r", user_id, title)
        return NotificationResult(
            channel="in_app",
            delivered=False,
            detail="In-app notifications are not implemented yet.",
        )

    @staticmethod
    def send_webhook_notification(
        url: str,
        title: str,
        message: str,
        provider: str = "slack",
    ) -> NotificationResult:
        """Real delivery: POSTs to a Slack- or Teams-compatible webhook."""
        import requests

        if provider == "slack":
            payload = {"text": f"*{title}*\n{message}"}
        elif provider == "teams":
            payload = {"title": title, "text": message}
        else:
            return NotificationResult(
                channel=f"webhook:{provider}",
                delivered=False,
                detail=f"Unsupported webhook provider '{provider}'.",
            )

        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            return NotificationResult(channel=f"webhook:{provider}", delivered=True)
        except Exception as exc:
            logger.error("webhook delivery to %s failed: %s", provider, exc)
            return NotificationResult(
                channel=f"webhook:{provider}",
                delivered=False,
                detail=f"Webhook POST failed: {exc}",
            )

    @classmethod
    def notify_scan_completion(
        cls,
        job_id: uuid.UUID,
        org_id: uuid.UUID,
        user_id: Optional[uuid.UUID],
        status: str,
        hosts: int,
        findings: int,
    ) -> list[NotificationResult]:
        title = f"Scan {status}"
        message = (
            f"Scan job {job_id} finished with status '{status}': {hosts} host(s) "
            f"discovered, {findings} finding(s) recorded."
        )
        results = []
        if user_id:
            results.append(cls.send_in_app_notification(user_id, title, message, org_id))
        return results

    @classmethod
    def notify_critical_finding(
        cls,
        org_id: uuid.UUID,
        asset_id: uuid.UUID,
        title: str,
    ) -> list[NotificationResult]:
        message = (
            f"A critical finding '{title}' was recorded on asset {asset_id}. "
            f"Review required."
        )
        logger.warning("org %s: %s", org_id, message)
        return [cls.send_in_app_notification(uuid.UUID(int=0), "Critical finding", message, org_id)]
