import logging
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

class NotificationService:
    @staticmethod
    def send_email(to_email: str, subject: str, body: str) -> None:
        """
        Mock email sender.
        In a production environment, this would integrate with SMTP or a service like SendGrid/AWS SES.
        """
        logger.info(f"[EMAIL NOTIFICATION] To: {to_email} | Subject: {subject} | Body: {body}")

    @staticmethod
    def send_in_app_notification(user_id: uuid.UUID, title: str, message: str, org_id: Optional[uuid.UUID] = None) -> None:
        """
        Mock in-app notification.
        In a real environment, this would save to a Notifications table and broadcast via WebSockets.
        """
        logger.info(f"[IN-APP NOTIFICATION] User: {user_id} | Title: {title} | Message: {message}")

    @staticmethod
    def send_webhook_notification(url: str, title: str, message: str, provider: str = "slack") -> None:
        """
        Sends a payload to a Slack or MS Teams webhook URL.
        """
        import requests
        payload = {}
        if provider == "slack":
            payload = {"text": f"*{title}*\n{message}"}
        elif provider == "teams":
            payload = {"title": title, "text": message}
            
        try:
            logger.info(f"[WEBHOOK NOTIFICATION] Sending to {provider}: {title}")
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logger.error(f"[WEBHOOK NOTIFICATION] Failed to send to {provider}: {str(e)}")

    @classmethod
    def notify_scan_completion(cls, job_id: uuid.UUID, org_id: uuid.UUID, user_id: Optional[uuid.UUID], status: str, hosts: int, findings: int) -> None:
        title = f"Scan {status.capitalize()}"
        msg = f"Scan job {job_id} finished with status '{status}'. Discovered {hosts} hosts and generated {findings} findings."
        if user_id:
            cls.send_in_app_notification(user_id, title, msg, org_id)

    @classmethod
    def notify_critical_finding(cls, org_id: uuid.UUID, asset_id: uuid.UUID, title: str) -> None:
        subject = "CRITICAL VULNERABILITY DETECTED"
        msg = f"A critical vulnerability '{title}' was detected on asset {asset_id}. Immediate review required."
        # Broadcast to org admins (mocked)
        logger.warning(f"[BROADCAST NOTIFICATION] Org: {org_id} | {subject} | {msg}")
