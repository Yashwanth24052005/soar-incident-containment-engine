"""
Slack Notifier - Advanced Feature
Sends real-time Slack notifications for critical and high risk alerts.
Requires SLACK_WEBHOOK_URL to be set in the .env file.
"""

import logging
import os
import httpx
from datetime import datetime, timezone

logger = logging.getLogger("soar.notifier")


def _get_webhook_url() -> str:
    return os.getenv("SLACK_WEBHOOK_URL", "").strip()


async def send_slack_alert(
    alert_id: str,
    source_ip: str,
    attack_type: str,
    severity: str,
    risk_level: str,
    composite_score: int,
    recommended_action: str,
) -> bool:
    """
    Sends a Slack notification for high/critical alerts.
    Returns True if sent successfully, False otherwise.
    """
    webhook_url = _get_webhook_url()

    if not webhook_url:
        logger.warning("[NOTIFIER] SLACK_WEBHOOK_URL not set.")
        return False

    emoji = "🔴" if risk_level == "critical" else "🟠"
    color = "#FF0000" if risk_level == "critical" else "#FF8C00"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    message = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} SOAR Alert: {risk_level.upper()} THREAT DETECTED"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Alert ID:*\n`{alert_id}`"},
                            {"type": "mrkdwn", "text": f"*Source IP:*\n`{source_ip}`"},
                            {"type": "mrkdwn", "text": f"*Attack Type:*\n{attack_type.replace('_', ' ').title()}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Risk Score:*\n{composite_score}/100"},
                            {"type": "mrkdwn", "text": f"*Recommended Action:*\n`{recommended_action}`"},
                        ]
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"🛡️ *SOAR Engine* | Infotact Solutions | {timestamp}"
                            }
                        ]
                    }
                ]
            }
        ]
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(webhook_url, json=message)
            response.raise_for_status()
            logger.info(f"[NOTIFIER] Slack alert sent for {alert_id} | risk={risk_level}")
            return True
    except Exception as e:
        logger.error(f"[NOTIFIER] Failed to send Slack alert for {alert_id}: {e}")
        return False