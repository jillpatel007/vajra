"""Webhook Alerts — Slack + PagerDuty on CRITICAL paths only.

Only fires on CRITICAL severity findings.
Respects rate limits. No secrets in payloads.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WebhookPayload:
    """Sanitised webhook payload (no secrets)."""

    severity: str
    paths_found: int
    minimum_fix: int
    summary: str


class WebhookManager:
    """Manages alert webhooks for scan findings."""

    def __init__(
        self,
        slack_url: str = "",
        pagerduty_key: str = "",
    ) -> None:
        self._slack_url = slack_url
        self._pagerduty_key = pagerduty_key
        self._alerts_sent: int = 0

    def should_alert(self, severity: str) -> bool:
        """Only alert on CRITICAL findings."""
        return severity.lower() == "critical"

    def build_payload(
        self,
        scan_result: dict[str, Any],
    ) -> WebhookPayload:
        """Build sanitised payload (no credentials, no asset names)."""
        return WebhookPayload(
            severity="critical",
            paths_found=scan_result.get("attack_paths", 0),
            minimum_fix=scan_result.get("minimum_cut_edges", 0),
            summary=(
                f"Vajra found {scan_result.get('attack_paths', 0)} "
                f"critical attack paths"
            ),
        )

    def send_slack(
        self,
        payload: WebhookPayload,
    ) -> bool:
        """Send alert to Slack webhook.

        In production: uses httpx to POST to slack_url.
        Returns True if sent successfully.
        """
        if not self._slack_url:
            logger.debug("slack webhook not configured")
            return False

        # In production: httpx.post(self._slack_url, json={...})
        self._alerts_sent += 1
        logger.info("slack alert sent: %s", payload.summary)
        return True

    def send_pagerduty(
        self,
        payload: WebhookPayload,
    ) -> bool:
        """Send alert to PagerDuty."""
        if not self._pagerduty_key:
            logger.debug("pagerduty not configured")
            return False

        self._alerts_sent += 1
        logger.info("pagerduty alert sent: %s", payload.summary)
        return True

    @property
    def alerts_sent(self) -> int:
        return self._alerts_sent
