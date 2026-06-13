"""Alerting integrations — Slack, PagerDuty, and generic webhooks.

Send scan results, regressions, and critical findings to external
notification channels.  All HTTP calls go through a thin transport
layer so callers can mock/replace it in tests.
"""

from __future__ import annotations

import json
import logging
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from enum import Enum
from typing import Any

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:

    class StrEnum(str, Enum):  # noqa: N801
        """Backport for Python 3.10."""

        def __str__(self) -> str:
            return self.value


from pydantic import BaseModel, Field

from .models.result import ScanReport, Verdict
from .models.scenario import Severity

logger = logging.getLogger(__name__)

# PagerDuty Events API v2 endpoint
_PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


# ---------------------------------------------------------------------------
# Enums & models
# ---------------------------------------------------------------------------


class AlertSeverity(StrEnum):
    """Severity levels for alerts dispatched by the AlertManager."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AlertConfig(BaseModel):
    """Configuration for alert channels."""

    slack_webhook_url: str | None = None
    pagerduty_routing_key: str | None = None
    webhook_url: str | None = None
    webhook_template: str | None = None
    severity_threshold: AlertSeverity = AlertSeverity.INFO


class Alert(BaseModel):
    """A single alert to be dispatched."""

    severity: AlertSeverity
    title: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Transport helper (mockable)
# ---------------------------------------------------------------------------


def _http_post(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> int:
    """Synchronous HTTP POST.  Returns status code (0 on network error)."""
    hdrs = {"Content-Type": "application/json", "User-Agent": "aastf-alerting/1.0"}
    if headers:
        hdrs.update(headers)

    from .netsec import UnsafeURLError, validate_outbound_url

    try:
        validate_outbound_url(url)
    except UnsafeURLError as exc:
        logger.error("Refusing to POST to unsafe URL: %s", exc)
        return 0

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (scheme validated above)
            return resp.status  # type: ignore[return-value]
    except urllib.error.URLError as exc:
        logger.error("HTTP POST to %s failed: %s", url, exc)
        return 0


# ---------------------------------------------------------------------------
# SlackAlerter
# ---------------------------------------------------------------------------


class SlackAlerter:
    """Format and send alerts to a Slack incoming webhook."""

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    # -- formatting ----------------------------------------------------------

    def format_message(self, report: ScanReport) -> dict[str, Any]:
        """Build a Slack Block Kit payload summarising a *ScanReport*."""
        risk_emoji = ":red_circle:" if report.overall_risk_score >= 70 else (
            ":large_yellow_circle:" if report.overall_risk_score >= 40 else ":large_green_circle:"
        )

        header_text = f"AASTF Scan Complete — {report.adapter}"
        summary_lines = [
            f"*Run ID:* `{report.run_id}`",
            f"*Risk Score:* {risk_emoji} {report.overall_risk_score}",
            f"*Scenarios:* {report.total_scenarios}  |  "
            f"*Vulnerable:* {report.vulnerable}  |  "
            f"*Safe:* {report.safe}  |  "
            f"*Errors:* {report.errors}",
            f"*EU AI Act:* {report.eu_ai_act_readiness}",
        ]

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(summary_lines)},
            },
        ]

        # Critical findings
        if report.critical_findings:
            finding_lines: list[str] = []
            for f in report.critical_findings[:5]:
                finding_lines.append(
                    f"- `{f.scenario_id}` {f.scenario_name}: {f.verdict.value}"
                )
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Critical Findings:*\n" + "\n".join(finding_lines),
                },
            })

        blocks.append({"type": "divider"})

        return {"blocks": blocks}

    def format_alert(self, alert: Alert) -> dict[str, Any]:
        """Build a Slack Block Kit payload for a single *Alert*."""
        severity_emoji = {
            AlertSeverity.INFO: ":information_source:",
            AlertSeverity.WARNING: ":warning:",
            AlertSeverity.CRITICAL: ":rotating_light:",
        }.get(alert.severity, ":grey_question:")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": alert.title},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{severity_emoji} *{alert.severity.value}*\n{alert.message}",
                },
            },
            {"type": "divider"},
        ]
        return {"blocks": blocks}

    # -- sending -------------------------------------------------------------

    def send(self, alert: Alert) -> int:
        """POST an alert to the Slack webhook.  Returns HTTP status code."""
        payload = self.format_alert(alert)
        status = _http_post(self._webhook_url, payload)
        if status and 200 <= status < 300:
            logger.info("Slack alert sent: %s", alert.title)
        else:
            logger.warning("Slack alert failed (HTTP %d): %s", status, alert.title)
        return status

    def send_report(self, report: ScanReport) -> int:
        """POST a full scan report summary to Slack.  Returns HTTP status code."""
        payload = self.format_message(report)
        return _http_post(self._webhook_url, payload)


# ---------------------------------------------------------------------------
# PagerDutyAlerter
# ---------------------------------------------------------------------------


class PagerDutyAlerter:
    """Format and trigger PagerDuty incidents via Events API v2."""

    def __init__(self, routing_key: str) -> None:
        self._routing_key = routing_key

    _SEVERITY_MAP: dict[AlertSeverity, str] = {
        AlertSeverity.INFO: "info",
        AlertSeverity.WARNING: "warning",
        AlertSeverity.CRITICAL: "critical",
    }

    def format_event(self, alert: Alert) -> dict[str, Any]:
        """Build a PagerDuty Events API v2 trigger payload."""
        return {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"[AASTF] {alert.title}: {alert.message}"[:1024],
                "source": "aastf",
                "severity": self._SEVERITY_MAP.get(alert.severity, "info"),
                "timestamp": alert.timestamp.isoformat(),
                "custom_details": alert.metadata,
            },
        }

    def trigger(self, alert: Alert) -> int:
        """POST a trigger event to PagerDuty.  Returns HTTP status code."""
        payload = self.format_event(alert)
        status = _http_post(_PAGERDUTY_EVENTS_URL, payload)
        if status and 200 <= status < 300:
            logger.info("PagerDuty incident triggered: %s", alert.title)
        else:
            logger.warning("PagerDuty trigger failed (HTTP %d): %s", status, alert.title)
        return status


# ---------------------------------------------------------------------------
# WebhookAlerter
# ---------------------------------------------------------------------------


class WebhookAlerter:
    """Send alerts to a generic webhook endpoint with optional template."""

    def __init__(self, url: str, template: str | None = None) -> None:
        self._url = url
        self._template = template

    def format_payload(self, alert: Alert, template: str | None = None) -> dict[str, Any]:
        """Render *template* (a JSON string with ``{placeholders}``) using alert data.

        If *template* is ``None``, falls back to a default JSON structure.
        Supported placeholders: ``{severity}``, ``{title}``, ``{message}``,
        ``{timestamp}``, ``{metadata}``.
        """
        tpl = template or self._template
        if tpl is None:
            return {
                "event": "aastf_alert",
                "severity": alert.severity.value,
                "title": alert.title,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat(),
                "metadata": alert.metadata,
            }

        rendered = (
            tpl.replace("{severity}", alert.severity.value)
            .replace("{title}", alert.title)
            .replace("{message}", alert.message)
            .replace("{timestamp}", alert.timestamp.isoformat())
            .replace("{metadata}", json.dumps(alert.metadata))
        )

        try:
            return json.loads(rendered)  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            logger.warning("Template rendered to invalid JSON; falling back to default payload")
            return {
                "event": "aastf_alert",
                "severity": alert.severity.value,
                "title": alert.title,
                "message": alert.message,
                "timestamp": alert.timestamp.isoformat(),
                "metadata": alert.metadata,
            }

    def send(self, alert: Alert) -> int:
        """POST an alert to the webhook URL.  Returns HTTP status code."""
        payload = self.format_payload(alert)
        status = _http_post(self._url, payload)
        if status and 200 <= status < 300:
            logger.info("Webhook alert sent to %s: %s", self._url, alert.title)
        else:
            logger.warning("Webhook alert to %s failed (HTTP %d): %s", self._url, status, alert.title)
        return status


# ---------------------------------------------------------------------------
# AlertManager — orchestrates alert generation and dispatch
# ---------------------------------------------------------------------------

# Map scenario Severity -> AlertSeverity
_SEVERITY_MAPPING: dict[Severity, AlertSeverity] = {
    Severity.CRITICAL: AlertSeverity.CRITICAL,
    Severity.HIGH: AlertSeverity.WARNING,
    Severity.MEDIUM: AlertSeverity.WARNING,
    Severity.LOW: AlertSeverity.INFO,
    Severity.INFO: AlertSeverity.INFO,
}

# Verdicts that represent an attack success
_ATTACK_VERDICTS: set[Verdict] = {
    Verdict.VULNERABLE,
    Verdict.TOOL_POISONING,
    Verdict.SCHEMA_POISONING,
    Verdict.PREFERENCE_MANIPULATION,
    Verdict.INFECTION_PROPAGATED,
    Verdict.COLLUSION,
    Verdict.WATCHDOG_BYPASS,
}


class AlertManager:
    """Generate alerts from scan reports and dispatch to configured channels."""

    def __init__(self, config: AlertConfig) -> None:
        self._config = config
        self._slack: SlackAlerter | None = None
        self._pagerduty: PagerDutyAlerter | None = None
        self._webhook: WebhookAlerter | None = None

        if config.slack_webhook_url:
            self._slack = SlackAlerter(config.slack_webhook_url)
        if config.pagerduty_routing_key:
            self._pagerduty = PagerDutyAlerter(config.pagerduty_routing_key)
        if config.webhook_url:
            self._webhook = WebhookAlerter(config.webhook_url, config.webhook_template)

    @property
    def config(self) -> AlertConfig:
        return self._config

    @property
    def has_channels(self) -> bool:
        """Return True if at least one notification channel is configured."""
        return any([self._slack, self._pagerduty, self._webhook])

    # -- alert generation ----------------------------------------------------

    def from_report(self, report: ScanReport) -> list[Alert]:
        """Derive a list of alerts from a completed scan report.

        Rules:
        - One alert per critical finding.
        - A summary alert if overall risk score >= 70 (CRITICAL) or >= 40 (WARNING).
        - An INFO summary if neither threshold is met but vulnerabilities exist.
        """
        alerts: list[Alert] = []
        threshold = self._config.severity_threshold

        # Per-finding alerts
        for finding in report.findings:
            sev = _SEVERITY_MAPPING.get(finding.severity, AlertSeverity.INFO)
            if self._above_threshold(sev, threshold):
                alerts.append(Alert(
                    severity=sev,
                    title=f"Finding: {finding.scenario_id}",
                    message=(
                        f"{finding.scenario_name} — {finding.verdict.value}. "
                        f"{finding.description}"
                    ),
                    metadata={
                        "scenario_id": finding.scenario_id,
                        "category": str(finding.category),
                        "severity": str(finding.severity),
                        "verdict": finding.verdict.value,
                        "run_id": report.run_id,
                    },
                ))

        # Summary alert based on risk score
        if report.overall_risk_score >= 70:
            summary_sev = AlertSeverity.CRITICAL
        elif report.overall_risk_score >= 40:
            summary_sev = AlertSeverity.WARNING
        elif report.vulnerable > 0:
            summary_sev = AlertSeverity.INFO
        else:
            summary_sev = None  # type: ignore[assignment]

        if summary_sev is not None and self._above_threshold(summary_sev, threshold):
            alerts.append(Alert(
                severity=summary_sev,
                title="AASTF Scan Summary",
                message=(
                    f"Risk score {report.overall_risk_score} | "
                    f"{report.vulnerable}/{report.total_scenarios} vulnerable | "
                    f"EU AI Act: {report.eu_ai_act_readiness}"
                ),
                metadata={
                    "run_id": report.run_id,
                    "adapter": report.adapter,
                    "risk_score": report.overall_risk_score,
                    "vulnerable": report.vulnerable,
                    "total_scenarios": report.total_scenarios,
                },
            ))

        return alerts

    # -- dispatch ------------------------------------------------------------

    def dispatch(self, alerts: list[Alert]) -> dict[str, list[int]]:
        """Send *alerts* to all configured channels.

        Returns a dict mapping channel name to list of HTTP status codes.
        """
        results: dict[str, list[int]] = {}

        if self._slack:
            statuses: list[int] = []
            for alert in alerts:
                statuses.append(self._slack.send(alert))
            results["slack"] = statuses

        if self._pagerduty:
            statuses = []
            for alert in alerts:
                # Only trigger PagerDuty for WARNING+ to avoid noise
                if self._above_threshold(alert.severity, AlertSeverity.WARNING):
                    statuses.append(self._pagerduty.trigger(alert))
            results["pagerduty"] = statuses

        if self._webhook:
            statuses = []
            for alert in alerts:
                statuses.append(self._webhook.send(alert))
            results["webhook"] = statuses

        return results

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _above_threshold(severity: AlertSeverity, threshold: AlertSeverity) -> bool:
        """Return True if *severity* is at or above *threshold*."""
        order = {AlertSeverity.INFO: 0, AlertSeverity.WARNING: 1, AlertSeverity.CRITICAL: 2}
        return order.get(severity, 0) >= order.get(threshold, 0)
