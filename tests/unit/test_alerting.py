"""Tests for aastf.alerting — Slack, PagerDuty, webhook integrations."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from aastf.alerting import (
    _PAGERDUTY_EVENTS_URL,
    Alert,
    AlertConfig,
    AlertManager,
    AlertSeverity,
    PagerDutyAlerter,
    SlackAlerter,
    WebhookAlerter,
    _http_post,
)
from aastf.models.result import (
    ScanReport,
    TestResult,
    Verdict,
    VulnerabilityFinding,
)
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_trace() -> AgentTrace:
    return AgentTrace(scenario_id="ASI01-001", adapter="test", steps=[])


def _make_finding(
    *,
    scenario_id: str = "ASI01-001",
    severity: Severity = Severity.CRITICAL,
    verdict: Verdict = Verdict.VULNERABLE,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name=f"Test scenario {scenario_id}",
        category=ASICategory.ASI01,
        severity=severity,
        verdict=verdict,
        triggered_by="test",
        description="Agent was compromised",
        remediation="Add guardrails",
    )


def _make_report(
    *,
    vulnerable: int = 2,
    safe: int = 8,
    errors: int = 0,
    risk_score: float = 75.0,
    findings: list[VulnerabilityFinding] | None = None,
) -> ScanReport:
    results: list[TestResult] = []
    for i in range(vulnerable):
        results.append(TestResult(
            scenario_id=f"ASI01-{i + 1:03d}",
            scenario_name=f"Vuln scenario {i + 1}",
            category=ASICategory.ASI01,
            severity=Severity.CRITICAL,
            verdict=Verdict.VULNERABLE,
            trace=_make_trace(),
        ))
    for i in range(safe):
        results.append(TestResult(
            scenario_id=f"ASI02-{i + 1:03d}",
            scenario_name=f"Safe scenario {i + 1}",
            category=ASICategory.ASI02,
            severity=Severity.MEDIUM,
            verdict=Verdict.SAFE,
            trace=_make_trace(),
        ))

    return ScanReport(
        aastf_version="0.10.0",
        adapter="test-adapter",
        total_scenarios=vulnerable + safe + errors,
        vulnerable=vulnerable,
        safe=safe,
        errors=errors,
        overall_risk_score=risk_score,
        results=results,
        findings=findings or [],
    )


@pytest.fixture
def sample_alert() -> Alert:
    return Alert(
        severity=AlertSeverity.CRITICAL,
        title="Critical Finding",
        message="Agent compromised in ASI01-001",
        timestamp=datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc),
        metadata={"scenario_id": "ASI01-001", "run_id": "abc123"},
    )


@pytest.fixture
def sample_report() -> ScanReport:
    findings = [_make_finding(), _make_finding(scenario_id="ASI01-002")]
    return _make_report(findings=findings)


# ---------------------------------------------------------------------------
# AlertSeverity enum
# ---------------------------------------------------------------------------


class TestAlertSeverity:
    def test_values(self):
        assert AlertSeverity.INFO == "INFO"
        assert AlertSeverity.WARNING == "WARNING"
        assert AlertSeverity.CRITICAL == "CRITICAL"

    def test_str(self):
        assert str(AlertSeverity.CRITICAL) == "CRITICAL"


# ---------------------------------------------------------------------------
# AlertConfig model
# ---------------------------------------------------------------------------


class TestAlertConfig:
    def test_defaults(self):
        cfg = AlertConfig()
        assert cfg.slack_webhook_url is None
        assert cfg.pagerduty_routing_key is None
        assert cfg.webhook_url is None
        assert cfg.webhook_template is None
        assert cfg.severity_threshold == AlertSeverity.INFO

    def test_all_fields(self):
        cfg = AlertConfig(
            slack_webhook_url="https://hooks.slack.com/xxx",
            pagerduty_routing_key="pd-key-123",
            webhook_url="https://example.com/hook",
            webhook_template='{"sev": "{severity}"}',
            severity_threshold=AlertSeverity.CRITICAL,
        )
        assert cfg.slack_webhook_url == "https://hooks.slack.com/xxx"
        assert cfg.severity_threshold == AlertSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------


class TestAlert:
    def test_defaults(self):
        a = Alert(severity=AlertSeverity.INFO, title="Hi", message="msg")
        assert a.metadata == {}
        assert a.timestamp is not None

    def test_full(self, sample_alert: Alert):
        assert sample_alert.severity == AlertSeverity.CRITICAL
        assert sample_alert.metadata["scenario_id"] == "ASI01-001"


# ---------------------------------------------------------------------------
# SlackAlerter
# ---------------------------------------------------------------------------


class TestSlackAlerter:
    def test_format_message_blocks_structure(self, sample_report: ScanReport):
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_message(sample_report)
        assert "blocks" in payload
        blocks = payload["blocks"]
        assert blocks[0]["type"] == "header"
        assert "test-adapter" in blocks[0]["text"]["text"]

    def test_format_message_summary_section(self, sample_report: ScanReport):
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_message(sample_report)
        section = payload["blocks"][1]
        assert section["type"] == "section"
        text = section["text"]["text"]
        assert "Risk Score" in text
        assert "75.0" in text

    def test_format_message_critical_findings(self, sample_report: ScanReport):
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_message(sample_report)
        # Should have header, summary, critical findings, divider
        assert len(payload["blocks"]) == 4
        assert "Critical Findings" in payload["blocks"][2]["text"]["text"]

    def test_format_message_no_critical_findings(self):
        report = _make_report(vulnerable=0, safe=5, risk_score=10.0)
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_message(report)
        # header + summary + divider only
        assert len(payload["blocks"]) == 3

    def test_format_message_risk_emoji_red(self):
        report = _make_report(risk_score=80.0)
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_message(report)
        assert ":red_circle:" in payload["blocks"][1]["text"]["text"]

    def test_format_message_risk_emoji_yellow(self):
        report = _make_report(risk_score=50.0)
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_message(report)
        assert ":large_yellow_circle:" in payload["blocks"][1]["text"]["text"]

    def test_format_message_risk_emoji_green(self):
        report = _make_report(risk_score=20.0)
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_message(report)
        assert ":large_green_circle:" in payload["blocks"][1]["text"]["text"]

    def test_format_alert(self, sample_alert: Alert):
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_alert(sample_alert)
        assert payload["blocks"][0]["text"]["text"] == "Critical Finding"
        assert ":rotating_light:" in payload["blocks"][1]["text"]["text"]

    def test_format_alert_info_emoji(self):
        a = Alert(severity=AlertSeverity.INFO, title="FYI", message="all good")
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        payload = sa.format_alert(a)
        assert ":information_source:" in payload["blocks"][1]["text"]["text"]

    @patch("aastf.alerting._http_post", return_value=200)
    def test_send_success(self, mock_post: MagicMock, sample_alert: Alert):
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        status = sa.send(sample_alert)
        assert status == 200
        mock_post.assert_called_once()
        call_url = mock_post.call_args[0][0]
        assert call_url == "https://hooks.slack.com/xxx"

    @patch("aastf.alerting._http_post", return_value=0)
    def test_send_failure(self, mock_post: MagicMock, sample_alert: Alert):
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        status = sa.send(sample_alert)
        assert status == 0

    @patch("aastf.alerting._http_post", return_value=200)
    def test_send_report(self, mock_post: MagicMock, sample_report: ScanReport):
        sa = SlackAlerter("https://hooks.slack.com/xxx")
        status = sa.send_report(sample_report)
        assert status == 200


# ---------------------------------------------------------------------------
# PagerDutyAlerter
# ---------------------------------------------------------------------------


class TestPagerDutyAlerter:
    def test_format_event_structure(self, sample_alert: Alert):
        pd = PagerDutyAlerter("routing-key-123")
        event = pd.format_event(sample_alert)
        assert event["routing_key"] == "routing-key-123"
        assert event["event_action"] == "trigger"
        assert event["payload"]["source"] == "aastf"
        assert event["payload"]["severity"] == "critical"

    def test_format_event_warning(self):
        a = Alert(severity=AlertSeverity.WARNING, title="Warn", message="hmm")
        pd = PagerDutyAlerter("key")
        event = pd.format_event(a)
        assert event["payload"]["severity"] == "warning"

    def test_format_event_info(self):
        a = Alert(severity=AlertSeverity.INFO, title="Info", message="ok")
        pd = PagerDutyAlerter("key")
        event = pd.format_event(a)
        assert event["payload"]["severity"] == "info"

    def test_format_event_summary_truncated(self):
        long_msg = "x" * 2000
        a = Alert(severity=AlertSeverity.CRITICAL, title="T", message=long_msg)
        pd = PagerDutyAlerter("key")
        event = pd.format_event(a)
        assert len(event["payload"]["summary"]) <= 1024

    def test_format_event_metadata(self, sample_alert: Alert):
        pd = PagerDutyAlerter("key")
        event = pd.format_event(sample_alert)
        assert event["payload"]["custom_details"] == sample_alert.metadata

    @patch("aastf.alerting._http_post", return_value=202)
    def test_trigger_success(self, mock_post: MagicMock, sample_alert: Alert):
        pd = PagerDutyAlerter("routing-key")
        status = pd.trigger(sample_alert)
        assert status == 202
        mock_post.assert_called_once()
        assert mock_post.call_args[0][0] == _PAGERDUTY_EVENTS_URL

    @patch("aastf.alerting._http_post", return_value=0)
    def test_trigger_failure(self, mock_post: MagicMock, sample_alert: Alert):
        pd = PagerDutyAlerter("routing-key")
        status = pd.trigger(sample_alert)
        assert status == 0


# ---------------------------------------------------------------------------
# WebhookAlerter
# ---------------------------------------------------------------------------


class TestWebhookAlerter:
    def test_format_payload_default(self, sample_alert: Alert):
        wh = WebhookAlerter("https://example.com/hook")
        payload = wh.format_payload(sample_alert)
        assert payload["event"] == "aastf_alert"
        assert payload["severity"] == "CRITICAL"
        assert payload["title"] == "Critical Finding"

    def test_format_payload_with_template(self, sample_alert: Alert):
        tpl = '{"level": "{severity}", "text": "{title}: {message}"}'
        wh = WebhookAlerter("https://example.com/hook", template=tpl)
        payload = wh.format_payload(sample_alert)
        assert payload["level"] == "CRITICAL"
        assert "Critical Finding" in payload["text"]

    def test_format_payload_template_override(self, sample_alert: Alert):
        wh = WebhookAlerter("https://example.com/hook", template='{"a": "1"}')
        override = '{"b": "{severity}"}'
        payload = wh.format_payload(sample_alert, template=override)
        assert payload["b"] == "CRITICAL"
        assert "a" not in payload

    def test_format_payload_invalid_template_falls_back(self, sample_alert: Alert):
        bad_tpl = "not valid json {severity}"
        wh = WebhookAlerter("https://example.com/hook", template=bad_tpl)
        payload = wh.format_payload(sample_alert)
        # Falls back to default structure
        assert payload["event"] == "aastf_alert"

    def test_format_payload_timestamp_placeholder(self, sample_alert: Alert):
        tpl = '{"ts": "{timestamp}", "sev": "{severity}"}'
        wh = WebhookAlerter("https://example.com/hook")
        payload = wh.format_payload(sample_alert, template=tpl)
        assert payload["ts"] == sample_alert.timestamp.isoformat()
        assert payload["sev"] == "CRITICAL"

    @patch("aastf.alerting._http_post", return_value=200)
    def test_send(self, mock_post: MagicMock, sample_alert: Alert):
        wh = WebhookAlerter("https://example.com/hook")
        status = wh.send(sample_alert)
        assert status == 200
        assert mock_post.call_args[0][0] == "https://example.com/hook"


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------


class TestAlertManager:
    def test_has_channels_true(self):
        cfg = AlertConfig(slack_webhook_url="https://hooks.slack.com/xxx")
        mgr = AlertManager(cfg)
        assert mgr.has_channels is True

    def test_has_channels_false(self):
        cfg = AlertConfig()
        mgr = AlertManager(cfg)
        assert mgr.has_channels is False

    def test_from_report_critical_risk_score(self):
        findings = [_make_finding()]
        report = _make_report(risk_score=80.0, findings=findings)
        mgr = AlertManager(AlertConfig())
        alerts = mgr.from_report(report)
        # 1 finding alert + 1 summary alert
        assert len(alerts) == 2
        summary = [a for a in alerts if a.title == "AASTF Scan Summary"]
        assert len(summary) == 1
        assert summary[0].severity == AlertSeverity.CRITICAL

    def test_from_report_warning_risk_score(self):
        report = _make_report(risk_score=50.0, vulnerable=1, safe=9)
        mgr = AlertManager(AlertConfig())
        alerts = mgr.from_report(report)
        summary = [a for a in alerts if a.title == "AASTF Scan Summary"]
        assert len(summary) == 1
        assert summary[0].severity == AlertSeverity.WARNING

    def test_from_report_info_vulnerabilities(self):
        report = _make_report(risk_score=20.0, vulnerable=1, safe=9)
        mgr = AlertManager(AlertConfig())
        alerts = mgr.from_report(report)
        summary = [a for a in alerts if a.title == "AASTF Scan Summary"]
        assert len(summary) == 1
        assert summary[0].severity == AlertSeverity.INFO

    def test_from_report_no_summary_when_clean(self):
        report = _make_report(vulnerable=0, safe=10, risk_score=0.0)
        mgr = AlertManager(AlertConfig())
        alerts = mgr.from_report(report)
        assert len(alerts) == 0

    def test_from_report_severity_threshold_filters(self):
        findings = [
            _make_finding(severity=Severity.LOW),
            _make_finding(scenario_id="ASI01-002", severity=Severity.CRITICAL),
        ]
        report = _make_report(risk_score=80.0, findings=findings)
        mgr = AlertManager(AlertConfig(severity_threshold=AlertSeverity.WARNING))
        alerts = mgr.from_report(report)
        # Only the CRITICAL finding + CRITICAL summary (LOW maps to INFO, filtered out)
        finding_alerts = [a for a in alerts if a.title.startswith("Finding")]
        assert len(finding_alerts) == 1
        assert "ASI01-002" in finding_alerts[0].title

    def test_from_report_empty_report(self):
        report = ScanReport(aastf_version="0.10.0", adapter="test")
        mgr = AlertManager(AlertConfig())
        alerts = mgr.from_report(report)
        assert alerts == []

    @patch("aastf.alerting._http_post", return_value=200)
    def test_dispatch_all_channels(self, mock_post: MagicMock, sample_alert: Alert):
        cfg = AlertConfig(
            slack_webhook_url="https://hooks.slack.com/xxx",
            pagerduty_routing_key="pd-key",
            webhook_url="https://example.com/hook",
        )
        mgr = AlertManager(cfg)
        results = mgr.dispatch([sample_alert])
        assert "slack" in results
        assert "pagerduty" in results
        assert "webhook" in results
        assert results["slack"] == [200]
        assert results["pagerduty"] == [200]
        assert results["webhook"] == [200]

    @patch("aastf.alerting._http_post", return_value=200)
    def test_dispatch_slack_only(self, mock_post: MagicMock, sample_alert: Alert):
        cfg = AlertConfig(slack_webhook_url="https://hooks.slack.com/xxx")
        mgr = AlertManager(cfg)
        results = mgr.dispatch([sample_alert])
        assert "slack" in results
        assert "pagerduty" not in results
        assert "webhook" not in results

    @patch("aastf.alerting._http_post", return_value=200)
    def test_dispatch_pagerduty_filters_info(self, mock_post: MagicMock):
        info_alert = Alert(severity=AlertSeverity.INFO, title="FYI", message="ok")
        cfg = AlertConfig(pagerduty_routing_key="pd-key")
        mgr = AlertManager(cfg)
        results = mgr.dispatch([info_alert])
        # INFO should not trigger PagerDuty
        assert results["pagerduty"] == []

    @patch("aastf.alerting._http_post", return_value=200)
    def test_dispatch_no_channels(self, mock_post: MagicMock, sample_alert: Alert):
        cfg = AlertConfig()
        mgr = AlertManager(cfg)
        results = mgr.dispatch([sample_alert])
        assert results == {}
        mock_post.assert_not_called()

    @patch("aastf.alerting._http_post", return_value=200)
    def test_dispatch_multiple_alerts(self, mock_post: MagicMock):
        alerts = [
            Alert(severity=AlertSeverity.CRITICAL, title="A", message="m1"),
            Alert(severity=AlertSeverity.WARNING, title="B", message="m2"),
        ]
        cfg = AlertConfig(slack_webhook_url="https://hooks.slack.com/xxx")
        mgr = AlertManager(cfg)
        results = mgr.dispatch(alerts)
        assert results["slack"] == [200, 200]
        assert mock_post.call_count == 2

    def test_config_property(self):
        cfg = AlertConfig(slack_webhook_url="https://hooks.slack.com/xxx")
        mgr = AlertManager(cfg)
        assert mgr.config is cfg


# ---------------------------------------------------------------------------
# _http_post transport
# ---------------------------------------------------------------------------


class TestHttpPost:
    @patch("aastf.alerting.urllib.request.urlopen")
    def test_success(self, mock_urlopen: MagicMock):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        status = _http_post("https://example.com", {"key": "val"})
        assert status == 200

    @patch("aastf.alerting.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("fail")
        status = _http_post("https://example.com", {"key": "val"})
        assert status == 0

    @patch("aastf.alerting.urllib.request.urlopen")
    def test_custom_headers(self, mock_urlopen: MagicMock):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        status = _http_post("https://example.com", {}, headers={"X-Custom": "yes"})
        assert status == 201
