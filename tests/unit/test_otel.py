"""Tests for aastf.otel — OpenTelemetry exporter, Prometheus metrics, Grafana dashboards."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from aastf.models.result import (
    ScanReport,
    TestResult,
    Verdict,
)
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace, ToolInvocation, TraceEvent, TraceEventType
from aastf.otel import AastfSpan, GrafanaDashboard, OTelExporter, PrometheusMetricsServer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_trace(
    scenario_id: str = "ASI01-001",
    adapter: str = "langgraph",
    *,
    with_tools: bool = True,
    with_events: bool = False,
    with_error: bool = False,
    ended: bool = True,
) -> AgentTrace:
    now = datetime(2026, 5, 29, 12, 0, 0, tzinfo=timezone.utc)
    end = now + timedelta(seconds=2) if ended else None
    tools = []
    if with_tools:
        tools = [
            ToolInvocation(
                tool_name="read_file",
                inputs={"path": "/etc/passwd"},
                outputs="root:x:0:0",
                duration_ms=50.0,
                sequence=0,
            ),
            ToolInvocation(
                tool_name="exec_cmd",
                inputs={"cmd": "whoami"},
                error="permission denied" if with_error else None,
                duration_ms=120.0,
                sequence=1,
            ),
        ]
    events = []
    if with_events:
        events = [
            TraceEvent(
                event_type=TraceEventType.TOOL_START,
                run_id="run-1",
                name="read_file",
                timestamp=now,
                sequence=0,
            ),
            TraceEvent(
                event_type=TraceEventType.TOOL_END,
                run_id="run-1",
                name="read_file",
                timestamp=now + timedelta(milliseconds=50),
                sequence=1,
            ),
        ]
    return AgentTrace(
        scenario_id=scenario_id,
        adapter=adapter,
        started_at=now,
        ended_at=end,
        tool_invocations=tools,
        events=events,
        error="boom" if with_error else None,
        iteration_count=3,
    )


def _make_report(
    *,
    total: int = 10,
    vulnerable: int = 3,
    safe: int = 5,
    inconclusive: int = 1,
    errors: int = 1,
    with_results: bool = True,
    with_asi_summary: bool = True,
) -> ScanReport:
    results = []
    if with_results:
        for i in range(vulnerable):
            trace = _make_trace(scenario_id=f"ASI01-{i + 1:03d}")
            results.append(
                TestResult(
                    scenario_id=trace.scenario_id,
                    scenario_name=f"Test {i}",
                    category=ASICategory.ASI01,
                    severity=Severity.HIGH,
                    verdict=Verdict.VULNERABLE,
                    trace=trace,
                    execution_time_ms=200.0 + i * 10,
                )
            )
        for i in range(safe):
            trace = _make_trace(scenario_id=f"ASI02-{i + 1:03d}")
            results.append(
                TestResult(
                    scenario_id=trace.scenario_id,
                    scenario_name=f"Safe test {i}",
                    category=ASICategory.ASI02,
                    severity=Severity.MEDIUM,
                    verdict=Verdict.SAFE,
                    trace=trace,
                    execution_time_ms=100.0 + i * 5,
                )
            )
    asi_summary = {}
    if with_asi_summary:
        asi_summary = {
            "ASI01": {"vulnerable": vulnerable, "safe": 0},
            "ASI02": {"vulnerable": 0, "safe": safe},
        }
    return ScanReport(
        aastf_version="0.10.0",
        adapter="langgraph",
        total_scenarios=total,
        vulnerable=vulnerable,
        safe=safe,
        inconclusive=inconclusive,
        errors=errors,
        overall_risk_score=45.0,
        results=results,
        asi_summary=asi_summary,
    )


# ---------------------------------------------------------------------------
# AastfSpan model
# ---------------------------------------------------------------------------


class TestAastfSpan:
    def test_default_fields(self) -> None:
        span = AastfSpan(trace_id="abc123", operation_name="test.op")
        assert span.trace_id == "abc123"
        assert span.service_name == "aastf"
        assert span.status == "OK"
        assert span.parent_span_id is None
        assert span.attributes == {}
        assert span.events == []

    def test_to_otlp_dict_structure(self) -> None:
        span = AastfSpan(
            trace_id="t1",
            span_id="s1",
            operation_name="scan",
            status="OK",
            attributes={"key": "val"},
        )
        d = span.to_otlp_dict()
        assert d["traceId"] == "t1"
        assert d["spanId"] == "s1"
        assert d["name"] == "scan"
        assert d["kind"] == 1
        assert d["status"]["code"] == 1
        assert len(d["attributes"]) == 1
        assert d["attributes"][0]["key"] == "key"

    def test_to_otlp_dict_error_status(self) -> None:
        span = AastfSpan(trace_id="t2", operation_name="fail", status="ERROR")
        d = span.to_otlp_dict()
        assert d["status"]["code"] == 2

    def test_to_otlp_dict_empty_parent(self) -> None:
        span = AastfSpan(trace_id="t3", operation_name="op")
        d = span.to_otlp_dict()
        assert d["parentSpanId"] == ""

    def test_to_otlp_dict_with_parent(self) -> None:
        span = AastfSpan(trace_id="t4", operation_name="op", parent_span_id="p1")
        d = span.to_otlp_dict()
        assert d["parentSpanId"] == "p1"


# ---------------------------------------------------------------------------
# OTelExporter — traces_to_spans
# ---------------------------------------------------------------------------


class TestTracesToSpans:
    def test_empty_traces(self) -> None:
        spans = OTelExporter.traces_to_spans([])
        assert spans == []

    def test_single_trace_produces_root_and_tool_spans(self) -> None:
        trace = _make_trace()
        spans = OTelExporter.traces_to_spans([trace])
        # 1 root + 2 tool invocations
        assert len(spans) == 3

    def test_root_span_attributes(self) -> None:
        trace = _make_trace(scenario_id="ASI02-001", adapter="crewai")
        spans = OTelExporter.traces_to_spans([trace])
        root = spans[0]
        assert root.attributes["aastf.scenario_id"] == "ASI02-001"
        assert root.attributes["aastf.adapter"] == "crewai"
        assert root.operation_name == "scenario.ASI02-001"

    def test_root_span_duration(self) -> None:
        trace = _make_trace()
        spans = OTelExporter.traces_to_spans([trace])
        root = spans[0]
        assert root.duration_ms == pytest.approx(2000.0, abs=1)

    def test_tool_child_spans_have_parent(self) -> None:
        trace = _make_trace()
        spans = OTelExporter.traces_to_spans([trace])
        root = spans[0]
        for child in spans[1:]:
            assert child.parent_span_id == root.span_id
            assert child.trace_id == root.trace_id

    def test_tool_span_names(self) -> None:
        trace = _make_trace()
        spans = OTelExporter.traces_to_spans([trace])
        assert spans[1].operation_name == "tool.read_file"
        assert spans[2].operation_name == "tool.exec_cmd"

    def test_tool_span_error_status(self) -> None:
        trace = _make_trace(with_error=True)
        spans = OTelExporter.traces_to_spans([trace])
        # root has error
        assert spans[0].status == "ERROR"
        # second tool invocation has error
        assert spans[2].status == "ERROR"
        # first tool invocation is OK
        assert spans[1].status == "OK"

    def test_trace_without_tools(self) -> None:
        trace = _make_trace(with_tools=False)
        spans = OTelExporter.traces_to_spans([trace])
        assert len(spans) == 1  # root only

    def test_trace_with_events(self) -> None:
        trace = _make_trace(with_events=True)
        spans = OTelExporter.traces_to_spans([trace])
        root = spans[0]
        assert len(root.events) == 2
        assert root.events[0]["name"] == "tool_start"

    def test_trace_not_ended(self) -> None:
        trace = _make_trace(ended=False)
        spans = OTelExporter.traces_to_spans([trace])
        root = spans[0]
        assert root.duration_ms == 0.0
        assert root.start_time_unix_nano == root.end_time_unix_nano

    def test_multiple_traces(self) -> None:
        t1 = _make_trace(scenario_id="ASI01-001")
        t2 = _make_trace(scenario_id="ASI02-001", with_tools=False)
        spans = OTelExporter.traces_to_spans([t1, t2])
        # t1: 1 root + 2 tools, t2: 1 root
        assert len(spans) == 4

    def test_span_trace_id_has_no_dashes(self) -> None:
        trace = _make_trace()
        # Force a UUID with dashes
        trace.trace_id = str(uuid.uuid4())
        spans = OTelExporter.traces_to_spans([trace])
        assert "-" not in spans[0].trace_id


# ---------------------------------------------------------------------------
# OTelExporter — export_otlp
# ---------------------------------------------------------------------------


class TestExportOtlp:
    def test_export_returns_resource_spans(self) -> None:
        trace = _make_trace()
        spans = OTelExporter.traces_to_spans([trace])
        payload = OTelExporter.export_otlp(spans, "http://localhost:4318")
        assert "resourceSpans" in payload
        assert len(payload["resourceSpans"]) == 1

    def test_export_contains_service_name(self) -> None:
        spans = OTelExporter.traces_to_spans([_make_trace()])
        payload = OTelExporter.export_otlp(spans, "http://localhost:4318")
        attrs = payload["resourceSpans"][0]["resource"]["attributes"]
        assert any(a["key"] == "service.name" for a in attrs)

    def test_export_scope_name(self) -> None:
        spans = OTelExporter.traces_to_spans([_make_trace()])
        payload = OTelExporter.export_otlp(spans, "http://localhost:4318")
        scope = payload["resourceSpans"][0]["scopeSpans"][0]["scope"]
        assert scope["name"] == "aastf.otel"

    def test_export_empty_spans(self) -> None:
        payload = OTelExporter.export_otlp([], "http://localhost:4318")
        scope_spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
        assert scope_spans == []

    def test_no_post_by_default(self, monkeypatch) -> None:
        import urllib.request
        called = {"n": 0}

        def _fail(*a, **k):
            called["n"] += 1
            raise AssertionError("should not POST when send=False")

        monkeypatch.setattr(urllib.request, "urlopen", _fail)
        OTelExporter.export_otlp([], "http://localhost:4318")
        assert called["n"] == 0

    def test_send_posts_payload(self, monkeypatch) -> None:
        import json
        import urllib.request

        captured = {}

        class _FakeResp:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def _fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["body"] = json.loads(req.data.decode("utf-8"))
            captured["content_type"] = req.headers.get("Content-type")
            return _FakeResp()

        monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)
        spans = OTelExporter.traces_to_spans([_make_trace()])
        payload = OTelExporter.export_otlp(
            spans, "http://collector:4318/v1/traces", send=True,
        )
        assert captured["url"] == "http://collector:4318/v1/traces"
        assert captured["method"] == "POST"
        assert captured["content_type"] == "application/json"
        assert captured["body"] == payload


# ---------------------------------------------------------------------------
# OTelExporter — prometheus_metrics
# ---------------------------------------------------------------------------


class TestPrometheusMetrics:
    def test_contains_total_scenarios(self) -> None:
        report = _make_report()
        text = OTelExporter.prometheus_metrics(report)
        assert "aastf_total_scenarios 10" in text

    def test_contains_vulnerable_total(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert "aastf_vulnerable_total 3" in text

    def test_contains_safe_total(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert "aastf_safe_total 5" in text

    def test_contains_risk_score(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert "aastf_risk_score 45.0" in text

    def test_help_lines_present(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert "# HELP aastf_total_scenarios" in text
        assert "# TYPE aastf_total_scenarios gauge" in text

    def test_verdict_breakdown(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert 'aastf_verdict_count{verdict="VULNERABLE"}' in text
        assert 'aastf_verdict_count{verdict="SAFE"}' in text

    def test_category_vulnerable(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert 'aastf_category_vulnerable{category="ASI01"} 3' in text
        assert 'aastf_category_vulnerable{category="ASI02"} 0' in text

    def test_scenario_duration_lines(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert "aastf_scenario_duration_ms" in text

    def test_empty_report(self) -> None:
        report = ScanReport(
            aastf_version="0.10.0",
            adapter="test",
            total_scenarios=0,
        )
        text = OTelExporter.prometheus_metrics(report)
        assert "aastf_total_scenarios 0" in text
        # No verdict or category lines
        assert "aastf_verdict_count" not in text
        assert "aastf_category_vulnerable" not in text

    def test_no_results_no_duration_lines(self) -> None:
        report = _make_report(with_results=False)
        text = OTelExporter.prometheus_metrics(report)
        assert "aastf_scenario_duration_ms" not in text

    def test_vulnerability_rate_metric(self) -> None:
        text = OTelExporter.prometheus_metrics(_make_report())
        assert "aastf_vulnerability_rate 30.0" in text


# ---------------------------------------------------------------------------
# PrometheusMetricsServer
# ---------------------------------------------------------------------------


class TestPrometheusMetricsServer:
    def test_update_stores_metrics(self) -> None:
        server = PrometheusMetricsServer(port=0)
        report = _make_report()
        server.update(report)
        assert "aastf_total_scenarios" in server._metrics_text

    def test_default_port(self) -> None:
        server = PrometheusMetricsServer()
        assert server.port == 9090


# ---------------------------------------------------------------------------
# GrafanaDashboard
# ---------------------------------------------------------------------------


class TestGrafanaDashboard:
    def test_generate_returns_dict(self) -> None:
        result = GrafanaDashboard.generate("My Scan")
        assert isinstance(result, dict)

    def test_dashboard_title(self) -> None:
        result = GrafanaDashboard.generate("Custom Title")
        assert result["dashboard"]["title"] == "Custom Title"

    def test_default_title(self) -> None:
        result = GrafanaDashboard.generate()
        assert result["dashboard"]["title"] == "AASTF Security Scan"

    def test_has_panels(self) -> None:
        result = GrafanaDashboard.generate()
        panels = result["dashboard"]["panels"]
        assert len(panels) == 6

    def test_panel_titles(self) -> None:
        result = GrafanaDashboard.generate()
        titles = {p["title"] for p in result["dashboard"]["panels"]}
        assert "Vulnerabilities by Category" in titles
        assert "Pass / Fail Ratio" in titles
        assert "Scan Duration" in titles
        assert "Verdict Distribution" in titles

    def test_panel_types(self) -> None:
        result = GrafanaDashboard.generate()
        types = {p["type"] for p in result["dashboard"]["panels"]}
        assert "piechart" in types
        assert "stat" in types
        assert "barchart" in types

    def test_datasource_template_variable(self) -> None:
        result = GrafanaDashboard.generate()
        tpl = result["dashboard"]["templating"]["list"]
        assert any(t["name"] == "DS_PROMETHEUS" for t in tpl)

    def test_panels_have_targets(self) -> None:
        result = GrafanaDashboard.generate()
        for panel in result["dashboard"]["panels"]:
            assert "targets" in panel
            assert len(panel["targets"]) >= 1
            assert "expr" in panel["targets"][0]

    def test_dashboard_tags(self) -> None:
        result = GrafanaDashboard.generate()
        tags = result["dashboard"]["tags"]
        assert "aastf" in tags
        assert "security" in tags

    def test_overwrite_flag(self) -> None:
        result = GrafanaDashboard.generate()
        assert result["overwrite"] is True

    def test_schema_version(self) -> None:
        result = GrafanaDashboard.generate()
        assert result["dashboard"]["schemaVersion"] == 39

    def test_uid(self) -> None:
        result = GrafanaDashboard.generate()
        assert result["dashboard"]["uid"] == "aastf-security-scan"

    def test_piechart_has_options(self) -> None:
        result = GrafanaDashboard.generate()
        pie_panels = [p for p in result["dashboard"]["panels"] if p["type"] == "piechart"]
        assert len(pie_panels) >= 1
        for p in pie_panels:
            assert "options" in p
            assert "pieType" in p["options"]

    def test_panels_have_grid_pos(self) -> None:
        result = GrafanaDashboard.generate()
        for panel in result["dashboard"]["panels"]:
            gp = panel["gridPos"]
            assert "h" in gp
            assert "w" in gp
            assert "x" in gp
            assert "y" in gp
