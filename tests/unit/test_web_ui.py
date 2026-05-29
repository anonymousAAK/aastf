"""Tests for the web UI backend server (aastf.web_ui)."""

from __future__ import annotations

import json
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import pytest

from aastf.models.result import ScanReport, TestResult, Verdict
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace
from aastf.web_ui import (
    DashboardData,
    WebUIConfig,
    WebUIServer,
    _category_stats,
    _gauge_color,
    _risk_color,
    _verdict_distribution,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_trace(scenario_id: str = "ASI01-001") -> AgentTrace:
    return AgentTrace(scenario_id=scenario_id, adapter="test")


def _make_result(
    scenario_id: str = "ASI01-001",
    name: str = "Test scenario",
    category: ASICategory = ASICategory.ASI01,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.SAFE,
    time_ms: float = 42.0,
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name=name,
        category=category,
        severity=severity,
        verdict=verdict,
        trace=_make_trace(scenario_id),
        execution_time_ms=time_ms,
    )


def _make_report(results: list[TestResult] | None = None) -> ScanReport:
    if results is None:
        results = [
            _make_result("ASI01-001", "Goal hijack", ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE),
            _make_result("ASI01-002", "Goal redirect", ASICategory.ASI01, Severity.MEDIUM, Verdict.SAFE),
            _make_result("ASI02-001", "Tool misuse", ASICategory.ASI02, Severity.CRITICAL, Verdict.TOOL_POISONING),
            _make_result("ASI03-001", "Priv abuse", ASICategory.ASI03, Severity.HIGH, Verdict.SAFE),
            _make_result("ASI04-001", "Supply chain", ASICategory.ASI04, Severity.LOW, Verdict.INCONCLUSIVE),
            _make_result("ASI05-001", "Code exec", ASICategory.ASI05, Severity.CRITICAL, Verdict.ERROR),
        ]
    return ScanReport(
        aastf_version="2.0.0",
        adapter="test",
        total_scenarios=len(results),
        vulnerable=sum(1 for r in results if r.verdict == Verdict.VULNERABLE),
        safe=sum(1 for r in results if r.verdict == Verdict.SAFE),
        errors=sum(1 for r in results if r.verdict == Verdict.ERROR),
        results=results,
        overall_risk_score=42.5,
    )


@pytest.fixture()
def report() -> ScanReport:
    return _make_report()


@pytest.fixture()
def config() -> WebUIConfig:
    return WebUIConfig(auto_open=False)


@pytest.fixture()
def server(config: WebUIConfig, report: ScanReport) -> WebUIServer:
    s = WebUIServer(config)
    s.load_report(report)
    return s


# ---------------------------------------------------------------------------
# DashboardData model tests
# ---------------------------------------------------------------------------


class TestDashboardData:
    def test_defaults(self) -> None:
        d = DashboardData(report={"key": "val"})
        assert d.version == "2.0.0"
        assert d.report == {"key": "val"}
        assert isinstance(d.generated_at, datetime)

    def test_custom_version(self) -> None:
        d = DashboardData(report={}, version="1.0.0")
        assert d.version == "1.0.0"

    def test_serialization(self) -> None:
        d = DashboardData(report={"a": 1})
        data = d.model_dump(mode="json")
        assert "report" in data
        assert "generated_at" in data


# ---------------------------------------------------------------------------
# WebUIConfig model tests
# ---------------------------------------------------------------------------


class TestWebUIConfig:
    def test_defaults(self) -> None:
        c = WebUIConfig()
        assert c.host == "127.0.0.1"
        assert c.port == 8080
        assert c.auto_open is True
        assert c.report_path is None

    def test_custom(self) -> None:
        c = WebUIConfig(host="0.0.0.0", port=9090, auto_open=False, report_path=Path("/tmp/r.json"))
        assert c.host == "0.0.0.0"
        assert c.port == 9090
        assert c.auto_open is False
        assert c.report_path == Path("/tmp/r.json")


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_risk_color_green(self) -> None:
        assert _risk_color(0) == "#4caf50"

    def test_risk_color_light_green(self) -> None:
        assert _risk_color(20) == "#8bc34a"

    def test_risk_color_orange(self) -> None:
        assert _risk_color(40) == "#ff9800"

    def test_risk_color_red(self) -> None:
        assert _risk_color(60) == "#f44336"

    def test_risk_color_dark_red(self) -> None:
        assert _risk_color(90) == "#b71c1c"

    def test_gauge_color(self) -> None:
        assert _gauge_color(0) == "#4caf50"

    def test_verdict_distribution(self, report: ScanReport) -> None:
        vd = _verdict_distribution(report)
        assert isinstance(vd, dict)
        assert sum(vd.values()) == len(report.results)

    def test_category_stats(self, report: ScanReport) -> None:
        cats = _category_stats(report)
        assert "ASI01" in cats
        assert cats["ASI01"]["total"] == 2


# ---------------------------------------------------------------------------
# HTML generation tests
# ---------------------------------------------------------------------------


class TestDashboardHTML:
    def test_contains_title(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "<title>AASTF Dashboard</title>" in html

    def test_contains_nav(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "/explorer" in html
        assert "/coverage" in html
        assert "/blast-radius" in html

    def test_contains_stats(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "Total Scenarios" in html
        assert "Vulnerable" in html
        assert "Safe" in html

    def test_contains_svg_pie(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "<svg" in html
        assert "Verdict Distribution" in html

    def test_contains_risk_gauge(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "Risk Score" in html
        assert "42.5" in html

    def test_contains_filter_input(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "filterTable" in html
        assert 'id="tbl-filter"' in html

    def test_contains_scenario_ids(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "ASI01-001" in html
        assert "ASI02-001" in html

    def test_contains_version(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_dashboard_html(report)
        assert "2.0.0" in html


class TestExplorerHTML:
    def test_contains_title(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_scenario_explorer_html(report)
        assert "<title>AASTF Scenario Explorer</title>" in html

    def test_contains_search(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_scenario_explorer_html(report)
        assert 'id="search"' in html
        assert "applyFilters" in html

    def test_contains_verdict_filter(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_scenario_explorer_html(report)
        assert 'id="verdict-filter"' in html

    def test_contains_category_filter(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_scenario_explorer_html(report)
        assert 'id="cat-filter"' in html

    def test_contains_data_attributes(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_scenario_explorer_html(report)
        assert 'data-verdict=' in html
        assert 'data-category=' in html


class TestCoverageHTML:
    def test_contains_title(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_coverage_html(report)
        assert "<title>AASTF Coverage Heatmap</title>" in html

    def test_contains_heatmap(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_coverage_html(report)
        assert "ASI Category Heatmap" in html

    def test_contains_risk_pct(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_coverage_html(report)
        # At least one percentage should appear
        assert "%" in html

    def test_contains_summary(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_coverage_html(report)
        assert "Vulnerability rate" in html


class TestBlastRadiusHTML:
    def test_contains_title(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_blast_radius_html(report)
        assert "<title>AASTF Blast Radius</title>" in html

    def test_contains_svg(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_blast_radius_html(report)
        assert '<svg id="svg">' in html

    def test_contains_legend(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_blast_radius_html(report)
        assert "Vulnerable" in html
        assert "Safe" in html

    def test_contains_js(self, server: WebUIServer, report: ScanReport) -> None:
        html = server.generate_blast_radius_html(report)
        assert "createElementNS" in html


# ---------------------------------------------------------------------------
# Empty report edge cases
# ---------------------------------------------------------------------------


class TestEmptyReport:
    def test_dashboard_empty(self, config: WebUIConfig) -> None:
        report = _make_report(results=[])
        srv = WebUIServer(config)
        srv.load_report(report)
        html = srv.generate_dashboard_html(report)
        assert "AASTF Dashboard" in html
        assert "No data" in html

    def test_explorer_empty(self, config: WebUIConfig) -> None:
        report = _make_report(results=[])
        srv = WebUIServer(config)
        html = srv.generate_scenario_explorer_html(report)
        assert "Scenario Explorer" in html

    def test_coverage_empty(self, config: WebUIConfig) -> None:
        report = _make_report(results=[])
        srv = WebUIServer(config)
        html = srv.generate_coverage_html(report)
        assert "Coverage Heatmap" in html


# ---------------------------------------------------------------------------
# Server lifecycle tests
# ---------------------------------------------------------------------------


class TestServerLifecycle:
    def test_load_report(self, server: WebUIServer, report: ScanReport) -> None:
        assert server._report is report

    def test_start_background_and_stop(self, report: ScanReport) -> None:
        cfg = WebUIConfig(host="127.0.0.1", port=0, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)

        # Use port 0 to get a free port — we need to grab it from the server
        # but WebUIServer binds to config.port, so use a high port
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg.port = free_port

        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        # Health check
        url = f"http://127.0.0.1:{free_port}/api/health"
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        assert data["status"] == "ok"
        assert data["version"] == "2.0.0"

        srv.stop()

    def test_api_report(self, report: ScanReport) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/api/report"
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        assert data["aastf_version"] == "2.0.0"
        assert data["total_scenarios"] == 6

        srv.stop()

    def test_api_scenarios(self, report: ScanReport) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/api/scenarios"
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        assert isinstance(data, list)
        assert len(data) == 6
        assert data[0]["scenario_id"] == "ASI01-001"

        srv.stop()

    def test_dashboard_route(self, report: ScanReport) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/"
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read().decode()
        assert "AASTF Dashboard" in body

        srv.stop()

    def test_explorer_route(self, report: ScanReport) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/explorer"
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read().decode()
        assert "Scenario Explorer" in body

        srv.stop()

    def test_coverage_route(self, report: ScanReport) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/coverage"
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read().decode()
        assert "Coverage Heatmap" in body

        srv.stop()

    def test_blast_radius_route(self, report: ScanReport) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/blast-radius"
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read().decode()
        assert "Blast Radius" in body

        srv.stop()

    def test_404_route(self, report: ScanReport) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        srv.load_report(report)
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/nonexistent"
        try:
            urllib.request.urlopen(url, timeout=5)
            pytest.fail("Expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404

        srv.stop()

    def test_no_report_returns_404(self) -> None:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        cfg = WebUIConfig(host="127.0.0.1", port=free_port, auto_open=False)
        srv = WebUIServer(cfg)
        # No report loaded
        srv.start_background()
        time.sleep(0.3)

        url = f"http://127.0.0.1:{free_port}/"
        try:
            urllib.request.urlopen(url, timeout=5)
            pytest.fail("Expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404

        srv.stop()

    def test_stop_idempotent(self, config: WebUIConfig) -> None:
        srv = WebUIServer(config)
        srv.stop()  # no error when no server running
        srv.stop()  # still no error


# ---------------------------------------------------------------------------
# Pie / bar / gauge SVG generation
# ---------------------------------------------------------------------------


class TestSVGGeneration:
    def test_pie_svg_contains_svg_tag(self, server: WebUIServer) -> None:
        vd = {"SAFE": 3, "VULNERABLE": 2}
        svg = server._build_pie_svg(vd)
        assert "<svg" in svg
        assert "</svg>" in svg

    def test_pie_svg_empty(self, server: WebUIServer) -> None:
        svg = server._build_pie_svg({})
        assert "No data" in svg

    def test_pie_svg_single_verdict(self, server: WebUIServer) -> None:
        svg = server._build_pie_svg({"SAFE": 5})
        assert "<circle" in svg  # full circle for 100%

    def test_bar_svg_contains_svg(self, server: WebUIServer) -> None:
        cats = {"ASI01": {"total": 5, "vulnerable": 2, "safe": 3}}
        svg = server._build_bar_svg(cats)
        assert "<svg" in svg
        assert "ASI01" in svg

    def test_bar_svg_empty(self, server: WebUIServer) -> None:
        svg = server._build_bar_svg({})
        assert "No data" in svg

    def test_gauge_svg(self, server: WebUIServer) -> None:
        svg = server._build_gauge_svg(50.0, "#ff9800")
        assert "<svg" in svg
        assert "50.0" in svg
        assert "Risk Score" in svg
