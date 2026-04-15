"""Unit tests for HTMLReporter — Jinja2 compliance report generator."""

from __future__ import annotations

from pathlib import Path

from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.reporting.html_reporter import HTMLReporter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(
    *,
    adapter: str = "langgraph",
    total_scenarios: int = 5,
    vulnerable: int = 1,
    safe: int = 4,
    risk_score: float = 35.0,
    eu_ai_act: str = "at_risk",
    findings: list | None = None,
) -> ScanReport:
    return ScanReport(
        aastf_version="0.9.0",
        adapter=adapter,
        total_scenarios=total_scenarios,
        vulnerable=vulnerable,
        safe=safe,
        overall_risk_score=risk_score,
        eu_ai_act_readiness=eu_ai_act,  # type: ignore[arg-type]
        findings=findings or [],
    )


def _make_finding(
    scenario_id: str = "ASI01-001",
    severity: Severity = Severity.HIGH,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name="Prompt Injection via User Message",
        category=ASICategory.ASI01,
        severity=severity,
        verdict=Verdict.VULNERABLE,
        triggered_by="tool_called: exfiltrate_data",
        description="Agent was hijacked by adversarial prompt.",
        remediation="Apply strict input sanitization and output filtering.",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestHTMLReporterGenerate:
    def test_generates_non_empty_html(self) -> None:
        reporter = HTMLReporter()
        report = _make_report()
        html = reporter.generate(report)
        assert isinstance(html, str)
        assert len(html) > 500  # substantive output

    def test_html_contains_report_adapter(self) -> None:
        reporter = HTMLReporter()
        report = _make_report(adapter="my-test-adapter")
        html = reporter.generate(report)
        assert "my-test-adapter" in html

    def test_html_contains_vulnerability_count(self) -> None:
        reporter = HTMLReporter()
        report = _make_report(vulnerable=7)
        html = reporter.generate(report)
        assert "7" in html

    def test_html_contains_risk_score(self) -> None:
        reporter = HTMLReporter()
        report = _make_report(risk_score=42.0)
        html = reporter.generate(report)
        assert "42" in html

    def test_html_contains_eu_ai_act_readiness(self) -> None:
        reporter = HTMLReporter()
        report = _make_report(eu_ai_act="non_compliant")
        html = reporter.generate(report)
        # Template uppercases and replaces _ with space
        assert "NON COMPLIANT" in html

    def test_html_contains_compliant_readiness(self) -> None:
        reporter = HTMLReporter()
        report = _make_report(eu_ai_act="compliant")
        html = reporter.generate(report)
        assert "COMPLIANT" in html

    def test_html_contains_finding_details(self) -> None:
        reporter = HTMLReporter()
        finding = _make_finding("ASI01-001", Severity.CRITICAL)
        report = _make_report(findings=[finding], vulnerable=1)
        html = reporter.generate(report)
        assert "ASI01-001" in html
        assert "CRITICAL" in html
        assert "Prompt Injection via User Message" in html

    def test_html_no_vulnerabilities_message(self) -> None:
        reporter = HTMLReporter()
        report = _make_report(vulnerable=0, findings=[])
        html = reporter.generate(report)
        assert "No vulnerabilities detected" in html

    def test_html_contains_aastf_version(self) -> None:
        reporter = HTMLReporter()
        report = _make_report()
        html = reporter.generate(report)
        assert "0.9.0" in html

    def test_html_is_valid_doctype(self) -> None:
        reporter = HTMLReporter()
        report = _make_report()
        html = reporter.generate(report)
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_html_escapes_special_chars(self) -> None:
        """Jinja2 autoescape must escape <, >, & in adapter name."""
        reporter = HTMLReporter()
        # adapter name with HTML-special characters
        report = _make_report(adapter="<script>alert('xss')</script>")
        html = reporter.generate(report)
        # The raw script tag must NOT appear verbatim
        assert "<script>" not in html
        # The escaped form should be present
        assert "&lt;script&gt;" in html


class TestHTMLReporterWrite:
    def test_write_creates_file(self, tmp_path: Path) -> None:
        reporter = HTMLReporter()
        report = _make_report()
        out = tmp_path / "report.html"
        returned = reporter.write(report, out)
        assert out.exists()
        assert returned == out

    def test_write_file_content_matches_generate(self, tmp_path: Path) -> None:
        reporter = HTMLReporter()
        report = _make_report(adapter="test-write-adapter")
        out = tmp_path / "report.html"
        reporter.write(report, out)
        content = out.read_text(encoding="utf-8")
        assert "test-write-adapter" in content

    def test_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        reporter = HTMLReporter()
        report = _make_report()
        out = tmp_path / "nested" / "deep" / "report.html"
        reporter.write(report, out)
        assert out.exists()

    def test_write_utf8_encoding(self, tmp_path: Path) -> None:
        reporter = HTMLReporter()
        report = _make_report(adapter="adaptör-ünïcode")
        out = tmp_path / "report.html"
        reporter.write(report, out)
        content = out.read_text(encoding="utf-8")
        assert "adaptör-ünïcode" in content
