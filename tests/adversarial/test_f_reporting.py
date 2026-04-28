"""
Category F — Reporting Integrity.

Hypotheses:
  F1.  JSON output is valid JSON and round-trips through Pydantic.
  F2.  SARIF output contains required SARIF 2.1 schema fields.
  F3.  SARIF level is 'error' for VULNERABLE HIGH/CRITICAL, 'warning' otherwise.
  F4.  SARIF level is always 'warning' for REFUSAL_ECHO (never 'error').
  F5.  HTML report starts with <!DOCTYPE html> and is non-empty.
  F6.  HTML report autoescapes XSS in adapter name (Jinja2 autoescape).
  F7.  HTML report autoescapes XSS in scenario_name via finding text.
  F8.  HTML report correctly separates VULNERABLE and REFUSAL_ECHO sections.
  F9.  Finding is traceable to its triggering criterion.
  F10. JSON and SARIF reports write to the specified path and create parents.
  F11. Scores are deterministic across multiple calls with same input.
"""

from __future__ import annotations

import json
from pathlib import Path

from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.reporting.html_reporter import HTMLReporter
from aastf.reporting.json_reporter import JSONReporter
from aastf.reporting.sarif_reporter import SARIFReporter


def _finding(
    verdict: Verdict = Verdict.VULNERABLE,
    severity: Severity = Severity.HIGH,
    scenario_id: str = "ASI01-001",
    triggered_by: str = "tool_called: send_email",
    scenario_name: str = "Test finding",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        category=ASICategory.ASI01,
        severity=severity,
        verdict=verdict,
        triggered_by=triggered_by,
        description="test",
        remediation="fix",
    )


def _report(**kwargs) -> ScanReport:
    defaults = dict(aastf_version="0.3.0", adapter="test-adapter", total_scenarios=5)
    defaults.update(kwargs)
    return ScanReport(**defaults)


# --------------------------------------------------------------------------- F1
class TestJSONReporter:
    """F1: JSON output validity."""

    def test_generates_valid_json(self):
        """Hypothesis: generate() returns valid JSON."""
        report = _report()
        j = JSONReporter().generate(report)
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_json_round_trips_through_pydantic(self):
        """Hypothesis: JSON output can be deserialized back into ScanReport."""
        f = _finding()
        report = _report(findings=[f], vulnerable=1)
        j = JSONReporter().generate(report)
        report2 = ScanReport.model_validate_json(j)
        assert report2.run_id == report.run_id
        assert len(report2.findings) == 1
        assert report2.findings[0].verdict == Verdict.VULNERABLE

    def test_json_write_creates_file(self, tmp_path: Path):
        """Hypothesis: write() creates the output file."""
        report = _report()
        out = tmp_path / "report.json"
        returned = JSONReporter().write(report, out)
        assert out.exists()
        assert returned == out

    def test_json_write_creates_parent_dirs(self, tmp_path: Path):
        """Hypothesis: write() creates parent directories."""
        out = tmp_path / "nested" / "deep" / "report.json"
        JSONReporter().write(_report(), out)
        assert out.exists()

    def test_json_contains_run_id(self):
        """Hypothesis: JSON output contains run_id for traceability."""
        report = _report()
        j = JSONReporter().generate(report)
        parsed = json.loads(j)
        assert "run_id" in parsed


# --------------------------------------------------------------------------- F2–F4
class TestSARIFReporter:
    """F2–F4: SARIF output structure and level mapping."""

    def test_sarif_has_required_fields(self):
        """F2: SARIF output has version, $schema, runs."""
        report = _report()
        sarif = SARIFReporter().generate(report)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_level_error_for_vulnerable_critical(self):
        """F3: VULNERABLE CRITICAL → level 'error'."""
        f = _finding(Verdict.VULNERABLE, Severity.CRITICAL)
        report = _report(findings=[f], vulnerable=1)
        sarif = SARIFReporter().generate(report)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["level"] == "error"

    def test_sarif_level_error_for_vulnerable_high(self):
        """F3: VULNERABLE HIGH → level 'error'."""
        f = _finding(Verdict.VULNERABLE, Severity.HIGH)
        report = _report(findings=[f], vulnerable=1)
        sarif = SARIFReporter().generate(report)
        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "error"

    def test_sarif_level_warning_for_vulnerable_medium(self):
        """F3: VULNERABLE MEDIUM → level 'warning' (not 'error')."""
        f = _finding(Verdict.VULNERABLE, Severity.MEDIUM)
        report = _report(findings=[f], vulnerable=1)
        sarif = SARIFReporter().generate(report)
        results = sarif["runs"][0]["results"]
        assert results[0]["level"] == "warning"

    def test_sarif_level_always_warning_for_refusal_echo(self):
        """F4: REFUSAL_ECHO at any severity → level 'warning' (never 'error')."""
        for sev in Severity:
            f = _finding(Verdict.REFUSAL_ECHO, sev)
            report = _report(findings=[f], refusal_echo_count=1)
            sarif = SARIFReporter().generate(report)
            results = sarif["runs"][0]["results"]
            assert len(results) == 1
            assert results[0]["level"] == "warning", (
                f"REFUSAL_ECHO at {sev} should be 'warning', got {results[0]['level']}"
            )

    def test_sarif_has_aastf_verdict_property(self):
        """Hypothesis: SARIF result properties include aastf.verdict extension."""
        f = _finding(Verdict.VULNERABLE, Severity.HIGH)
        report = _report(findings=[f], vulnerable=1)
        sarif = SARIFReporter().generate(report)
        props = sarif["runs"][0]["results"][0]["properties"]
        assert "aastf.verdict" in props
        assert props["aastf.verdict"] == "VULNERABLE"

    def test_sarif_safe_findings_excluded(self):
        """Hypothesis: SAFE findings do not appear in SARIF results."""
        # Only way to get SAFE in findings is to add it manually (shouldn't happen via runner)
        from aastf.models.result import TestResult
        from aastf.models.trace import AgentTrace
        report = _report()
        # Add a test result with SAFE verdict but no finding
        report.results.append(TestResult(
            scenario_id="ASI01-001",
            scenario_name="Safe test",
            category=ASICategory.ASI01,
            severity=Severity.HIGH,
            verdict=Verdict.SAFE,
            trace=AgentTrace(scenario_id="ASI01-001", adapter="test"),
        ))
        sarif = SARIFReporter().generate(report)
        # findings list is empty → no SARIF results
        assert sarif["runs"][0]["results"] == []

    def test_sarif_json_is_valid(self):
        """Hypothesis: generate_json() returns valid JSON string."""
        f = _finding()
        report = _report(findings=[f], vulnerable=1)
        j = SARIFReporter().generate_json(report)
        parsed = json.loads(j)
        assert parsed["version"] == "2.1.0"

    def test_sarif_write_creates_file(self, tmp_path: Path):
        """Hypothesis: write() creates SARIF output file."""
        report = _report()
        out = tmp_path / "results.sarif"
        SARIFReporter().write(report, out)
        assert out.exists()
        content = json.loads(out.read_text())
        assert content["version"] == "2.1.0"


# --------------------------------------------------------------------------- F5–F8
class TestHTMLReporter:
    """F5–F8: HTML report structure and XSS safety."""

    def test_html_starts_with_doctype(self):
        """F5: HTML starts with <!DOCTYPE html>."""
        report = _report()
        html = HTMLReporter().generate(report)
        assert html.strip().startswith("<!DOCTYPE html>")

    def test_html_is_non_empty(self):
        """F5: HTML output is substantive."""
        html = HTMLReporter().generate(_report())
        assert len(html) > 500

    def test_html_escapes_xss_in_adapter_name(self):
        """F6: XSS in adapter name is escaped by Jinja2 autoescape."""
        report = _report(adapter="<script>alert('xss')</script>")
        html = HTMLReporter().generate(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_escapes_xss_in_scenario_name(self):
        """F7: XSS in scenario_name (via finding) is escaped."""
        f = VulnerabilityFinding(
            scenario_id="ASI01-001",
            scenario_name="<img src=x onerror=alert(1)>",
            category=ASICategory.ASI01,
            severity=Severity.HIGH,
            verdict=Verdict.VULNERABLE,
            triggered_by="test",
            description="test",
            remediation="fix",
        )
        report = _report(findings=[f], vulnerable=1)
        html = HTMLReporter().generate(report)
        assert "<img src=x onerror=alert(1)>" not in html

    def test_html_escapes_xss_in_triggered_by(self):
        """F7: XSS in triggered_by field is escaped."""
        f = _finding(triggered_by='<script>alert("pwned")</script>')
        report = _report(findings=[f], vulnerable=1)
        html = HTMLReporter().generate(report)
        assert '<script>alert("pwned")</script>' not in html
        assert "&lt;script&gt;" in html

    def test_html_separates_vulnerable_and_refusal_echo(self):
        """F8: HTML report has separate sections for VULNERABLE and REFUSAL_ECHO."""
        vuln_f = _finding(Verdict.VULNERABLE, Severity.HIGH, "ASI01-001", scenario_name="Vuln Test")
        echo_f = _finding(Verdict.REFUSAL_ECHO, Severity.HIGH, "ASI02-001", scenario_name="Echo Test")
        report = _report(findings=[vuln_f, echo_f], vulnerable=1, refusal_echo_count=1)
        html = HTMLReporter().generate(report)
        assert "findings-vulnerable" in html
        assert "findings-refusal-echo" in html
        assert "Behavioral Vulnerabilities" in html
        assert "Output Sanitization" in html

    def test_html_shows_no_vulnerabilities_message(self):
        """Hypothesis: No-findings report shows the clean message."""
        report = _report(vulnerable=0, findings=[])
        html = HTMLReporter().generate(report)
        assert "No behavioral vulnerabilities detected" in html

    def test_html_write_utf8(self, tmp_path: Path):
        """Hypothesis: HTML file is written as UTF-8 and contains unicode."""
        report = _report(adapter="adaptör-ünïcode")
        out = tmp_path / "report.html"
        HTMLReporter().write(report, out)
        content = out.read_text(encoding="utf-8")
        assert "adaptör-ünïcode" in content


# --------------------------------------------------------------------------- F9
class TestFindingTraceability:
    """F9: Findings are traceable to their triggering criterion."""

    def test_finding_triggered_by_is_not_empty(self):
        """Hypothesis: Every finding has a non-empty triggered_by field."""
        from aastf.scenarios.evaluators import get_evaluator

        from .conftest import make_scenario, make_trace

        scenario = make_scenario(ASICategory.ASI01, tool_called=["send_email"])
        trace = make_trace(tools=["send_email"])
        ev = get_evaluator(ASICategory.ASI01)
        result = ev.evaluate(scenario, trace)
        assert result.triggered_by.strip() != ""

    def test_finding_evidence_contains_relevant_data(self):
        """Hypothesis: Evidence dict contains the tool that triggered the finding."""
        from aastf.scenarios.evaluators import get_evaluator

        from .conftest import make_scenario, make_trace

        scenario = make_scenario(ASICategory.ASI01, tool_called=["send_email"])
        trace = make_trace(tools=["send_email"])
        ev = get_evaluator(ASICategory.ASI01)
        result = ev.evaluate(scenario, trace)
        assert "send_email" in str(result.evidence)


# --------------------------------------------------------------------------- F11
class TestScoreDeterminism:
    """F11: Scoring is deterministic."""

    def test_score_finding_is_deterministic(self):
        """Hypothesis: score_finding() returns the same value on repeated calls."""
        from aastf.scoring import score_finding
        f = _finding(Verdict.VULNERABLE, Severity.HIGH)
        scores = [score_finding(f) for _ in range(10)]
        assert len(set(scores)) == 1

    def test_compute_risk_score_is_deterministic(self):
        """Hypothesis: compute_risk_score() returns the same value on repeated calls."""
        from aastf.scoring import compute_risk_score
        f = _finding(Verdict.VULNERABLE, Severity.HIGH)
        report = _report(findings=[f], vulnerable=1)
        scores = [compute_risk_score(report) for _ in range(10)]
        assert len(set(scores)) == 1
