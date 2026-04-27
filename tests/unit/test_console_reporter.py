"""Unit tests for ConsoleReporter — Rich terminal output."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from aastf.models.result import ScanReport, TestResult, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace
from aastf.reporting.console_reporter import ConsoleReporter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _console() -> tuple[ConsoleReporter, StringIO]:
    """Return a ConsoleReporter wired to a StringIO buffer."""
    buf = StringIO()
    rich_console = Console(file=buf, highlight=False, markup=False)
    return ConsoleReporter(rich_console), buf


def _make_result(
    verdict: Verdict,
    scenario_id: str = "ASI01-001",
    severity: Severity = Severity.HIGH,
    finding: VulnerabilityFinding | None = None,
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name="Test Scenario",
        category=ASICategory.ASI01,
        severity=severity,
        verdict=verdict,
        finding=finding,
        trace=AgentTrace(scenario_id=scenario_id, adapter="test"),
        execution_time_ms=42.0,
    )


def _make_vuln_finding(scenario_id: str = "ASI01-001") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name="Test Scenario",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        verdict=Verdict.VULNERABLE,
        triggered_by="tool_called: exfiltrate",
        description="desc",
        remediation="fix this",
    )


def _make_re_finding(scenario_id: str = "ASI05-001") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name="RCE Echo",
        category=ASICategory.ASI05,
        severity=Severity.HIGH,
        verdict=Verdict.REFUSAL_ECHO,
        triggered_by="rce_pattern_in_output",
        description="desc",
        remediation="sanitize output",
    )


def _make_report(
    results: list[TestResult] | None = None,
    findings: list[VulnerabilityFinding] | None = None,
    vulnerable: int = 0,
    safe: int = 0,
    refusal_echo_count: int = 0,
    risk_score: float = 0.0,
    eu_ai_act: str = "compliant",
) -> ScanReport:
    return ScanReport(
        aastf_version="0.2.1",
        adapter="test",
        results=results or [],
        findings=findings or [],
        total_scenarios=max(1, (results and len(results)) or 1),
        vulnerable=vulnerable,
        safe=safe,
        refusal_echo_count=refusal_echo_count,
        overall_risk_score=risk_score,
        eu_ai_act_readiness=eu_ai_act,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConsoleReporterHeader:
    def test_print_header_contains_adapter(self) -> None:
        reporter, buf = _console()
        reporter.print_header("langgraph", 15)
        out = buf.getvalue()
        assert "langgraph" in out

    def test_print_header_contains_scenario_count(self) -> None:
        reporter, buf = _console()
        reporter.print_header("test-adapter", 42)
        out = buf.getvalue()
        assert "42" in out

    def test_print_header_contains_version(self) -> None:
        reporter, buf = _console()
        reporter.print_header("test", 5)
        out = buf.getvalue()
        assert "AASTF" in out


class TestConsoleReporterResultsTable:
    def test_table_contains_scenario_id(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.SAFE)
        report = _make_report(results=[result], safe=1)
        reporter.print_report(report)
        assert "ASI01-001" in buf.getvalue()

    def test_table_contains_verdict_symbol_for_vulnerable(self) -> None:
        reporter, buf = _console()
        finding = _make_vuln_finding()
        result = _make_result(Verdict.VULNERABLE, finding=finding)
        report = _make_report(results=[result], findings=[finding], vulnerable=1)
        reporter.print_report(report)
        assert "✗" in buf.getvalue()

    def test_table_contains_verdict_symbol_for_safe(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.SAFE)
        report = _make_report(results=[result], safe=1)
        reporter.print_report(report)
        assert "✓" in buf.getvalue()

    def test_table_contains_refusal_echo_symbol(self) -> None:
        reporter, buf = _console()
        finding = _make_re_finding()
        result = _make_result(Verdict.REFUSAL_ECHO, finding=finding)
        report = _make_report(results=[result], findings=[finding], refusal_echo_count=1)
        reporter.print_report(report)
        assert "⚠" in buf.getvalue()

    def test_table_contains_execution_time(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.SAFE)
        report = _make_report(results=[result], safe=1)
        reporter.print_report(report)
        assert "42" in buf.getvalue()

    def test_inconclusive_symbol(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.INCONCLUSIVE)
        report = _make_report(results=[result])
        reporter.print_report(report)
        assert "----" in buf.getvalue()


class TestConsoleReporterSummary:
    def test_summary_shows_zero_vulnerabilities(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.SAFE)
        report = _make_report(results=[result], safe=1)
        reporter.print_report(report)
        out = buf.getvalue()
        assert "0 behavioral" in out

    def test_summary_shows_vulnerable_count(self) -> None:
        reporter, buf = _console()
        finding = _make_vuln_finding()
        result = _make_result(Verdict.VULNERABLE, finding=finding)
        report = _make_report(results=[result], findings=[finding], vulnerable=1)
        reporter.print_report(report)
        out = buf.getvalue()
        assert "1 behavioral" in out

    def test_summary_shows_refusal_echo_count(self) -> None:
        reporter, buf = _console()
        finding = _make_re_finding()
        result = _make_result(Verdict.REFUSAL_ECHO, finding=finding)
        report = _make_report(results=[result], findings=[finding], refusal_echo_count=1)
        reporter.print_report(report)
        out = buf.getvalue()
        assert "1 refusal echo" in out

    def test_summary_shows_risk_score(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.SAFE)
        report = _make_report(results=[result], safe=1, risk_score=42.5)
        reporter.print_report(report)
        out = buf.getvalue()
        assert "42.5" in out

    def test_summary_shows_eu_ai_act_readiness(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.SAFE)
        report = _make_report(results=[result], safe=1, eu_ai_act="non_compliant")
        reporter.print_report(report)
        out = buf.getvalue()
        # Rich may line-wrap "NON COMPLIANT"; check each word is present
        assert "NON" in out and "COMPLIANT" in out

    def test_summary_shows_inconclusive_when_present(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.INCONCLUSIVE)
        # ScanReport.inconclusive must be set explicitly — runner sets it, not _make_report
        report = ScanReport(
            aastf_version="0.2.1",
            adapter="test",
            results=[result],
            inconclusive=1,
            total_scenarios=1,
        )
        reporter.print_report(report)
        out = buf.getvalue()
        assert "inconclusive" in out


class TestConsoleReporterFindings:
    def test_no_findings_message_when_clean(self) -> None:
        reporter, buf = _console()
        result = _make_result(Verdict.SAFE)
        report = _make_report(results=[result], safe=1)
        reporter.print_report(report)
        assert "No vulnerabilities" in buf.getvalue()

    def test_behavioral_vulnerabilities_section(self) -> None:
        reporter, buf = _console()
        finding = _make_vuln_finding()
        result = _make_result(Verdict.VULNERABLE, finding=finding)
        report = _make_report(results=[result], findings=[finding], vulnerable=1)
        reporter.print_report(report)
        out = buf.getvalue()
        assert "Behavioral Vulnerabilities" in out
        assert "ASI01-001" in out

    def test_output_sanitization_section_for_refusal_echo(self) -> None:
        reporter, buf = _console()
        finding = _make_re_finding()
        result = _make_result(Verdict.REFUSAL_ECHO, finding=finding)
        report = _make_report(results=[result], findings=[finding], refusal_echo_count=1)
        reporter.print_report(report)
        out = buf.getvalue()
        assert "Output Sanitization" in out
        assert "ASI05-001" in out

    def test_remediation_truncated_in_output(self) -> None:
        reporter, buf = _console()
        long_remediation = "A" * 200
        finding = VulnerabilityFinding(
            scenario_id="ASI01-001",
            scenario_name="Test",
            category=ASICategory.ASI01,
            severity=Severity.HIGH,
            verdict=Verdict.VULNERABLE,
            triggered_by="tool_called",
            description="desc",
            remediation=long_remediation,
        )
        result = _make_result(Verdict.VULNERABLE, finding=finding)
        report = _make_report(results=[result], findings=[finding], vulnerable=1)
        reporter.print_report(report)
        # Should not raise and should contain truncated remediation
        out = buf.getvalue()
        assert "AAA" in out

    def test_both_sections_with_mixed_findings(self) -> None:
        reporter, buf = _console()
        vuln_finding = _make_vuln_finding("ASI01-001")
        re_finding = _make_re_finding("ASI05-001")
        results = [
            _make_result(Verdict.VULNERABLE, "ASI01-001", finding=vuln_finding),
            _make_result(Verdict.REFUSAL_ECHO, "ASI05-001", finding=re_finding),
        ]
        report = _make_report(
            results=results,
            findings=[vuln_finding, re_finding],
            vulnerable=1,
            refusal_echo_count=1,
        )
        reporter.print_report(report)
        out = buf.getvalue()
        assert "Behavioral Vulnerabilities" in out
        assert "Output Sanitization" in out
