"""Unit tests for the Runner orchestration logic."""

from __future__ import annotations

import pytest

from aastf.cli.commands.run import get_blocking_findings
from aastf.models.config import FrameworkConfig
from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.runner import Runner


def _config(**kwargs) -> FrameworkConfig:
    defaults = dict(
        adapter="langgraph",
        agent_factory="tests.fixtures.mock_agent:create_agent",
    )
    defaults.update(kwargs)
    return FrameworkConfig(**defaults)


class TestRunnerAccumulateLogic:
    """Test the accumulation logic without a real harness."""

    def _make_runner(self) -> Runner:
        return Runner(_config())

    def test_accumulate_vulnerable(self):
        from aastf.models.result import TestResult, VulnerabilityFinding
        from aastf.models.trace import AgentTrace

        runner = self._make_runner()
        report = ScanReport(aastf_version="0.1.0", adapter="test")
        finding = VulnerabilityFinding(
            scenario_id="ASI02-001", scenario_name="Test",
            category=ASICategory.ASI02, severity=Severity.HIGH,
            verdict=Verdict.VULNERABLE, triggered_by="tool_called",
            description="desc", remediation="fix",
        )
        result = TestResult(
            scenario_id="ASI02-001", scenario_name="Test",
            category=ASICategory.ASI02, severity=Severity.HIGH,
            verdict=Verdict.VULNERABLE, finding=finding,
            trace=AgentTrace(scenario_id="ASI02-001", adapter="test"),
        )
        runner._accumulate(report, result)
        assert report.vulnerable == 1
        assert report.safe == 0
        assert len(report.findings) == 1

    def test_accumulate_safe(self):
        from aastf.models.result import TestResult
        from aastf.models.trace import AgentTrace

        runner = self._make_runner()
        report = ScanReport(aastf_version="0.1.0", adapter="test")
        result = TestResult(
            scenario_id="ASI01-001", scenario_name="Test",
            category=ASICategory.ASI01, severity=Severity.HIGH,
            verdict=Verdict.SAFE,
            trace=AgentTrace(scenario_id="ASI01-001", adapter="test"),
        )
        runner._accumulate(report, result)
        assert report.safe == 1
        assert report.vulnerable == 0
        assert report.findings == []

    def test_accumulate_error(self):
        from aastf.models.result import TestResult
        from aastf.models.trace import AgentTrace

        runner = self._make_runner()
        report = ScanReport(aastf_version="0.1.0", adapter="test")
        result = TestResult(
            scenario_id="ASI01-001", scenario_name="Test",
            category=ASICategory.ASI01, severity=Severity.HIGH,
            verdict=Verdict.ERROR,
            trace=AgentTrace(scenario_id="ASI01-001", adapter="test", error="timeout"),
        )
        runner._accumulate(report, result)
        assert report.errors == 1

    def test_accumulate_refusal_echo(self):
        from aastf.models.result import TestResult, VulnerabilityFinding
        from aastf.models.trace import AgentTrace

        runner = self._make_runner()
        report = ScanReport(aastf_version="0.1.0", adapter="test", total_scenarios=1)
        finding = VulnerabilityFinding(
            scenario_id="ASI05-001", scenario_name="RCE Echo",
            category=ASICategory.ASI05, severity=Severity.HIGH,
            verdict=Verdict.REFUSAL_ECHO, triggered_by="rce_pattern_in_output: 'os.system'",
            description="desc", remediation="fix",
        )
        result = TestResult(
            scenario_id="ASI05-001", scenario_name="RCE Echo",
            category=ASICategory.ASI05, severity=Severity.HIGH,
            verdict=Verdict.REFUSAL_ECHO, finding=finding,
            trace=AgentTrace(scenario_id="ASI05-001", adapter="test"),
        )
        runner._accumulate(report, result)
        assert report.refusal_echo_count == 1
        assert report.vulnerable == 0
        assert len(report.findings) == 1
        assert report.findings[0].verdict == Verdict.REFUSAL_ECHO
        assert len(report.results) == 1  # total_scenarios tracked via results

    def test_accumulate_mixed_verdicts(self):
        from aastf.models.result import TestResult, VulnerabilityFinding
        from aastf.models.trace import AgentTrace

        runner = self._make_runner()
        report = ScanReport(aastf_version="0.1.0", adapter="test")

        vuln_finding = VulnerabilityFinding(
            scenario_id="ASI02-001", scenario_name="Tool Misuse",
            category=ASICategory.ASI02, severity=Severity.HIGH,
            verdict=Verdict.VULNERABLE, triggered_by="tool_called",
            description="desc", remediation="fix",
        )
        re_finding = VulnerabilityFinding(
            scenario_id="ASI05-001", scenario_name="RCE Echo",
            category=ASICategory.ASI05, severity=Severity.HIGH,
            verdict=Verdict.REFUSAL_ECHO, triggered_by="rce_pattern_in_output",
            description="desc", remediation="fix",
        )

        for verdict, finding in [
            (Verdict.VULNERABLE, vuln_finding),
            (Verdict.REFUSAL_ECHO, re_finding),
            (Verdict.SAFE, None),
        ]:
            result = TestResult(
                scenario_id="ASI01-001", scenario_name="T",
                category=ASICategory.ASI01, severity=Severity.HIGH,
                verdict=verdict, finding=finding,
                trace=AgentTrace(scenario_id="ASI01-001", adapter="test"),
            )
            runner._accumulate(report, result)

        assert report.vulnerable == 1
        assert report.refusal_echo_count == 1
        assert report.safe == 1
        assert len(report.results) == 3
        # SAFE is excluded from findings; VULNERABLE and REFUSAL_ECHO both appear
        assert len(report.findings) == 2
        verdict_set = {f.verdict for f in report.findings}
        assert verdict_set == {Verdict.VULNERABLE, Verdict.REFUSAL_ECHO}

    def test_build_asi_summary(self):
        from aastf.models.result import TestResult
        from aastf.models.trace import AgentTrace

        runner = self._make_runner()
        report = ScanReport(aastf_version="0.1.0", adapter="test")

        for verdict in [Verdict.VULNERABLE, Verdict.SAFE, Verdict.SAFE]:
            result = TestResult(
                scenario_id="ASI01-001", scenario_name="T",
                category=ASICategory.ASI01, severity=Severity.HIGH,
                verdict=verdict,
                trace=AgentTrace(scenario_id="ASI01-001", adapter="test"),
            )
            runner._accumulate(report, result)

        summary = runner._build_asi_summary(report)
        assert "ASI01" in summary
        assert summary["ASI01"]["vulnerable"] == 1
        assert summary["ASI01"]["safe"] == 2


class TestRunnerLoadAgent:
    def test_raises_on_bad_dotted_path(self):
        runner = Runner(_config(agent_factory="no_colon_here"))
        with pytest.raises(ValueError, match="module.path:callable"):
            runner._load_agent_factory()

    def test_raises_on_missing_module(self):
        from aastf.exceptions import AdapterNotFoundError
        runner = Runner(_config(agent_factory="nonexistent.module:create_agent"))
        with pytest.raises(AdapterNotFoundError):
            runner._load_agent_factory()


class TestStrictOutputFlag:
    """Test --strict-output flag blocking-findings logic end-to-end."""

    def _re_finding(self, severity: Severity = Severity.HIGH) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            scenario_id="ASI05-001", scenario_name="RCE Echo",
            category=ASICategory.ASI05, severity=severity,
            verdict=Verdict.REFUSAL_ECHO, triggered_by="rce_pattern_in_output",
            description="desc", remediation="fix",
        )

    def _vuln_finding(self, severity: Severity = Severity.HIGH) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            scenario_id="ASI02-001", scenario_name="Tool Misuse",
            category=ASICategory.ASI02, severity=severity,
            verdict=Verdict.VULNERABLE, triggered_by="tool_called",
            description="desc", remediation="fix",
        )

    def _report(self, *findings: VulnerabilityFinding) -> ScanReport:
        return ScanReport(
            aastf_version="0.1.0", adapter="test", findings=list(findings)
        )

    def test_refusal_echo_not_blocking_without_strict_output(self):
        """Default behaviour: REFUSAL_ECHO findings do not cause exit code 1."""
        report = self._report(self._re_finding(Severity.HIGH))
        blocking = get_blocking_findings(report, Severity.HIGH, strict_output=False)
        assert blocking == []

    def test_refusal_echo_blocking_with_strict_output(self):
        """--strict-output: REFUSAL_ECHO at or above threshold causes exit code 1."""
        report = self._report(self._re_finding(Severity.HIGH))
        blocking = get_blocking_findings(report, Severity.HIGH, strict_output=True)
        assert len(blocking) == 1
        assert blocking[0].verdict == Verdict.REFUSAL_ECHO

    def test_vulnerable_always_blocking_regardless_of_strict_output(self):
        report = self._report(self._vuln_finding(Severity.HIGH))
        assert len(get_blocking_findings(report, Severity.HIGH, strict_output=False)) == 1
        assert len(get_blocking_findings(report, Severity.HIGH, strict_output=True)) == 1

    def test_refusal_echo_below_threshold_not_blocking_even_with_strict_output(self):
        report = self._report(self._re_finding(Severity.LOW))
        blocking = get_blocking_findings(report, Severity.HIGH, strict_output=True)
        assert blocking == []

    def test_no_fail_severity_never_blocks(self):
        report = self._report(self._vuln_finding(Severity.CRITICAL))
        assert get_blocking_findings(report, None, strict_output=True) == []


class TestSARIFReporter:
    def test_generates_valid_sarif_structure(self):
        from aastf.models.result import ScanReport, TestResult, Verdict, VulnerabilityFinding
        from aastf.models.trace import AgentTrace
        from aastf.reporting.sarif_reporter import SARIFReporter

        finding = VulnerabilityFinding(
            scenario_id="ASI02-001", scenario_name="RAG exfil",
            category=ASICategory.ASI02, severity=Severity.CRITICAL,
            verdict=Verdict.VULNERABLE, triggered_by="tool_called: send_email",
            description="desc", remediation="fix", cvss_score=9.5,
        )
        result = TestResult(
            scenario_id="ASI02-001", scenario_name="RAG exfil",
            category=ASICategory.ASI02, severity=Severity.CRITICAL,
            verdict=Verdict.VULNERABLE, finding=finding,
            trace=AgentTrace(scenario_id="ASI02-001", adapter="test"),
        )
        report = ScanReport(
            aastf_version="0.1.0", adapter="test",
            results=[result], findings=[finding],
            overall_risk_score=95.0,
        )

        sarif = SARIFReporter().generate(report)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "aastf"
        assert len(run["results"]) == 1
        assert run["results"][0]["ruleId"] == "ASI02-001"
        assert run["results"][0]["level"] == "error"

    def test_safe_findings_not_in_sarif(self):
        from aastf.models.result import ScanReport
        from aastf.reporting.sarif_reporter import SARIFReporter

        report = ScanReport(aastf_version="0.1.0", adapter="test")
        sarif = SARIFReporter().generate(report)
        assert sarif["runs"][0]["results"] == []

    def test_write_creates_file(self, tmp_path):
        from aastf.models.result import ScanReport
        from aastf.reporting.sarif_reporter import SARIFReporter

        report = ScanReport(aastf_version="0.1.0", adapter="test")
        out = SARIFReporter().write(report, tmp_path / "results.sarif")
        assert out.exists()
        import json
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"


class TestJSONReporter:
    def test_generates_valid_json(self):
        import json

        from aastf.models.result import ScanReport
        from aastf.reporting.json_reporter import JSONReporter

        report = ScanReport(aastf_version="0.1.0", adapter="test", total_scenarios=5)
        json_str = JSONReporter().generate(report)
        data = json.loads(json_str)
        assert data["aastf_version"] == "0.1.0"
        assert data["total_scenarios"] == 5

    def test_write_creates_file(self, tmp_path):
        from aastf.models.result import ScanReport
        from aastf.reporting.json_reporter import JSONReporter

        report = ScanReport(aastf_version="0.1.0", adapter="test")
        out = JSONReporter().write(report, tmp_path / "report.json")
        assert out.exists()
