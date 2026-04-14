"""Unit tests for the Runner orchestration logic."""

from __future__ import annotations

import pytest

from aastf.models.config import FrameworkConfig
from aastf.models.result import ScanReport, Verdict
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
