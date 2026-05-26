"""Tests for drift detection module."""

from __future__ import annotations

from aastf.drift import DriftDetector, DriftItem, DriftReport
from aastf.models.result import ScanReport, TestResult, Verdict
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace


def _trace() -> AgentTrace:
    """Minimal trace for test results."""
    return AgentTrace(scenario_id="TEST-001", adapter="test", raw_output="test")


def _result(
    scenario_id: str,
    verdict: Verdict,
    category: ASICategory = ASICategory.ASI01,
    severity: Severity = Severity.HIGH,
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name=f"Test {scenario_id}",
        category=category,
        severity=severity,
        verdict=verdict,
        trace=_trace(),
    )


def _report(
    results: list[TestResult] | None = None,
    overall_risk_score: float = 0.0,
    asi_summary: dict | None = None,
) -> ScanReport:
    results = results or []
    vuln_count = sum(1 for r in results if r.verdict == Verdict.VULNERABLE)
    safe_count = sum(1 for r in results if r.verdict == Verdict.SAFE)
    return ScanReport(
        aastf_version="0.7.0",
        adapter="test",
        total_scenarios=len(results),
        vulnerable=vuln_count,
        safe=safe_count,
        overall_risk_score=overall_risk_score,
        results=results,
        asi_summary=asi_summary or {},
    )


class TestDriftDetectorNoDrift:
    """Identical reports should produce no drift."""

    def test_identical_reports(self) -> None:
        results = [
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-002", Verdict.SAFE),
        ]
        baseline = _report(results, overall_risk_score=10.0)
        current = _report(results, overall_risk_score=10.0)

        detector = DriftDetector(baseline, current)
        report = detector.detect()

        assert report.overall_drift == "stable"
        assert report.new_vulnerabilities == []
        assert report.severity_upgrades == []
        assert report.score_regressions == []
        assert report.resolved == []
        assert not detector.has_regressions()

    def test_empty_reports(self) -> None:
        baseline = _report()
        current = _report()

        report = DriftDetector(baseline, current).detect()
        assert report.overall_drift == "stable"


class TestDriftDetectorNewVulnerability:
    """Detect when a previously safe scenario becomes vulnerable."""

    def test_safe_to_vulnerable(self) -> None:
        baseline = _report([_result("ASI01-001", Verdict.SAFE)])
        current = _report(
            [_result("ASI01-001", Verdict.VULNERABLE)],
            overall_risk_score=20.0,
        )

        report = DriftDetector(baseline, current).detect()

        assert len(report.new_vulnerabilities) == 1
        item = report.new_vulnerabilities[0]
        assert item.scenario_id == "ASI01-001"
        assert item.previous_verdict == "SAFE"
        assert item.current_verdict == "VULNERABLE"
        assert report.overall_drift == "regressed"

    def test_inconclusive_to_vulnerable(self) -> None:
        baseline = _report([_result("ASI02-001", Verdict.INCONCLUSIVE)])
        current = _report(
            [_result("ASI02-001", Verdict.VULNERABLE)],
            overall_risk_score=15.0,
        )

        report = DriftDetector(baseline, current).detect()

        assert len(report.new_vulnerabilities) == 1
        assert report.overall_drift == "regressed"

    def test_new_scenario_vulnerable(self) -> None:
        """A scenario that only exists in current and is vulnerable."""
        baseline = _report([])
        current = _report(
            [_result("ASI03-001", Verdict.VULNERABLE)],
            overall_risk_score=10.0,
        )

        report = DriftDetector(baseline, current).detect()
        assert len(report.new_vulnerabilities) == 1
        assert report.new_vulnerabilities[0].previous_verdict == "N/A"


class TestDriftDetectorSeverityUpgrade:
    """Detect when a vulnerability's severity increases."""

    def test_severity_upgrade(self) -> None:
        baseline = _report([
            _result("ASI01-001", Verdict.VULNERABLE, severity=Severity.LOW),
        ])
        current = _report([
            _result("ASI01-001", Verdict.VULNERABLE, severity=Severity.CRITICAL),
        ])

        report = DriftDetector(baseline, current).detect()

        assert len(report.severity_upgrades) == 1
        item = report.severity_upgrades[0]
        assert item.scenario_id == "ASI01-001"
        assert item.previous_severity == "LOW"
        assert item.current_severity == "CRITICAL"
        assert report.overall_drift == "regressed"

    def test_no_upgrade_when_severity_decreases(self) -> None:
        baseline = _report([
            _result("ASI01-001", Verdict.VULNERABLE, severity=Severity.HIGH),
        ])
        current = _report([
            _result("ASI01-001", Verdict.VULNERABLE, severity=Severity.LOW),
        ])

        report = DriftDetector(baseline, current).detect()
        assert report.severity_upgrades == []


class TestDriftDetectorScoreRegression:
    """Detect when risk scores go up."""

    def test_overall_score_regression(self) -> None:
        baseline = _report(overall_risk_score=20.0)
        current = _report(overall_risk_score=45.0)

        report = DriftDetector(baseline, current).detect()

        assert len(report.score_regressions) == 1
        assert report.score_regressions[0].scenario_id == "overall"
        assert "25.0" in report.score_regressions[0].description
        assert report.overall_drift == "regressed"

    def test_category_score_regression(self) -> None:
        baseline = _report(
            asi_summary={"ASI01": {"vulnerable": 1, "safe": 4}},
        )
        current = _report(
            asi_summary={"ASI01": {"vulnerable": 3, "safe": 2}},
        )

        report = DriftDetector(baseline, current).detect()

        cat_regressions = [r for r in report.score_regressions if r.scenario_id == "ASI01"]
        assert len(cat_regressions) == 1
        assert "1" in cat_regressions[0].previous_verdict
        assert "3" in cat_regressions[0].current_verdict

    def test_no_regression_when_score_improves(self) -> None:
        baseline = _report(overall_risk_score=50.0)
        current = _report(overall_risk_score=30.0)

        report = DriftDetector(baseline, current).detect()
        assert report.score_regressions == []


class TestDriftDetectorResolved:
    """Detect when vulnerabilities are fixed."""

    def test_vulnerable_to_safe(self) -> None:
        baseline = _report([_result("ASI01-001", Verdict.VULNERABLE)])
        current = _report([_result("ASI01-001", Verdict.SAFE)])

        report = DriftDetector(baseline, current).detect()

        assert len(report.resolved) == 1
        assert report.resolved[0].scenario_id == "ASI01-001"
        assert report.overall_drift == "improved"

    def test_tool_poisoning_to_safe(self) -> None:
        baseline = _report([_result("ASI04-001", Verdict.TOOL_POISONING)])
        current = _report([_result("ASI04-001", Verdict.SAFE)])

        report = DriftDetector(baseline, current).detect()

        assert len(report.resolved) == 1
        assert report.overall_drift == "improved"


class TestDriftDetectorMixed:
    """Mixed changes — some improvements, some regressions."""

    def test_mixed_changes(self) -> None:
        baseline = _report(
            [
                _result("ASI01-001", Verdict.VULNERABLE, severity=Severity.HIGH),
                _result("ASI01-002", Verdict.SAFE),
                _result("ASI02-001", Verdict.VULNERABLE, severity=Severity.LOW),
            ],
            overall_risk_score=30.0,
        )
        current = _report(
            [
                _result("ASI01-001", Verdict.SAFE),  # resolved
                _result("ASI01-002", Verdict.VULNERABLE),  # new vuln
                _result("ASI02-001", Verdict.VULNERABLE, severity=Severity.CRITICAL),  # severity up
            ],
            overall_risk_score=35.0,
        )

        detector = DriftDetector(baseline, current)
        report = detector.detect()

        # resolved: ASI01-001
        assert len(report.resolved) == 1
        assert report.resolved[0].scenario_id == "ASI01-001"

        # new vuln: ASI01-002
        assert len(report.new_vulnerabilities) == 1
        assert report.new_vulnerabilities[0].scenario_id == "ASI01-002"

        # severity upgrade: ASI02-001
        assert len(report.severity_upgrades) == 1
        assert report.severity_upgrades[0].scenario_id == "ASI02-001"

        # score regression: overall
        overall_regs = [r for r in report.score_regressions if r.scenario_id == "overall"]
        assert len(overall_regs) == 1

        # Mixed = regressed (regressions take priority)
        assert report.overall_drift == "regressed"
        assert detector.has_regressions()

    def test_only_improvements(self) -> None:
        baseline = _report(
            [
                _result("ASI01-001", Verdict.VULNERABLE),
                _result("ASI01-002", Verdict.VULNERABLE),
            ],
            overall_risk_score=50.0,
        )
        current = _report(
            [
                _result("ASI01-001", Verdict.SAFE),
                _result("ASI01-002", Verdict.SAFE),
            ],
            overall_risk_score=10.0,
        )

        report = DriftDetector(baseline, current).detect()
        assert len(report.resolved) == 2
        assert report.new_vulnerabilities == []
        assert report.overall_drift == "improved"


class TestDriftReport:
    """Test DriftReport model methods."""

    def test_to_console_no_drift(self) -> None:
        report = DriftReport()
        text = report.to_console()
        assert "STABLE" in text
        assert "No drift detected" in text

    def test_to_console_with_items(self) -> None:
        report = DriftReport(
            new_vulnerabilities=[
                DriftItem(
                    scenario_id="ASI01-001",
                    category="ASI01",
                    previous_verdict="SAFE",
                    current_verdict="VULNERABLE",
                    description="went bad",
                )
            ],
            overall_drift="regressed",
        )
        text = report.to_console()
        assert "REGRESSED" in text
        assert "ASI01-001" in text

    def test_json_roundtrip(self) -> None:
        report = DriftReport(
            new_vulnerabilities=[
                DriftItem(
                    scenario_id="ASI01-001",
                    category="ASI01",
                    previous_verdict="SAFE",
                    current_verdict="VULNERABLE",
                    description="test",
                )
            ],
            overall_drift="regressed",
        )
        json_str = report.model_dump_json()
        loaded = DriftReport.model_validate_json(json_str)
        assert loaded.overall_drift == "regressed"
        assert len(loaded.new_vulnerabilities) == 1
