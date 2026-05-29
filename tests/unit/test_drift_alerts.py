"""Tests for baseline-drift alert module."""

from __future__ import annotations

from pathlib import Path

from aastf.drift_alerts import (
    BaselineDriftDetector,
    BaselineStore,
    DriftAlert,
    DriftAlertPolicy,
    _drift_severity,
    _extract_model_version,
    _verdict_is_vulnerable,
)
from aastf.models.result import ScanReport, TestResult, Verdict
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace

# ── Helpers ──────────────────────────────────────────────────────────


def _trace() -> AgentTrace:
    return AgentTrace(scenario_id="TEST-001", adapter="test", raw_output="ok")


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
    adapter: str = "test",
    aastf_version: str = "0.9.0",
) -> ScanReport:
    results = results or []
    vuln = sum(1 for r in results if r.verdict == Verdict.VULNERABLE)
    safe = sum(1 for r in results if r.verdict == Verdict.SAFE)
    return ScanReport(
        aastf_version=aastf_version,
        adapter=adapter,
        total_scenarios=len(results),
        vulnerable=vuln,
        safe=safe,
        overall_risk_score=overall_risk_score,
        results=results,
    )


# ═══════════════════════════════════════════════════════════════════════
# BaselineStore
# ═══════════════════════════════════════════════════════════════════════


class TestBaselineStore:
    """BaselineStore save / load / list / delete."""

    def test_save_and_load(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        report = _report([_result("ASI01-001", Verdict.SAFE)])
        store.save_baseline(report, "v1")
        loaded = store.load_baseline("v1")
        assert loaded is not None
        assert loaded.run_id == report.run_id

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        assert store.load_baseline("nonexistent") is None

    def test_list_baselines_empty(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        assert store.list_baselines() == []

    def test_list_baselines_sorted(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        report = _report()
        store.save_baseline(report, "beta")
        store.save_baseline(report, "alpha")
        store.save_baseline(report, "gamma")
        assert store.list_baselines() == ["alpha", "beta", "gamma"]

    def test_delete_baseline(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        store.save_baseline(_report(), "v1")
        assert store.delete_baseline("v1") is True
        assert store.load_baseline("v1") is None

    def test_delete_nonexistent(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        assert store.delete_baseline("nope") is False

    def test_overwrite_baseline(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        r1 = _report([_result("ASI01-001", Verdict.SAFE)])
        r2 = _report([_result("ASI01-001", Verdict.VULNERABLE)])
        store.save_baseline(r1, "latest")
        store.save_baseline(r2, "latest")
        loaded = store.load_baseline("latest")
        assert loaded is not None
        assert loaded.vulnerable == 1

    def test_save_returns_path(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        path = store.save_baseline(_report(), "v1")
        assert path.exists()
        assert path.suffix == ".json"

    def test_label_with_slashes(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "baselines")
        store.save_baseline(_report(), "feat/branch")
        assert "feat_branch" in store.list_baselines()

    def test_creates_directory(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path / "deep" / "nested" / "dir")
        store.save_baseline(_report(), "v1")
        assert store.load_baseline("v1") is not None


# ═══════════════════════════════════════════════════════════════════════
# DriftAlert model
# ═══════════════════════════════════════════════════════════════════════


class TestDriftAlert:

    def test_fields(self) -> None:
        a = DriftAlert(
            scenario_id="ASI01-001",
            old_verdict="SAFE",
            new_verdict="VULNERABLE",
            severity="critical",
        )
        assert a.scenario_id == "ASI01-001"
        assert a.model_version == ""
        assert a.timestamp is not None

    def test_with_model_version(self) -> None:
        a = DriftAlert(
            scenario_id="ASI01-001",
            old_verdict="SAFE",
            new_verdict="VULNERABLE",
            severity="critical",
            model_version="test@0.9.0",
        )
        assert a.model_version == "test@0.9.0"


# ═══════════════════════════════════════════════════════════════════════
# BaselineDriftDetector — compare
# ═══════════════════════════════════════════════════════════════════════


class TestBaselineDriftDetectorCompare:

    def test_no_drift_identical(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        results = [_result("ASI01-001", Verdict.SAFE)]
        store.save_baseline(_report(results), "base")
        detector = BaselineDriftDetector(store)
        alerts = detector.compare(_report(results), "base")
        assert alerts == []

    def test_regression_safe_to_vulnerable(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report([_result("ASI01-001", Verdict.SAFE)]), "base"
        )
        current = _report([_result("ASI01-001", Verdict.VULNERABLE)])
        detector = BaselineDriftDetector(store)
        alerts = detector.compare(current, "base")
        assert len(alerts) == 1
        assert alerts[0].old_verdict == "SAFE"
        assert alerts[0].new_verdict == "VULNERABLE"
        assert alerts[0].severity == "critical"

    def test_improvement_vulnerable_to_safe(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report([_result("ASI01-001", Verdict.VULNERABLE)]), "base"
        )
        current = _report([_result("ASI01-001", Verdict.SAFE)])
        alerts = BaselineDriftDetector(store).compare(current, "base")
        assert len(alerts) == 1
        assert alerts[0].severity == "info"

    def test_missing_baseline_returns_empty(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        alerts = BaselineDriftDetector(store).compare(_report(), "missing")
        assert alerts == []

    def test_new_scenario_ignored(self, tmp_path: Path) -> None:
        """A scenario present only in current is not a regression."""
        store = BaselineStore(tmp_path)
        store.save_baseline(_report([_result("ASI01-001", Verdict.SAFE)]), "base")
        current = _report([
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-002", Verdict.VULNERABLE),
        ])
        alerts = BaselineDriftDetector(store).compare(current, "base")
        assert alerts == []

    def test_removed_scenario_ignored(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report([
                _result("ASI01-001", Verdict.SAFE),
                _result("ASI01-002", Verdict.SAFE),
            ]),
            "base",
        )
        current = _report([_result("ASI01-001", Verdict.SAFE)])
        alerts = BaselineDriftDetector(store).compare(current, "base")
        assert alerts == []

    def test_multiple_regressions(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report([
                _result("ASI01-001", Verdict.SAFE),
                _result("ASI01-002", Verdict.SAFE),
                _result("ASI01-003", Verdict.SAFE),
            ]),
            "base",
        )
        current = _report([
            _result("ASI01-001", Verdict.VULNERABLE),
            _result("ASI01-002", Verdict.TOOL_POISONING),
            _result("ASI01-003", Verdict.SAFE),
        ])
        alerts = BaselineDriftDetector(store).compare(current, "base")
        assert len(alerts) == 2

    def test_inconclusive_to_safe(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report([_result("ASI01-001", Verdict.INCONCLUSIVE)]), "base"
        )
        current = _report([_result("ASI01-001", Verdict.SAFE)])
        alerts = BaselineDriftDetector(store).compare(current, "base")
        assert len(alerts) == 1
        assert alerts[0].severity == "medium"

    def test_empty_reports(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(_report(), "base")
        alerts = BaselineDriftDetector(store).compare(_report(), "base")
        assert alerts == []

    def test_alert_contains_model_version(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report([_result("ASI01-001", Verdict.SAFE)]), "base"
        )
        current = _report(
            [_result("ASI01-001", Verdict.VULNERABLE)],
            adapter="openai",
            aastf_version="0.10.0",
        )
        alerts = BaselineDriftDetector(store).compare(current, "base")
        assert alerts[0].model_version == "openai@0.10.0"


# ═══════════════════════════════════════════════════════════════════════
# Model version change detection
# ═══════════════════════════════════════════════════════════════════════


class TestModelChangeDetection:

    def test_same_version(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        r = _report(adapter="test", aastf_version="0.9.0")
        store.save_baseline(r, "base")
        detector = BaselineDriftDetector(store)
        assert detector.detect_model_change(r, "base") is False

    def test_different_version(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report(adapter="test", aastf_version="0.9.0"), "base"
        )
        current = _report(adapter="test", aastf_version="0.10.0")
        assert BaselineDriftDetector(store).detect_model_change(current, "base") is True

    def test_different_adapter(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report(adapter="openai", aastf_version="0.9.0"), "base"
        )
        current = _report(adapter="crewai", aastf_version="0.9.0")
        assert BaselineDriftDetector(store).detect_model_change(current, "base") is True

    def test_missing_baseline(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        assert BaselineDriftDetector(store).detect_model_change(_report(), "x") is False

    def test_should_retest_true(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        store.save_baseline(
            _report(adapter="test", aastf_version="0.9.0"), "base"
        )
        current = _report(adapter="test", aastf_version="0.10.0")
        assert BaselineDriftDetector(store).should_retest(current, "base") is True

    def test_should_retest_false(self, tmp_path: Path) -> None:
        store = BaselineStore(tmp_path)
        r = _report(adapter="test", aastf_version="0.9.0")
        store.save_baseline(r, "base")
        assert BaselineDriftDetector(store).should_retest(r, "base") is False


# ═══════════════════════════════════════════════════════════════════════
# Regression summary
# ═══════════════════════════════════════════════════════════════════════


class TestRegressionSummary:

    def test_empty_alerts(self, tmp_path: Path) -> None:
        detector = BaselineDriftDetector(BaselineStore(tmp_path))
        assert detector.regression_summary([]) == "No regressions detected."

    def test_single_regression(self, tmp_path: Path) -> None:
        detector = BaselineDriftDetector(BaselineStore(tmp_path))
        alert = DriftAlert(
            scenario_id="ASI01-001",
            old_verdict="SAFE",
            new_verdict="VULNERABLE",
            severity="critical",
        )
        summary = detector.regression_summary([alert])
        assert "REGRESSIONS (1)" in summary
        assert "ASI01-001" in summary
        assert "SAFE -> VULNERABLE" in summary

    def test_improvement_in_summary(self, tmp_path: Path) -> None:
        detector = BaselineDriftDetector(BaselineStore(tmp_path))
        alert = DriftAlert(
            scenario_id="ASI01-001",
            old_verdict="VULNERABLE",
            new_verdict="SAFE",
            severity="info",
        )
        summary = detector.regression_summary([alert])
        assert "IMPROVEMENTS (1)" in summary
        assert "RESOLVED" in summary

    def test_mixed_summary(self, tmp_path: Path) -> None:
        detector = BaselineDriftDetector(BaselineStore(tmp_path))
        alerts = [
            DriftAlert(
                scenario_id="ASI01-001",
                old_verdict="SAFE",
                new_verdict="VULNERABLE",
                severity="critical",
            ),
            DriftAlert(
                scenario_id="ASI01-002",
                old_verdict="VULNERABLE",
                new_verdict="SAFE",
                severity="info",
            ),
            DriftAlert(
                scenario_id="ASI01-003",
                old_verdict="INCONCLUSIVE",
                new_verdict="SAFE",
                severity="medium",
            ),
        ]
        summary = detector.regression_summary(alerts)
        assert "3 change(s) detected" in summary
        assert "REGRESSIONS" in summary
        assert "IMPROVEMENTS" in summary
        assert "OTHER CHANGES" in summary


# ═══════════════════════════════════════════════════════════════════════
# DriftAlertPolicy
# ═══════════════════════════════════════════════════════════════════════


class TestDriftAlertPolicy:

    def _alerts(self) -> list[DriftAlert]:
        return [
            DriftAlert(
                scenario_id="ASI01-001",
                old_verdict="SAFE",
                new_verdict="VULNERABLE",
                severity="critical",
            ),
            DriftAlert(
                scenario_id="ASI01-002",
                old_verdict="INCONCLUSIVE",
                new_verdict="SAFE",
                severity="medium",
            ),
            DriftAlert(
                scenario_id="ASI01-003",
                old_verdict="VULNERABLE",
                new_verdict="SAFE",
                severity="info",
            ),
        ]

    def test_default_policy_filters_inconclusive(self) -> None:
        policy = DriftAlertPolicy()
        filtered = policy.filter_alerts(self._alerts())
        # Should keep critical (ASI01-001), drop inconclusive (ASI01-002), drop info (ASI01-003)
        assert len(filtered) == 1
        assert filtered[0].scenario_id == "ASI01-001"

    def test_policy_include_inconclusive(self) -> None:
        policy = DriftAlertPolicy(ignore_inconclusive=False)
        filtered = policy.filter_alerts(self._alerts())
        # critical + medium pass threshold, info does not
        assert len(filtered) == 2

    def test_policy_high_threshold(self) -> None:
        policy = DriftAlertPolicy(severity_threshold="high")
        filtered = policy.filter_alerts(self._alerts())
        # Only critical passes (high=3, critical=4)
        assert len(filtered) == 1

    def test_policy_low_threshold(self) -> None:
        policy = DriftAlertPolicy(severity_threshold="low", ignore_inconclusive=False)
        filtered = policy.filter_alerts(self._alerts())
        # low=1, all medium+ pass; info=0 does not
        assert len(filtered) == 2

    def test_should_fail_true(self) -> None:
        policy = DriftAlertPolicy(fail_on_regression=True)
        assert policy.should_fail(self._alerts()) is True

    def test_should_fail_false_when_disabled(self) -> None:
        policy = DriftAlertPolicy(fail_on_regression=False)
        assert policy.should_fail(self._alerts()) is False

    def test_should_fail_false_no_actionable(self) -> None:
        policy = DriftAlertPolicy(severity_threshold="critical")
        # Only info-level alerts
        alerts = [
            DriftAlert(
                scenario_id="ASI01-001",
                old_verdict="VULNERABLE",
                new_verdict="SAFE",
                severity="info",
            ),
        ]
        assert policy.should_fail(alerts) is False

    def test_notify_channels(self) -> None:
        policy = DriftAlertPolicy(notify_channels=["slack", "pagerduty"])
        assert policy.notify_channels == ["slack", "pagerduty"]

    def test_default_values(self) -> None:
        policy = DriftAlertPolicy()
        assert policy.fail_on_regression is True
        assert policy.ignore_inconclusive is True
        assert policy.severity_threshold == "medium"
        assert policy.notify_channels == []


# ═══════════════════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════════════════


class TestHelpers:

    def test_verdict_is_vulnerable_true(self) -> None:
        assert _verdict_is_vulnerable("VULNERABLE") is True
        assert _verdict_is_vulnerable("TOOL_POISONING") is True

    def test_verdict_is_vulnerable_false(self) -> None:
        assert _verdict_is_vulnerable("SAFE") is False
        assert _verdict_is_vulnerable("INCONCLUSIVE") is False

    def test_drift_severity_regression(self) -> None:
        assert _drift_severity("SAFE", "VULNERABLE") == "critical"

    def test_drift_severity_improvement(self) -> None:
        assert _drift_severity("VULNERABLE", "SAFE") == "info"

    def test_drift_severity_same(self) -> None:
        assert _drift_severity("SAFE", "SAFE") == "none"

    def test_drift_severity_other(self) -> None:
        assert _drift_severity("INCONCLUSIVE", "SAFE") == "medium"

    def test_extract_model_version(self) -> None:
        r = _report(adapter="openai", aastf_version="0.10.0")
        assert _extract_model_version(r) == "openai@0.10.0"
