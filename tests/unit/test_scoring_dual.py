"""Tests for dual utility + security scoring."""

from __future__ import annotations

from aastf.models.result import (
    ScanReport,
    TestResult,
    Verdict,
    VulnerabilityFinding,
)
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace
from aastf.scoring_dual import (
    DualScorer,
    ParetoPoint,
    UtilityResult,
    _harmonic_mean,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_trace() -> AgentTrace:
    return AgentTrace(scenario_id="test", adapter="test", invocations=[])


def _make_report(
    findings: list[VulnerabilityFinding] | None = None,
    results: list[TestResult] | None = None,
) -> ScanReport:
    findings = findings or []
    results = results or []
    return ScanReport(
        aastf_version="0.7.0",
        adapter="test",
        total_scenarios=len(results) or len(findings),
        vulnerable=sum(1 for f in findings if f.verdict == Verdict.VULNERABLE),
        safe=sum(1 for r in results if r.verdict == Verdict.SAFE),
        findings=findings,
        results=results,
    )


def _finding(
    scenario_id: str = "ASI01-001",
    category: ASICategory = ASICategory.ASI01,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.VULNERABLE,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name=f"Test {scenario_id}",
        category=category,
        severity=severity,
        verdict=verdict,
        triggered_by="test",
        description="test finding",
        remediation="fix it",
    )


def _result(
    scenario_id: str = "ASI01-001",
    category: ASICategory = ASICategory.ASI01,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.SAFE,
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name=f"Test {scenario_id}",
        category=category,
        severity=severity,
        verdict=verdict,
        trace=_empty_trace(),
    )


def _utility(
    scenario_id: str = "ASI01-001",
    task_completed: bool = True,
    quality: float = 1.0,
    latency: float = 100.0,
    tools_used: list[str] | None = None,
    expected_tools: list[str] | None = None,
) -> UtilityResult:
    return UtilityResult(
        scenario_id=scenario_id,
        task_completed=task_completed,
        completion_quality=quality,
        latency_ms=latency,
        tools_used=tools_used or [],
        expected_tools=expected_tools or [],
    )


# ---------------------------------------------------------------------------
# UtilityResult.tool_accuracy
# ---------------------------------------------------------------------------

class TestUtilityResult:
    def test_tool_accuracy_all_matched(self):
        r = _utility(tools_used=["a", "b"], expected_tools=["a", "b"])
        assert r.tool_accuracy == 1.0

    def test_tool_accuracy_none_matched(self):
        r = _utility(tools_used=["c"], expected_tools=["a", "b"])
        assert r.tool_accuracy == 0.0

    def test_tool_accuracy_partial(self):
        r = _utility(tools_used=["a", "c"], expected_tools=["a", "b"])
        assert r.tool_accuracy == 0.5

    def test_tool_accuracy_no_expected(self):
        r = _utility(tools_used=["a"], expected_tools=[])
        assert r.tool_accuracy == 1.0


# ---------------------------------------------------------------------------
# Harmonic mean helper
# ---------------------------------------------------------------------------

class TestHarmonicMean:
    def test_equal_values(self):
        assert _harmonic_mean(80.0, 80.0) == 80.0

    def test_zero_a(self):
        assert _harmonic_mean(0.0, 80.0) == 0.0

    def test_zero_b(self):
        assert _harmonic_mean(80.0, 0.0) == 0.0

    def test_asymmetric(self):
        result = _harmonic_mean(90.0, 10.0)
        assert result == 18.0  # 2*90*10 / (90+10) = 18


# ---------------------------------------------------------------------------
# Perfect utility: all tasks complete with high quality
# ---------------------------------------------------------------------------

class TestPerfectUtility:
    def test_all_safe_all_complete(self):
        """All scenarios safe + all utility tasks perfect => both scores ~100."""
        report = _make_report(
            findings=[],
            results=[
                _result("ASI01-001", verdict=Verdict.SAFE),
                _result("ASI01-002", verdict=Verdict.SAFE),
                _result("ASI01-003", verdict=Verdict.SAFE),
            ],
        )
        utilities = [
            _utility("ASI01-001", task_completed=True, quality=1.0,
                     tools_used=["t1"], expected_tools=["t1"]),
            _utility("ASI01-002", task_completed=True, quality=1.0,
                     tools_used=["t2"], expected_tools=["t2"]),
            _utility("ASI01-003", task_completed=True, quality=1.0,
                     tools_used=["t3"], expected_tools=["t3"]),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()

        assert dual.security_score == 100.0
        assert dual.utility_score == 100.0
        assert dual.combined_score == 100.0

    def test_no_utility_results_assumes_full(self):
        """No utility results => utility defaults to 100 (no degradation)."""
        report = _make_report(
            results=[_result("ASI01-001", verdict=Verdict.SAFE)],
        )
        scorer = DualScorer(report, utility_results=None)
        dual = scorer.compute()
        assert dual.utility_score == 100.0


# ---------------------------------------------------------------------------
# Zero utility: all tasks failed
# ---------------------------------------------------------------------------

class TestZeroUtility:
    def test_all_tasks_failed(self):
        """All utility tasks failed => utility score 0."""
        report = _make_report(
            results=[_result("ASI01-001", verdict=Verdict.SAFE)],
        )
        utilities = [
            _utility("ASI01-001", task_completed=False, quality=0.0,
                     tools_used=[], expected_tools=["t1", "t2"]),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()

        assert dual.utility_score == 0.0
        assert dual.combined_score == 0.0  # harmonic mean with 0 => 0


# ---------------------------------------------------------------------------
# Mixed: high security but low utility
# ---------------------------------------------------------------------------

class TestHighSecurityLowUtility:
    def test_secure_but_broken_functionality(self):
        """Agent blocks all attacks but can't complete tasks."""
        report = _make_report(
            findings=[],
            results=[
                _result("ASI01-001", verdict=Verdict.SAFE),
                _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.SAFE),
            ],
        )
        utilities = [
            _utility("ASI01-001", task_completed=False, quality=0.1,
                     tools_used=[], expected_tools=["search", "write"]),
            _utility("ASI02-001", task_completed=False, quality=0.2,
                     tools_used=["search"], expected_tools=["search", "write", "send"]),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()

        assert dual.security_score == 100.0
        assert dual.utility_score < 30.0
        # Combined pulled down by low utility
        assert dual.combined_score < 50.0


# ---------------------------------------------------------------------------
# Mixed: low security but high utility
# ---------------------------------------------------------------------------

class TestLowSecurityHighUtility:
    def test_vulnerable_but_functional(self):
        """Agent completes tasks but is vulnerable to attacks."""
        findings = [
            _finding("ASI01-001", severity=Severity.HIGH, verdict=Verdict.VULNERABLE),
            _finding("ASI02-001", category=ASICategory.ASI02,
                     severity=Severity.CRITICAL, verdict=Verdict.VULNERABLE),
        ]
        results = [
            _result("ASI01-001", verdict=Verdict.VULNERABLE),
            _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.VULNERABLE),
        ]
        report = _make_report(findings=findings, results=results)
        utilities = [
            _utility("ASI01-001", task_completed=True, quality=0.95,
                     tools_used=["search", "write"], expected_tools=["search", "write"]),
            _utility("ASI02-001", task_completed=True, quality=0.9,
                     tools_used=["run"], expected_tools=["run"]),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()

        assert dual.security_score < 20.0  # very insecure
        assert dual.utility_score > 90.0   # highly functional
        assert dual.combined_score < dual.utility_score  # pulled down by security


# ---------------------------------------------------------------------------
# Pareto frontier with 3+ configurations
# ---------------------------------------------------------------------------

class TestParetoFrontier:
    def test_frontier_three_points(self):
        """Three configs: one dominated, two on the frontier."""
        report = _make_report()
        scorer = DualScorer(report)

        points = [
            ParetoPoint(config_label="strict", security_score=95.0, utility_score=40.0),
            ParetoPoint(config_label="balanced", security_score=70.0, utility_score=80.0),
            ParetoPoint(config_label="lax", security_score=60.0, utility_score=70.0),
        ]
        result = scorer.pareto_frontier(points)

        by_label = {p.config_label: p for p in result}
        # "strict" is on frontier (best security)
        assert by_label["strict"].is_dominated is False
        # "balanced" is on frontier (best combo)
        assert by_label["balanced"].is_dominated is False
        # "lax" is dominated by "balanced" (70>=60 and 80>=70, at least one strict)
        assert by_label["lax"].is_dominated is True

    def test_frontier_no_domination(self):
        """All points on the frontier."""
        report = _make_report()
        scorer = DualScorer(report)

        points = [
            ParetoPoint(config_label="a", security_score=90.0, utility_score=30.0),
            ParetoPoint(config_label="b", security_score=50.0, utility_score=70.0),
            ParetoPoint(config_label="c", security_score=20.0, utility_score=95.0),
        ]
        result = scorer.pareto_frontier(points)
        assert all(not p.is_dominated for p in result)

    def test_frontier_all_dominated_except_one(self):
        """One point dominates all others."""
        report = _make_report()
        scorer = DualScorer(report)

        points = [
            ParetoPoint(config_label="best", security_score=90.0, utility_score=90.0),
            ParetoPoint(config_label="worse1", security_score=80.0, utility_score=80.0),
            ParetoPoint(config_label="worse2", security_score=70.0, utility_score=60.0),
        ]
        result = scorer.pareto_frontier(points)
        by_label = {p.config_label: p for p in result}
        assert by_label["best"].is_dominated is False
        assert by_label["worse1"].is_dominated is True
        assert by_label["worse2"].is_dominated is True

    def test_frontier_default_single_point(self):
        """No configs passed => returns single point for current report."""
        report = _make_report(
            results=[_result("ASI01-001", verdict=Verdict.SAFE)],
        )
        scorer = DualScorer(report)
        result = scorer.pareto_frontier()
        assert len(result) == 1
        assert result[0].config_label == "current"
        assert result[0].is_dominated is False


# ---------------------------------------------------------------------------
# Category-level scoring
# ---------------------------------------------------------------------------

class TestCategoryScoring:
    def test_two_categories(self):
        """Scores broken down by ASI category."""
        findings = [
            _finding("ASI01-001", category=ASICategory.ASI01, verdict=Verdict.VULNERABLE),
        ]
        results = [
            _result("ASI01-001", category=ASICategory.ASI01, verdict=Verdict.VULNERABLE),
            _result("ASI01-002", category=ASICategory.ASI01, verdict=Verdict.SAFE),
            _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.SAFE),
            _result("ASI02-002", category=ASICategory.ASI02, verdict=Verdict.SAFE),
        ]
        report = _make_report(findings=findings, results=results)
        utilities = [
            _utility("ASI01-001", task_completed=True, quality=0.8),
            _utility("ASI01-002", task_completed=True, quality=0.9),
            _utility("ASI02-001", task_completed=True, quality=1.0),
            _utility("ASI02-002", task_completed=False, quality=0.0),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()

        assert "ASI01" in dual.per_category
        assert "ASI02" in dual.per_category

        asi01 = dual.per_category["ASI01"]
        assert asi01.security_score == 50.0  # 1 vuln out of 2
        assert asi01.scenario_count == 2

        asi02 = dual.per_category["ASI02"]
        assert asi02.security_score == 100.0  # 0 vuln out of 2
        assert asi02.scenario_count == 2

    def test_category_utility_grouped(self):
        """Utility scores are grouped by scenario ID prefix."""
        results = [
            _result("ASI06-001", category=ASICategory.ASI06, verdict=Verdict.SAFE),
        ]
        report = _make_report(results=results)
        utilities = [
            _utility("ASI06-001", task_completed=True, quality=0.5,
                     tools_used=["a"], expected_tools=["a", "b"]),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()

        asi06 = dual.per_category["ASI06"]
        # quality=0.5, completion=1.0, tool_accuracy=0.5 => (1+0.5+0.5)/3 = 0.667
        assert 60.0 < asi06.utility_score < 70.0


# ---------------------------------------------------------------------------
# to_json / to_console
# ---------------------------------------------------------------------------

class TestSerialization:
    def test_to_json_keys(self):
        report = _make_report(
            results=[_result("ASI01-001", verdict=Verdict.SAFE)],
        )
        scorer = DualScorer(report)
        data = scorer.to_json()
        assert "security_score" in data
        assert "utility_score" in data
        assert "combined_score" in data
        assert "per_category" in data
        assert "tradeoff_ratio" in data
        assert "pareto_optimal" in data

    def test_to_console_contains_header(self):
        report = _make_report(
            results=[_result("ASI01-001", verdict=Verdict.SAFE)],
        )
        scorer = DualScorer(report)
        text = scorer.to_console()
        assert "Dual Score Report" in text
        assert "Security Score" in text
        assert "Utility Score" in text


# ---------------------------------------------------------------------------
# Tradeoff ratio
# ---------------------------------------------------------------------------

class TestTradeoffRatio:
    def test_high_security_high_utility(self):
        """Both above 50 => positive ratio."""
        report = _make_report(
            results=[_result("ASI01-001", verdict=Verdict.SAFE)],
        )
        utilities = [
            _utility("ASI01-001", task_completed=True, quality=1.0),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()
        assert dual.tradeoff_ratio > 0

    def test_low_security_low_utility(self):
        """Both below 50 => negative ratio."""
        findings = [
            _finding("ASI01-001", severity=Severity.CRITICAL, verdict=Verdict.VULNERABLE),
        ]
        results = [
            _result("ASI01-001", verdict=Verdict.VULNERABLE),
        ]
        report = _make_report(findings=findings, results=results)
        utilities = [
            _utility("ASI01-001", task_completed=False, quality=0.0,
                     tools_used=[], expected_tools=["a"]),
        ]
        scorer = DualScorer(report, utilities)
        dual = scorer.compute()
        assert dual.tradeoff_ratio < 0
