"""Comprehensive tests for the coverage metrics dashboard."""

from __future__ import annotations

from pathlib import Path

import pytest

from aastf.coverage import (
    ASICoverage,
    AttackVectorCoverage,
    CategoryStats,
    CoverageAnalyzer,
    ToolCoverage,
    VectorStats,
    _risk_bar,
    _risk_color,
)
from aastf.models.result import ScanReport, TestResult, Verdict
from aastf.models.scenario import (
    ASICategory,
    AttackScenario,
    DetectionCriteria,
    InjectionPoint,
    Severity,
)
from aastf.models.trace import AgentTrace, ToolInvocation
from aastf.scenarios.registry import ScenarioRegistry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _trace(
    scenario_id: str = "ASI01-001",
    tools: list[str] | None = None,
) -> AgentTrace:
    invocations = [
        ToolInvocation(tool_name=t, sequence=i)
        for i, t in enumerate(tools or [])
    ]
    return AgentTrace(
        scenario_id=scenario_id,
        adapter="test",
        tool_invocations=invocations,
    )


def _result(
    scenario_id: str = "ASI01-001",
    category: ASICategory = ASICategory.ASI01,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.SAFE,
    tools: list[str] | None = None,
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name=f"Test {scenario_id}",
        category=category,
        severity=severity,
        verdict=verdict,
        trace=_trace(scenario_id, tools),
    )


def _report(results: list[TestResult]) -> ScanReport:
    return ScanReport(
        aastf_version="0.5.0",
        adapter="test",
        total_scenarios=len(results),
        results=results,
    )


def _scenario(
    scenario_id: str = "ASI01-001",
    category: ASICategory = ASICategory.ASI01,
    inject_into: InjectionPoint = InjectionPoint.USER_MESSAGE,
    available_tools: list[str] | None = None,
    tags: list[str] | None = None,
) -> AttackScenario:
    return AttackScenario(
        id=scenario_id,
        name=f"Test {scenario_id}",
        category=category,
        severity=Severity.HIGH,
        description="Test scenario",
        attack_vector="test",
        inject_into=inject_into,
        payload="test payload",
        detection=DetectionCriteria(output_contains=["bad"]),
        expected_behavior="Agent should refuse",
        remediation="Fix it",
        available_tools=available_tools or [],
        tags=tags or [],
    )


def _registry_with(*scenarios: AttackScenario) -> ScenarioRegistry:
    reg = ScenarioRegistry()
    for s in scenarios:
        reg._scenarios[s.id] = s
    return reg


# ---------------------------------------------------------------------------
# ToolCoverage
# ---------------------------------------------------------------------------


class TestToolCoverage:
    def test_empty_report(self):
        report = _report([])
        analyzer = CoverageAnalyzer(report)
        tc = analyzer.tool_coverage()
        assert tc.total_tools == 0
        assert tc.tested_tools == 0
        assert tc.coverage_pct == 0.0
        assert tc.untested_tools == []

    def test_all_tools_tested(self):
        reg = _registry_with(
            _scenario("ASI01-001", available_tools=["tool_a", "tool_b"]),
        )
        results = [
            _result("ASI01-001", tools=["tool_a", "tool_b"]),
        ]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        tc = analyzer.tool_coverage()
        assert tc.total_tools == 2
        assert tc.tested_tools == 2
        assert tc.coverage_pct == 100.0
        assert tc.untested_tools == []

    def test_partial_coverage(self):
        reg = _registry_with(
            _scenario("ASI01-001", available_tools=["tool_a", "tool_b", "tool_c"]),
        )
        results = [_result("ASI01-001", tools=["tool_a"])]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        tc = analyzer.tool_coverage()
        assert tc.total_tools == 3
        assert tc.tested_tools == 1
        assert tc.coverage_pct == pytest.approx(33.3, abs=0.1)
        assert sorted(tc.untested_tools) == ["tool_b", "tool_c"]

    def test_no_registry_fallback(self):
        """Without registry, all tools = tested tools -> 100%."""
        results = [_result("ASI01-001", tools=["x", "y"])]
        analyzer = CoverageAnalyzer(_report(results))
        tc = analyzer.tool_coverage()
        assert tc.total_tools == 2
        assert tc.tested_tools == 2
        assert tc.coverage_pct == 100.0

    def test_tools_from_multiple_scenarios(self):
        reg = _registry_with(
            _scenario("ASI01-001", available_tools=["a", "b"]),
            _scenario("ASI02-001", category=ASICategory.ASI02, available_tools=["b", "c"]),
        )
        results = [
            _result("ASI01-001", tools=["a"]),
            _result("ASI02-001", category=ASICategory.ASI02, tools=["c"]),
        ]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        tc = analyzer.tool_coverage()
        assert tc.total_tools == 3  # a, b, c
        assert tc.tested_tools == 2  # a, c
        assert "b" in tc.untested_tools


# ---------------------------------------------------------------------------
# AttackVectorCoverage
# ---------------------------------------------------------------------------


class TestAttackVectorCoverage:
    def test_empty_report(self):
        analyzer = CoverageAnalyzer(_report([]))
        avc = analyzer.attack_vector_coverage()
        assert avc.total_scenarios == 0
        for vs in avc.vectors.values():
            assert vs.scenario_count == 0

    def test_direct_input_vector(self):
        reg = _registry_with(
            _scenario("ASI01-001", inject_into=InjectionPoint.USER_MESSAGE),
        )
        results = [_result("ASI01-001", verdict=Verdict.VULNERABLE)]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        avc = analyzer.attack_vector_coverage()
        assert avc.vectors["direct_input"].scenario_count == 1
        assert avc.vectors["direct_input"].vulnerable_count == 1

    def test_tool_output_vector(self):
        reg = _registry_with(
            _scenario("ASI02-001", category=ASICategory.ASI02,
                      inject_into=InjectionPoint.TOOL_RESPONSE),
        )
        results = [_result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.SAFE)]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        avc = analyzer.attack_vector_coverage()
        assert avc.vectors["tool_output"].scenario_count == 1
        assert avc.vectors["tool_output"].safe_count == 1

    def test_memory_write_vector(self):
        reg = _registry_with(
            _scenario("ASI06-001", category=ASICategory.ASI06,
                      inject_into=InjectionPoint.MEMORY),
        )
        results = [_result("ASI06-001", category=ASICategory.ASI06, verdict=Verdict.SAFE)]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        avc = analyzer.attack_vector_coverage()
        assert avc.vectors["memory_write"].scenario_count == 1

    def test_inter_agent_via_tag(self):
        reg = _registry_with(
            _scenario("ASI07-001", category=ASICategory.ASI07,
                      inject_into=InjectionPoint.USER_MESSAGE,
                      tags=["inter-agent"]),
        )
        results = [_result("ASI07-001", category=ASICategory.ASI07, verdict=Verdict.SAFE)]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        avc = analyzer.attack_vector_coverage()
        assert avc.vectors["inter_agent_message"].scenario_count == 1

    def test_fallback_asi07_no_registry(self):
        """ASI07 maps to inter_agent_message when no registry."""
        results = [_result("ASI07-001", category=ASICategory.ASI07)]
        analyzer = CoverageAnalyzer(_report(results))
        avc = analyzer.attack_vector_coverage()
        assert avc.vectors["inter_agent_message"].scenario_count == 1

    def test_fallback_asi06_no_registry(self):
        """ASI06 maps to memory_write when no registry."""
        results = [_result("ASI06-001", category=ASICategory.ASI06)]
        analyzer = CoverageAnalyzer(_report(results))
        avc = analyzer.attack_vector_coverage()
        assert avc.vectors["memory_write"].scenario_count == 1

    def test_multiple_vectors(self):
        reg = _registry_with(
            _scenario("ASI01-001", inject_into=InjectionPoint.USER_MESSAGE),
            _scenario("ASI06-001", category=ASICategory.ASI06,
                      inject_into=InjectionPoint.MEMORY),
        )
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE),
            _result("ASI06-001", category=ASICategory.ASI06, verdict=Verdict.VULNERABLE),
        ]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        avc = analyzer.attack_vector_coverage()
        assert avc.total_scenarios == 2
        assert avc.vectors["direct_input"].scenario_count == 1
        assert avc.vectors["memory_write"].scenario_count == 1


# ---------------------------------------------------------------------------
# ASICoverage
# ---------------------------------------------------------------------------


class TestASICoverage:
    def test_empty_report(self):
        analyzer = CoverageAnalyzer(_report([]))
        asic = analyzer.asi_coverage()
        assert asic.covered_categories == 0
        assert asic.total_categories == 10  # ASI01..ASI10
        assert asic.categories == {}

    def test_single_category(self):
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE),
            _result("ASI01-002", verdict=Verdict.VULNERABLE),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        asic = analyzer.asi_coverage()
        assert asic.covered_categories == 1
        assert "ASI01" in asic.categories
        cs = asic.categories["ASI01"]
        assert cs.scenario_count == 2
        assert cs.vulnerable == 1
        assert cs.safe == 1
        assert cs.risk_score == 50.0

    def test_multiple_categories(self):
        results = [
            _result("ASI01-001"),
            _result("ASI02-001", category=ASICategory.ASI02),
            _result("ASI03-001", category=ASICategory.ASI03),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        asic = analyzer.asi_coverage()
        assert asic.covered_categories == 3

    def test_risk_score_all_vulnerable(self):
        results = [
            _result("ASI01-001", verdict=Verdict.VULNERABLE),
            _result("ASI01-002", verdict=Verdict.VULNERABLE),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        asic = analyzer.asi_coverage()
        assert asic.categories["ASI01"].risk_score == 100.0

    def test_risk_score_all_safe(self):
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        asic = analyzer.asi_coverage()
        assert asic.categories["ASI01"].risk_score == 0.0

    def test_tool_poisoning_counts_as_vulnerable(self):
        results = [
            _result("ASI04-001", category=ASICategory.ASI04,
                    verdict=Verdict.TOOL_POISONING),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        asic = analyzer.asi_coverage()
        assert asic.categories["ASI04"].vulnerable == 1

    def test_schema_poisoning_counts_as_vulnerable(self):
        results = [
            _result("ASI04-002", category=ASICategory.ASI04,
                    verdict=Verdict.SCHEMA_POISONING),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        asic = analyzer.asi_coverage()
        assert asic.categories["ASI04"].vulnerable == 1


# ---------------------------------------------------------------------------
# Verdict distribution
# ---------------------------------------------------------------------------


class TestVerdictDistribution:
    def test_empty(self):
        analyzer = CoverageAnalyzer(_report([]))
        assert analyzer.verdict_distribution() == {}

    def test_counts(self):
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE),
            _result("ASI01-002", verdict=Verdict.SAFE),
            _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.VULNERABLE),
            _result("ASI03-001", category=ASICategory.ASI03, verdict=Verdict.ERROR),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        dist = analyzer.verdict_distribution()
        assert dist["SAFE"] == 2
        assert dist["VULNERABLE"] == 1
        assert dist["ERROR"] == 1

    def test_all_verdict_types(self):
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE),
            _result("ASI01-002", verdict=Verdict.VULNERABLE),
            _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.INCONCLUSIVE),
            _result("ASI03-001", category=ASICategory.ASI03, verdict=Verdict.ERROR),
            _result("ASI04-001", category=ASICategory.ASI04, verdict=Verdict.REFUSAL_ECHO),
            _result("ASI04-002", category=ASICategory.ASI04, verdict=Verdict.TOOL_POISONING),
            _result("ASI04-003", category=ASICategory.ASI04, verdict=Verdict.SCHEMA_POISONING),
            _result("ASI05-001", category=ASICategory.ASI05,
                    verdict=Verdict.PREFERENCE_MANIPULATION),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        dist = analyzer.verdict_distribution()
        assert len(dist) == 8


# ---------------------------------------------------------------------------
# Overall score
# ---------------------------------------------------------------------------


class TestOverallScore:
    def test_empty_report_zero(self):
        analyzer = CoverageAnalyzer(_report([]))
        assert analyzer.overall_score() == 0.0

    def test_all_safe_high_score(self):
        """All safe + full vector/category coverage should be near 100."""
        reg = _registry_with(
            _scenario("ASI01-001", inject_into=InjectionPoint.USER_MESSAGE,
                      available_tools=["a"]),
            _scenario("ASI02-001", category=ASICategory.ASI02,
                      inject_into=InjectionPoint.TOOL_RESPONSE,
                      available_tools=["a"]),
            _scenario("ASI06-001", category=ASICategory.ASI06,
                      inject_into=InjectionPoint.MEMORY,
                      available_tools=["a"]),
            _scenario("ASI07-001", category=ASICategory.ASI07,
                      inject_into=InjectionPoint.USER_MESSAGE,
                      tags=["inter-agent"], available_tools=["a"]),
            _scenario("ASI01-002", inject_into=InjectionPoint.SYSTEM_PROMPT,
                      available_tools=["a"]),
        )
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE, tools=["a"]),
            _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.SAFE, tools=["a"]),
            _result("ASI06-001", category=ASICategory.ASI06, verdict=Verdict.SAFE, tools=["a"]),
            _result("ASI07-001", category=ASICategory.ASI07, verdict=Verdict.SAFE, tools=["a"]),
            _result("ASI01-002", verdict=Verdict.SAFE, tools=["a"]),
        ]
        analyzer = CoverageAnalyzer(_report(results), registry=reg)
        score = analyzer.overall_score()
        # tool=100%, vectors=100%, cats=4/10=40%, safety=100%
        # 100*0.25 + 100*0.25 + 40*0.30 + 100*0.20 = 25+25+12+20 = 82
        assert score == pytest.approx(82.0, abs=1.0)

    def test_score_bounded_100(self):
        analyzer = CoverageAnalyzer(_report([]))
        assert analyzer.overall_score() <= 100.0

    def test_score_with_vulnerabilities(self):
        """Vulnerabilities lower the safety component."""
        results = [
            _result("ASI01-001", verdict=Verdict.VULNERABLE, tools=["a"]),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        score = analyzer.overall_score()
        # safety = 0%, so score must be < 100
        assert score < 80.0

    def test_mixed_verdicts(self):
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE, tools=["a"]),
            _result("ASI01-002", verdict=Verdict.VULNERABLE, tools=["b"]),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        score = analyzer.overall_score()
        assert 0.0 < score < 100.0


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestToJson:
    def test_structure(self):
        results = [_result("ASI01-001", verdict=Verdict.SAFE, tools=["a"])]
        analyzer = CoverageAnalyzer(_report(results))
        data = analyzer.to_json()
        assert "tool_coverage" in data
        assert "attack_vector_coverage" in data
        assert "asi_coverage" in data
        assert "verdict_distribution" in data
        assert "overall_score" in data
        assert isinstance(data["overall_score"], float)

    def test_json_serializable(self):
        """Output must be JSON-serializable (no pydantic objects)."""
        import json
        results = [_result("ASI01-001")]
        analyzer = CoverageAnalyzer(_report(results))
        # Should not raise
        json.dumps(analyzer.to_json())


class TestToConsole:
    def test_contains_sections(self):
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE, tools=["a"]),
            _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.VULNERABLE),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        out = analyzer.to_console()
        assert "AASTF Coverage Dashboard" in out
        assert "Tool Coverage" in out
        assert "Attack Vector Coverage" in out
        assert "ASI Category Coverage" in out
        assert "Verdict Distribution" in out
        assert "Overall Coverage Score" in out

    def test_empty_report_no_crash(self):
        analyzer = CoverageAnalyzer(_report([]))
        out = analyzer.to_console()
        assert "0/100" in out or "0.0/100" in out


class TestToHtml:
    def test_creates_file(self, tmp_path: Path):
        results = [_result("ASI01-001", verdict=Verdict.SAFE)]
        analyzer = CoverageAnalyzer(_report(results))
        out = tmp_path / "dashboard.html"
        analyzer.to_html(out)
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "AASTF Coverage Dashboard" in content

    def test_contains_heatmap(self, tmp_path: Path):
        results = [
            _result("ASI01-001", verdict=Verdict.SAFE),
            _result("ASI02-001", category=ASICategory.ASI02, verdict=Verdict.VULNERABLE),
        ]
        analyzer = CoverageAnalyzer(_report(results))
        out = tmp_path / "sub" / "dashboard.html"
        analyzer.to_html(out)
        content = out.read_text(encoding="utf-8")
        assert "ASI01" in content
        assert "ASI02" in content
        # Untested categories should show N/A
        assert "N/A" in content

    def test_html_no_external_deps(self, tmp_path: Path):
        """HTML should be self-contained with no external stylesheet/script links."""
        results = [_result("ASI01-001")]
        analyzer = CoverageAnalyzer(_report(results))
        out = tmp_path / "dashboard.html"
        analyzer.to_html(out)
        content = out.read_text(encoding="utf-8")
        assert 'rel="stylesheet"' not in content
        assert "<script src=" not in content

    def test_html_escapes_content(self, tmp_path: Path):
        """HTML special chars in tool names should be escaped."""
        results = [_result("ASI01-001", tools=["tool<script>"])]
        analyzer = CoverageAnalyzer(_report(results))
        out = tmp_path / "dashboard.html"
        analyzer.to_html(out)
        content = out.read_text(encoding="utf-8")
        assert "<script>" not in content or "&lt;script&gt;" in content


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TestPydanticModels:
    def test_tool_coverage_defaults(self):
        tc = ToolCoverage()
        assert tc.total_tools == 0
        assert tc.coverage_pct == 0.0

    def test_vector_stats(self):
        vs = VectorStats(name="test", scenario_count=5, vulnerable_count=2, safe_count=3)
        assert vs.name == "test"

    def test_category_stats(self):
        cs = CategoryStats(category="ASI01", scenario_count=10, vulnerable=3, safe=7, risk_score=30.0)
        assert cs.risk_score == 30.0

    def test_asi_coverage(self):
        asic = ASICoverage(total_categories=10, covered_categories=5)
        assert asic.total_categories == 10

    def test_attack_vector_coverage(self):
        avc = AttackVectorCoverage(total_scenarios=10)
        assert avc.total_scenarios == 10


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_risk_bar_zero(self):
        assert _risk_bar(0) == "[..........]"

    def test_risk_bar_fifty(self):
        assert _risk_bar(50) == "[#####.....]"

    def test_risk_bar_hundred(self):
        assert _risk_bar(100) == "[##########]"

    def test_risk_color_zero_green(self):
        c = _risk_color(0)
        assert c == "#4caf50"

    def test_risk_color_hundred_red(self):
        c = _risk_color(100)
        assert c == "#b71c1c"

    def test_risk_color_mid_orange(self):
        c = _risk_color(50)
        assert c == "#ff9800"
