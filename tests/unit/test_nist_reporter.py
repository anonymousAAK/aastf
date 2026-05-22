"""Unit tests for NIST AI RMF compliance reporter."""

from __future__ import annotations

import pytest

from aastf.compliance.nist_ai_rmf import (
    GENAI_PROFILE_RISKS,
    NIST_RMF_FUNCTION_MAPPING,
    NISTAIRMFReporter,
)
from aastf.models.result import ScanReport, TestResult, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    category: ASICategory = ASICategory.ASI02,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.VULNERABLE,
    scenario_id: str = "ASI02-001",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name="Test finding",
        category=category,
        severity=severity,
        verdict=verdict,
        triggered_by="tool_called",
        description="Test description",
        remediation="Apply fix",
    )


def _test_result(
    category: ASICategory = ASICategory.ASI02,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.SAFE,
    scenario_id: str = "ASI02-001",
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name="Test scenario",
        category=category,
        severity=severity,
        verdict=verdict,
        trace=AgentTrace(scenario_id=scenario_id, adapter="test"),
    )


def _report(
    findings: list[VulnerabilityFinding] | None = None,
    results: list[TestResult] | None = None,
    **kwargs,
) -> ScanReport:
    findings = findings or []
    results = results or []
    defaults = {
        "aastf_version": "0.6.0",
        "adapter": "test",
        "total_scenarios": len(results) or len(findings) or 0,
        "vulnerable": sum(1 for f in findings if f.verdict == Verdict.VULNERABLE),
        "safe": sum(1 for r in results if r.verdict == Verdict.SAFE),
    }
    defaults.update(kwargs)
    return ScanReport(findings=findings, results=results, **defaults)


@pytest.fixture()
def sample_report() -> ScanReport:
    results = [
        _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001"),
        _test_result(ASICategory.ASI01, Severity.MEDIUM, Verdict.SAFE, "ASI01-002"),
        _test_result(ASICategory.ASI03, Severity.HIGH, Verdict.SAFE, "ASI03-001"),
        _test_result(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, "ASI05-001"),
        _test_result(ASICategory.ASI09, Severity.HIGH, Verdict.SAFE, "ASI09-001"),
    ]
    findings = [
        _finding(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001"),
        _finding(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, "ASI05-001"),
    ]
    return _report(findings=findings, results=results, total_scenarios=5, vulnerable=2, safe=3)


@pytest.fixture()
def empty_report() -> ScanReport:
    return _report()


# ---------------------------------------------------------------------------
# RMF function mapping
# ---------------------------------------------------------------------------


class TestFunctionMapping:
    def test_four_rmf_functions(self):
        assert set(NIST_RMF_FUNCTION_MAPPING.keys()) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}

    def test_all_asi_categories_covered(self):
        """Every ASI category should appear in at least one RMF function."""
        all_mapped: set[ASICategory] = set()
        for func_info in NIST_RMF_FUNCTION_MAPPING.values():
            all_mapped.update(func_info["mapped_asi"])
        for cat in ASICategory:
            assert cat in all_mapped, f"{cat.value} not mapped to any RMF function"

    def test_each_function_has_required_keys(self):
        required = {"description", "mapped_asi", "subcategories"}
        for func_name, func_info in NIST_RMF_FUNCTION_MAPPING.items():
            assert required <= set(func_info.keys()), (
                f"Function {func_name!r} missing keys"
            )

    def test_subcategories_have_required_keys(self):
        required = {"id", "title", "relevance"}
        for func_name, func_info in NIST_RMF_FUNCTION_MAPPING.items():
            for sub in func_info["subcategories"]:
                assert required <= set(sub.keys()), (
                    f"Subcategory in {func_name} missing keys"
                )

    def test_govern_includes_asi10(self):
        mapped = NIST_RMF_FUNCTION_MAPPING["GOVERN"]["mapped_asi"]
        assert ASICategory.ASI10 in mapped


class TestGenAIProfile:
    def test_ten_risk_areas(self):
        assert len(GENAI_PROFILE_RISKS) == 10

    def test_each_risk_has_required_keys(self):
        required = {"description", "mapped_asi"}
        for risk_name, risk_info in GENAI_PROFILE_RISKS.items():
            assert required <= set(risk_info.keys()), (
                f"GenAI risk {risk_name!r} missing keys"
            )


# ---------------------------------------------------------------------------
# generate() output
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_output_has_required_keys(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        expected = {
            "report_metadata", "overall_maturity",
            "function_assessment", "genai_profile_risks",
            "recommendations", "evidence_summary",
        }
        assert expected <= set(result.keys())

    def test_report_metadata(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        meta = result["report_metadata"]
        assert meta["framework"] == "aastf"
        assert meta["report_type"] == "nist_ai_rmf"
        assert meta["run_id"] == sample_report.run_id

    def test_four_functions_assessed(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        assert len(result["function_assessment"]) == 4

    def test_function_has_required_fields(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        required = {
            "description", "mapped_asi", "subcategories",
            "scenarios_tested", "vulnerabilities_found",
            "findings_count", "findings",
        }
        for func_data in result["function_assessment"].values():
            assert required <= set(func_data.keys())

    def test_genai_risks_assessed(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        assert len(result["genai_profile_risks"]) == 10


# ---------------------------------------------------------------------------
# Maturity level calculation
# ---------------------------------------------------------------------------


class TestMaturityLevel:
    def test_l1_few_categories(self, empty_report):
        """Empty report (< 3 categories tested) should be L1."""
        result = NISTAIRMFReporter().generate(empty_report)
        assert result["overall_maturity"]["level"] == "L1"
        assert result["overall_maturity"]["label"] == "INITIAL"

    def test_l1_critical_vuln(self):
        """Critical vuln even with many categories should be L1."""
        results = [
            _test_result(cat, Severity.HIGH, Verdict.SAFE, f"{cat.value}-001")
            for cat in ASICategory
        ]
        findings = [
            _finding(ASICategory.ASI01, Severity.CRITICAL, Verdict.VULNERABLE, "ASI01-001"),
        ]
        report = _report(findings=findings, results=results, total_scenarios=10, vulnerable=1, safe=9)
        result = NISTAIRMFReporter().generate(report)
        assert result["overall_maturity"]["level"] == "L1"

    def test_l2_high_vuln(self):
        """High vuln with >= 3 categories should be L2."""
        results = [
            _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001"),
            _test_result(ASICategory.ASI02, Severity.HIGH, Verdict.SAFE, "ASI02-001"),
            _test_result(ASICategory.ASI03, Severity.HIGH, Verdict.SAFE, "ASI03-001"),
        ]
        findings = [
            _finding(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001"),
        ]
        report = _report(findings=findings, results=results, total_scenarios=3, vulnerable=1, safe=2)
        result = NISTAIRMFReporter().generate(report)
        assert result["overall_maturity"]["level"] == "L2"

    def test_l5_full_coverage_no_vulns(self):
        """All 10 categories tested, all safe, all functions covered => L5."""
        results = [
            _test_result(cat, Severity.HIGH, Verdict.SAFE, f"{cat.value}-001")
            for cat in ASICategory
        ]
        report = _report(results=results, total_scenarios=10, safe=10)
        result = NISTAIRMFReporter().generate(report)
        assert result["overall_maturity"]["level"] == "L5"
        assert result["overall_maturity"]["label"] == "OPTIMIZING"

    def test_maturity_has_required_keys(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        maturity = result["overall_maturity"]
        assert "level" in maturity
        assert "label" in maturity
        assert "description" in maturity


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_returns_string(self, sample_report):
        md = NISTAIRMFReporter().generate_markdown(sample_report)
        assert isinstance(md, str)

    def test_contains_key_sections(self, sample_report):
        md = NISTAIRMFReporter().generate_markdown(sample_report)
        assert "# NIST AI Risk Management Framework Report" in md
        assert "## Executive Summary" in md
        assert "## Evidence Summary" in md
        assert "## RMF Function Assessment" in md
        assert "## GenAI Profile (AI 600-1) Risk Assessment" in md
        assert "## Recommendations" in md
        assert "## Scan Metadata" in md

    def test_contains_disclaimer(self, sample_report):
        md = NISTAIRMFReporter().generate_markdown(sample_report)
        assert "does not constitute regulatory or legal advice" in md

    def test_contains_function_names(self, sample_report):
        md = NISTAIRMFReporter().generate_markdown(sample_report)
        assert "GOVERN" in md
        assert "MAP" in md
        assert "MEASURE" in md
        assert "MANAGE" in md

    def test_contains_maturity_level(self, sample_report):
        md = NISTAIRMFReporter().generate_markdown(sample_report)
        assert "Maturity Level" in md


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


class TestRecommendations:
    def test_critical_finding_generates_critical_rec(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        recs = result["recommendations"]
        critical = [r for r in recs if r["priority"] == "CRITICAL"]
        assert len(critical) >= 1

    def test_high_finding_generates_high_rec(self, sample_report):
        result = NISTAIRMFReporter().generate(sample_report)
        recs = result["recommendations"]
        high = [r for r in recs if r["priority"] == "HIGH"]
        assert len(high) >= 1

    def test_untested_function_generates_info_rec(self, empty_report):
        result = NISTAIRMFReporter().generate(empty_report)
        recs = result["recommendations"]
        info = [r for r in recs if r["priority"] == "INFO"]
        # All 4 functions untested => at least 4 INFO recs
        assert len(info) >= 4


# ---------------------------------------------------------------------------
# Empty report
# ---------------------------------------------------------------------------


class TestEmptyReport:
    def test_empty_generates(self, empty_report):
        result = NISTAIRMFReporter().generate(empty_report)
        assert result["evidence_summary"]["total_scenarios"] == 0
        assert result["evidence_summary"]["vulnerability_rate"] == 0.0

    def test_empty_maturity_l1(self, empty_report):
        result = NISTAIRMFReporter().generate(empty_report)
        assert result["overall_maturity"]["level"] == "L1"

    def test_empty_markdown(self, empty_report):
        md = NISTAIRMFReporter().generate_markdown(empty_report)
        assert isinstance(md, str)
        assert len(md) > 0

    def test_empty_function_assessment(self, empty_report):
        result = NISTAIRMFReporter().generate(empty_report)
        for func_data in result["function_assessment"].values():
            assert func_data["scenarios_tested"] == 0
            assert func_data["vulnerabilities_found"] == 0

    def test_empty_genai_profile(self, empty_report):
        result = NISTAIRMFReporter().generate(empty_report)
        for risk_data in result["genai_profile_risks"].values():
            assert risk_data["scenarios_tested"] == 0
            assert risk_data["vulnerabilities_found"] == 0
