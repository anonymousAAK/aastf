"""Unit tests for Singapore IMDA Agentic AI Governance reporter."""

from __future__ import annotations

import pytest

from aastf.compliance.singapore_imda import (
    IMDA_GOVERNANCE_DIMENSIONS,
    IMDA_RISK_CATEGORY_MAPPING,
    IMDAReporter,
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
# Risk category mapping
# ---------------------------------------------------------------------------


class TestRiskCategoryMapping:
    def test_five_risk_categories(self):
        assert len(IMDA_RISK_CATEGORY_MAPPING) == 5

    def test_all_asi_categories_covered(self):
        """Every ASI category should appear in at least one IMDA risk category."""
        all_mapped_asi: set[ASICategory] = set()
        for cat_info in IMDA_RISK_CATEGORY_MAPPING.values():
            all_mapped_asi.update(cat_info["mapped_asi"])
        for cat in ASICategory:
            assert cat in all_mapped_asi, f"{cat.value} not mapped to any IMDA risk category"

    def test_each_mapping_has_required_keys(self):
        required = {"description", "mapped_asi", "governance_concern"}
        for cat_name, cat_info in IMDA_RISK_CATEGORY_MAPPING.items():
            assert required <= set(cat_info.keys()), (
                f"Risk category {cat_name!r} missing keys"
            )

    def test_asi01_in_erroneous_actions(self):
        mapped = IMDA_RISK_CATEGORY_MAPPING["Erroneous Actions"]["mapped_asi"]
        assert ASICategory.ASI01 in mapped


class TestGovernanceDimensions:
    def test_four_dimensions(self):
        assert len(IMDA_GOVERNANCE_DIMENSIONS) == 4

    def test_dimension_names(self):
        expected = {"Risk Bounding", "Human Accountability", "Technical Controls", "Transparency"}
        assert set(IMDA_GOVERNANCE_DIMENSIONS.keys()) == expected


# ---------------------------------------------------------------------------
# generate() output
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_output_has_required_keys(self, sample_report):
        result = IMDAReporter().generate(sample_report)
        expected = {
            "report_metadata", "overall_readiness",
            "risk_category_assessment", "governance_dimensions",
            "recommendations", "evidence_summary",
        }
        assert expected <= set(result.keys())

    def test_report_metadata(self, sample_report):
        result = IMDAReporter().generate(sample_report)
        meta = result["report_metadata"]
        assert meta["framework"] == "aastf"
        assert meta["report_type"] == "singapore_imda_agentic_ai"
        assert meta["run_id"] == sample_report.run_id

    def test_five_risk_categories_assessed(self, sample_report):
        result = IMDAReporter().generate(sample_report)
        assert len(result["risk_category_assessment"]) == 5

    def test_four_governance_dimensions_scored(self, sample_report):
        result = IMDAReporter().generate(sample_report)
        assert len(result["governance_dimensions"]) == 4

    def test_risk_category_has_required_fields(self, sample_report):
        result = IMDAReporter().generate(sample_report)
        required = {
            "description", "governance_concern", "mapped_asi",
            "scenarios_tested", "vulnerabilities_found", "findings_count",
            "findings",
        }
        for cat_data in result["risk_category_assessment"].values():
            assert required <= set(cat_data.keys())

    def test_dimension_has_required_fields(self, sample_report):
        result = IMDAReporter().generate(sample_report)
        required = {
            "description", "score", "mapped_asi",
            "scenarios_tested", "vulnerabilities_found",
        }
        for dim_data in result["governance_dimensions"].values():
            assert required <= set(dim_data.keys())


# ---------------------------------------------------------------------------
# Governance dimension scoring
# ---------------------------------------------------------------------------


class TestGovernanceScoring:
    def test_no_vulns_high_score(self):
        """All safe results should give score of 100 (no deductions)."""
        results = [
            _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.SAFE, "ASI01-001"),
        ]
        report = _report(results=results, total_scenarios=1, safe=1)
        result = IMDAReporter().generate(report)
        # ASI01 is in "Risk Bounding" dimension
        risk_bounding = result["governance_dimensions"]["Risk Bounding"]
        assert risk_bounding["score"] == 100

    def test_critical_vuln_deducts_25(self):
        results = [
            _test_result(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, "ASI05-001"),
        ]
        findings = [
            _finding(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, "ASI05-001"),
        ]
        report = _report(findings=findings, results=results, total_scenarios=1, vulnerable=1)
        result = IMDAReporter().generate(report)
        # ASI05 is in "Technical Controls" dimension
        tech = result["governance_dimensions"]["Technical Controls"]
        assert tech["score"] == 75  # 100 - 25

    def test_high_vuln_deducts_15(self):
        results = [
            _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001"),
        ]
        findings = [
            _finding(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001"),
        ]
        report = _report(findings=findings, results=results, total_scenarios=1, vulnerable=1)
        result = IMDAReporter().generate(report)
        risk_bounding = result["governance_dimensions"]["Risk Bounding"]
        assert risk_bounding["score"] == 85  # 100 - 15

    def test_untested_dimension_penalty(self, empty_report):
        result = IMDAReporter().generate(empty_report)
        for dim_data in result["governance_dimensions"].values():
            assert dim_data["score"] == 90  # 100 - 10 penalty for no coverage

    def test_score_floors_at_zero(self):
        """Multiple critical vulns should not go below 0."""
        results = [
            _test_result(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, f"ASI05-00{i}")
            for i in range(1, 6)
        ]
        findings = [
            _finding(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, f"ASI05-00{i}")
            for i in range(1, 6)
        ]
        report = _report(findings=findings, results=results, total_scenarios=5, vulnerable=5)
        result = IMDAReporter().generate(report)
        tech = result["governance_dimensions"]["Technical Controls"]
        assert tech["score"] == 0  # 100 - 5*25 = -25, floored to 0


# ---------------------------------------------------------------------------
# Readiness levels
# ---------------------------------------------------------------------------


class TestReadinessLevels:
    def test_ready_no_findings(self, empty_report):
        result = IMDAReporter().generate(empty_report)
        assert result["overall_readiness"]["status"] == "ready"

    def test_insufficient_critical(self):
        findings = [_finding(severity=Severity.CRITICAL, verdict=Verdict.VULNERABLE)]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        result = IMDAReporter().generate(report)
        assert result["overall_readiness"]["status"] == "insufficient"

    def test_partial_high(self):
        findings = [_finding(severity=Severity.HIGH, verdict=Verdict.VULNERABLE)]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        result = IMDAReporter().generate(report)
        assert result["overall_readiness"]["status"] == "partial"

    def test_readiness_label(self, empty_report):
        result = IMDAReporter().generate(empty_report)
        assert result["overall_readiness"]["label"] == "GOVERNANCE READY"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_returns_string(self, sample_report):
        md = IMDAReporter().generate_markdown(sample_report)
        assert isinstance(md, str)

    def test_contains_key_sections(self, sample_report):
        md = IMDAReporter().generate_markdown(sample_report)
        assert "# Singapore IMDA Agentic AI Governance Report" in md
        assert "## Executive Summary" in md
        assert "## Evidence Summary" in md
        assert "## Governance Dimension Scores" in md
        assert "## Risk Category Assessment" in md
        assert "## Recommendations" in md
        assert "## Scan Metadata" in md

    def test_contains_disclaimer(self, sample_report):
        md = IMDAReporter().generate_markdown(sample_report)
        assert "does not constitute regulatory or legal advice" in md

    def test_contains_dimension_names(self, sample_report):
        md = IMDAReporter().generate_markdown(sample_report)
        assert "Risk Bounding" in md
        assert "Human Accountability" in md
        assert "Technical Controls" in md
        assert "Transparency" in md

    def test_contains_risk_category_names(self, sample_report):
        md = IMDAReporter().generate_markdown(sample_report)
        assert "Erroneous Actions" in md
        assert "Unauthorized Actions" in md


# ---------------------------------------------------------------------------
# Empty report
# ---------------------------------------------------------------------------


class TestEmptyReport:
    def test_empty_generates(self, empty_report):
        result = IMDAReporter().generate(empty_report)
        assert result["evidence_summary"]["total_scenarios"] == 0
        assert result["evidence_summary"]["vulnerability_rate"] == 0.0

    def test_empty_markdown(self, empty_report):
        md = IMDAReporter().generate_markdown(empty_report)
        assert isinstance(md, str)
        assert len(md) > 0

    def test_empty_risk_categories_zero_tested(self, empty_report):
        result = IMDAReporter().generate(empty_report)
        for cat_data in result["risk_category_assessment"].values():
            assert cat_data["scenarios_tested"] == 0
            assert cat_data["vulnerabilities_found"] == 0

    def test_empty_recommendations_info(self, empty_report):
        result = IMDAReporter().generate(empty_report)
        recs = result["recommendations"]
        info_recs = [r for r in recs if r["priority"] == "INFO"]
        # Should have INFO recommendations for untested risk categories
        assert len(info_recs) > 0
