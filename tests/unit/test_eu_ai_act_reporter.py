"""Unit tests for EU AI Act Article 50 compliance reporter."""

from __future__ import annotations

import json
from pathlib import Path

from aastf.compliance.eu_ai_act import EU_AI_ACT_ARTICLE_MAPPING, EUAIActReporter
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
    scenario_name: str = "Test finding",
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name=scenario_name,
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
        "aastf_version": "0.5.0",
        "adapter": "test",
        "total_scenarios": len(results) or len(findings) or 0,
        "vulnerable": sum(1 for f in findings if f.verdict == Verdict.VULNERABLE),
        "safe": sum(1 for r in results if r.verdict == Verdict.SAFE),
    }
    defaults.update(kwargs)
    return ScanReport(
        findings=findings,
        results=results,
        **defaults,
    )


# ---------------------------------------------------------------------------
# Article mapping completeness
# ---------------------------------------------------------------------------


class TestArticleMapping:
    """All 10 ASI categories must be represented in the mapping."""

    def test_all_asi_categories_mapped(self):
        for cat in ASICategory:
            assert cat in EU_AI_ACT_ARTICLE_MAPPING or cat.value in EU_AI_ACT_ARTICLE_MAPPING, (
                f"{cat.value} not found in EU_AI_ACT_ARTICLE_MAPPING"
            )

    def test_each_mapping_has_required_fields(self):
        required_keys = {"article_number", "article_title", "requirement", "how_aastf_tests_it"}
        for cat, mappings in EU_AI_ACT_ARTICLE_MAPPING.items():
            assert isinstance(mappings, list), f"Mapping for {cat} should be a list"
            assert len(mappings) > 0, f"Mapping for {cat} should have at least one article"
            for mapping in mappings:
                assert required_keys <= set(mapping.keys()), (
                    f"Mapping for {cat} missing keys: {required_keys - set(mapping.keys())}"
                )

    def test_article_50_articles_present(self):
        """Article 50 sub-articles must appear in the mapping."""
        all_articles = set()
        for mappings in EU_AI_ACT_ARTICLE_MAPPING.values():
            for m in mappings:
                all_articles.add(m["article_number"])

        assert "Art. 50(1)" in all_articles
        assert "Art. 50(2)" in all_articles
        assert "Art. 50(3)" in all_articles
        assert "Art. 50(4)" in all_articles

    def test_asi09_maps_to_article_50(self):
        """ASI09 (Trust Exploitation) must map to Article 50 transparency."""
        mappings = EU_AI_ACT_ARTICLE_MAPPING[ASICategory.ASI09]
        articles = {m["article_number"] for m in mappings}
        assert "Art. 50(1)" in articles
        assert "Art. 50(2)" in articles


# ---------------------------------------------------------------------------
# generate() output structure
# ---------------------------------------------------------------------------


class TestGenerate:
    def test_output_has_required_keys(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        expected_keys = {
            "report_metadata",
            "overall_readiness",
            "article_50_assessment",
            "per_article_findings",
            "asi_to_article_mapping",
            "recommendations",
            "evidence_summary",
        }
        assert expected_keys <= set(result.keys())

    def test_report_metadata(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        meta = result["report_metadata"]
        assert meta["framework"] == "aastf"
        assert meta["aastf_version"] == "0.5.0"
        assert meta["run_id"] == report.run_id
        assert meta["report_type"] == "eu_ai_act_article_50"

    def test_evidence_summary_counts(self):
        findings = [
            _finding(severity=Severity.HIGH, verdict=Verdict.VULNERABLE),
            _finding(severity=Severity.MEDIUM, verdict=Verdict.VULNERABLE, scenario_id="ASI02-002"),
        ]
        results = [
            _test_result(verdict=Verdict.SAFE),
            _test_result(verdict=Verdict.SAFE, scenario_id="ASI02-002"),
            _test_result(verdict=Verdict.SAFE, scenario_id="ASI02-003"),
        ]
        report = _report(
            findings=findings,
            results=results,
            total_scenarios=3,
            vulnerable=2,
            safe=1,
        )
        result = EUAIActReporter().generate(report)
        evidence = result["evidence_summary"]
        assert evidence["total_scenarios"] == 3
        assert evidence["vulnerable"] == 2
        assert evidence["safe"] == 1

    def test_article_50_assessment_structure(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        a50 = result["article_50_assessment"]
        assert isinstance(a50, list)
        assert len(a50) == 4  # Art. 50(1) through 50(4)
        for item in a50:
            assert "article_number" in item
            assert "status" in item
            assert item["status"] in ("pass", "fail", "not_tested")

    def test_asi_to_article_mapping_has_all_categories(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        mapping = result["asi_to_article_mapping"]
        for cat in ASICategory:
            assert cat.value in mapping


# ---------------------------------------------------------------------------
# Empty report
# ---------------------------------------------------------------------------


class TestEmptyReport:
    def test_empty_report_is_compliant(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        assert result["overall_readiness"]["status"] == "compliant"

    def test_empty_report_all_articles_not_tested(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        for item in result["article_50_assessment"]:
            assert item["status"] == "not_tested"

    def test_empty_report_zero_counts(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        evidence = result["evidence_summary"]
        assert evidence["total_scenarios"] == 0
        assert evidence["vulnerable"] == 0
        assert evidence["vulnerability_rate"] == 0.0

    def test_empty_report_has_recommendations(self):
        """Empty report should recommend expanding coverage."""
        report = _report()
        result = EUAIActReporter().generate(report)
        recs = result["recommendations"]
        # Should have recommendations for untested categories
        assert len(recs) > 0
        info_recs = [r for r in recs if r["priority"] == "INFO"]
        assert len(info_recs) > 0


# ---------------------------------------------------------------------------
# Mixed findings
# ---------------------------------------------------------------------------


class TestMixedFindings:
    def test_mixed_vulnerable_and_safe(self):
        findings = [
            _finding(
                category=ASICategory.ASI09,
                severity=Severity.HIGH,
                verdict=Verdict.VULNERABLE,
                scenario_id="ASI09-001",
                scenario_name="Trust exploit",
            ),
        ]
        results = [
            _test_result(
                category=ASICategory.ASI09,
                verdict=Verdict.VULNERABLE,
                scenario_id="ASI09-001",
            ),
            _test_result(
                category=ASICategory.ASI09,
                verdict=Verdict.SAFE,
                scenario_id="ASI09-002",
            ),
        ]
        report = _report(
            findings=findings,
            results=results,
            total_scenarios=2,
            vulnerable=1,
            safe=1,
        )
        result = EUAIActReporter().generate(report)

        # Article 50(1) should fail (ASI09 vulnerable)
        a50 = result["article_50_assessment"]
        art_50_1 = next(a for a in a50 if a["article_number"] == "Art. 50(1)")
        assert art_50_1["status"] == "fail"
        assert len(art_50_1["findings"]) == 1

    def test_refusal_echo_findings_included(self):
        findings = [
            _finding(
                category=ASICategory.ASI09,
                severity=Severity.HIGH,
                verdict=Verdict.REFUSAL_ECHO,
                scenario_id="ASI09-001",
            ),
        ]
        results = [
            _test_result(
                category=ASICategory.ASI09,
                verdict=Verdict.SAFE,
                scenario_id="ASI09-001",
            ),
        ]
        report = _report(findings=findings, results=results, total_scenarios=1, safe=1)
        result = EUAIActReporter().generate(report)

        # REFUSAL_ECHO is not VULNERABLE so Art 50(1) should pass
        a50 = result["article_50_assessment"]
        art_50_1 = next(a for a in a50 if a["article_number"] == "Art. 50(1)")
        assert art_50_1["status"] == "pass"
        assert len(art_50_1["findings"]) == 1  # still listed as finding

    def test_per_article_findings_groups_correctly(self):
        findings = [
            _finding(
                category=ASICategory.ASI09,
                severity=Severity.HIGH,
                verdict=Verdict.VULNERABLE,
                scenario_id="ASI09-001",
            ),
            _finding(
                category=ASICategory.ASI01,
                severity=Severity.MEDIUM,
                verdict=Verdict.VULNERABLE,
                scenario_id="ASI01-001",
            ),
        ]
        report = _report(findings=findings, total_scenarios=2, vulnerable=2)
        result = EUAIActReporter().generate(report)
        per_article = result["per_article_findings"]

        # Art. 50(3) should have findings from both ASI01 and ASI09
        art_50_3 = per_article.get("Art. 50(3)")
        assert art_50_3 is not None
        categories_in_50_3 = {f["category"] for f in art_50_3["findings"]}
        assert "ASI01" in categories_in_50_3
        assert "ASI09" in categories_in_50_3


# ---------------------------------------------------------------------------
# Readiness levels
# ---------------------------------------------------------------------------


class TestReadinessLevels:
    def test_compliant_no_findings(self):
        report = _report()
        result = EUAIActReporter().generate(report)
        assert result["overall_readiness"]["status"] == "compliant"

    def test_compliant_medium_findings(self):
        findings = [
            _finding(severity=Severity.MEDIUM, verdict=Verdict.VULNERABLE),
        ]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        result = EUAIActReporter().generate(report)
        assert result["overall_readiness"]["status"] == "compliant"

    def test_at_risk_high_vulnerable(self):
        findings = [
            _finding(severity=Severity.HIGH, verdict=Verdict.VULNERABLE),
        ]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        result = EUAIActReporter().generate(report)
        assert result["overall_readiness"]["status"] == "at_risk"

    def test_at_risk_critical_refusal_echo(self):
        findings = [
            _finding(severity=Severity.CRITICAL, verdict=Verdict.REFUSAL_ECHO),
        ]
        report = _report(findings=findings, total_scenarios=1)
        result = EUAIActReporter().generate(report)
        assert result["overall_readiness"]["status"] == "at_risk"

    def test_non_compliant_critical_vulnerable(self):
        findings = [
            _finding(severity=Severity.CRITICAL, verdict=Verdict.VULNERABLE),
        ]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        result = EUAIActReporter().generate(report)
        assert result["overall_readiness"]["status"] == "non_compliant"

    def test_readiness_display_info(self):
        findings = [
            _finding(severity=Severity.CRITICAL, verdict=Verdict.VULNERABLE),
        ]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        result = EUAIActReporter().generate(report)
        readiness = result["overall_readiness"]
        assert readiness["label"] == "NON-COMPLIANT"
        assert "description" in readiness


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_markdown_contains_key_sections(self):
        findings = [
            _finding(
                category=ASICategory.ASI09,
                severity=Severity.HIGH,
                verdict=Verdict.VULNERABLE,
                scenario_id="ASI09-001",
                scenario_name="Trust exploit test",
            ),
        ]
        results = [
            _test_result(
                category=ASICategory.ASI09,
                verdict=Verdict.VULNERABLE,
                scenario_id="ASI09-001",
            ),
        ]
        report = _report(
            findings=findings,
            results=results,
            total_scenarios=1,
            vulnerable=1,
        )
        md = EUAIActReporter().generate_markdown(report)

        assert "# EU AI Act Compliance Report" in md
        assert "## Executive Summary" in md
        assert "## Evidence Summary" in md
        assert "## Article 50 Transparency Assessment" in md
        assert "## Per-Article Findings" in md
        assert "## ASI Category Coverage Matrix" in md
        assert "## Recommendations" in md
        assert "## Scan Metadata" in md

    def test_markdown_contains_readiness_status(self):
        report = _report()
        md = EUAIActReporter().generate_markdown(report)
        assert "COMPLIANT" in md

    def test_markdown_contains_article_50_sections(self):
        report = _report()
        md = EUAIActReporter().generate_markdown(report)
        assert "Art. 50(1)" in md
        assert "Art. 50(2)" in md
        assert "Art. 50(3)" in md
        assert "Art. 50(4)" in md

    def test_markdown_shows_enforcement_date(self):
        report = _report()
        md = EUAIActReporter().generate_markdown(report)
        assert "2 August 2026" in md

    def test_markdown_empty_report(self):
        report = _report()
        md = EUAIActReporter().generate_markdown(report)
        assert "NOT TESTED" in md
        assert "does not constitute legal advice" in md


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


class TestJSON:
    def test_generate_json_is_valid(self):
        report = _report()
        json_str = EUAIActReporter().generate_json(report)
        parsed = json.loads(json_str)
        assert "report_metadata" in parsed
        assert "overall_readiness" in parsed

    def test_generate_json_roundtrip(self):
        findings = [
            _finding(severity=Severity.HIGH, verdict=Verdict.VULNERABLE),
        ]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        json_str = EUAIActReporter().generate_json(report)
        parsed = json.loads(json_str)
        assert parsed["overall_readiness"]["status"] == "at_risk"


# ---------------------------------------------------------------------------
# write() creates file
# ---------------------------------------------------------------------------


class TestWrite:
    def test_write_creates_file(self, tmp_path: Path):
        report = _report()
        output_path = tmp_path / "compliance" / "eu-ai-act.json"
        result_path = EUAIActReporter().write(report, output_path)
        assert result_path == output_path
        assert output_path.exists()

        content = json.loads(output_path.read_text(encoding="utf-8"))
        assert "report_metadata" in content
        assert content["overall_readiness"]["status"] == "compliant"

    def test_write_creates_parent_dirs(self, tmp_path: Path):
        report = _report()
        output_path = tmp_path / "deep" / "nested" / "dir" / "report.json"
        EUAIActReporter().write(report, output_path)
        assert output_path.exists()


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


class TestRecommendations:
    def test_critical_finding_generates_critical_recommendation(self):
        findings = [
            _finding(severity=Severity.CRITICAL, verdict=Verdict.VULNERABLE),
        ]
        report = _report(findings=findings, total_scenarios=1, vulnerable=1)
        result = EUAIActReporter().generate(report)
        recs = result["recommendations"]
        critical_recs = [r for r in recs if r["priority"] == "CRITICAL"]
        assert len(critical_recs) >= 1

    def test_refusal_echo_generates_medium_recommendation(self):
        findings = [
            _finding(severity=Severity.HIGH, verdict=Verdict.REFUSAL_ECHO),
        ]
        report = _report(findings=findings, total_scenarios=1)
        result = EUAIActReporter().generate(report)
        recs = result["recommendations"]
        medium_recs = [r for r in recs if r["priority"] == "MEDIUM"]
        assert len(medium_recs) >= 1
        assert "refusal" in medium_recs[0]["recommendation"].lower() or "sanitise" in medium_recs[0]["recommendation"].lower()

    def test_untested_asi09_generates_high_recommendation(self):
        """If ASI09 is not tested, there should be a high-priority recommendation."""
        report = _report()
        result = EUAIActReporter().generate(report)
        recs = result["recommendations"]
        asi09_recs = [r for r in recs if r.get("asi_category") == "ASI09" and r["priority"] == "HIGH"]
        assert len(asi09_recs) >= 1
        assert "Article 50" in asi09_recs[0]["recommendation"]
