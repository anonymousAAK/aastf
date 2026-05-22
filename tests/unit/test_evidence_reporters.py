"""Unit tests for article-specific EU AI Act evidence reporters."""

from __future__ import annotations

import csv
import json

import pytest

from aastf.compliance.evidence_reporters import (
    Article9RiskRegister,
    Article11TechDoc,
    Article12AutoLog,
    Article13TransparencyDeclaration,
    Article14OversightChecklist,
    Article15TestMatrix,
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
    scenario_name: str = "Test scenario",
    tool_names: list[str] | None = None,
) -> TestResult:
    trace = AgentTrace(scenario_id=scenario_id, adapter="test")
    if tool_names:
        from aastf.models.trace import ToolInvocation

        trace.tool_invocations = [ToolInvocation(tool_name=t) for t in tool_names]
    return TestResult(
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        category=category,
        severity=severity,
        verdict=verdict,
        trace=trace,
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
    return ScanReport(
        findings=findings,
        results=results,
        **defaults,
    )


@pytest.fixture()
def sample_report() -> ScanReport:
    """Build a minimal ScanReport with findings across multiple categories."""
    results = [
        _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001",
                      tool_names=["send_email", "read_file"]),
        _test_result(ASICategory.ASI01, Severity.MEDIUM, Verdict.SAFE, "ASI01-002"),
        _test_result(ASICategory.ASI03, Severity.HIGH, Verdict.SAFE, "ASI03-001"),
        _test_result(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, "ASI05-001",
                      tool_names=["exec_code"]),
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
# Article 9 - Risk Register
# ---------------------------------------------------------------------------


class TestArticle9RiskRegister:
    def test_generate_returns_list(self, sample_report):
        rows = Article9RiskRegister().generate(sample_report)
        assert isinstance(rows, list)
        assert len(rows) == 5  # one per TestResult

    def test_row_has_required_fields(self, sample_report):
        rows = Article9RiskRegister().generate(sample_report)
        required = {
            "risk_id", "asi_category", "scenario_id", "scenario_name",
            "severity", "verdict", "mitigation_status", "residual_risk_score",
            "last_tested",
        }
        for row in rows:
            assert required <= set(row.keys())

    def test_risk_ids_are_sequential(self, sample_report):
        rows = Article9RiskRegister().generate(sample_report)
        ids = [r["risk_id"] for r in rows]
        assert ids == ["RISK-0001", "RISK-0002", "RISK-0003", "RISK-0004", "RISK-0005"]

    def test_mitigated_residual_score_reduced(self, sample_report):
        rows = Article9RiskRegister().generate(sample_report)
        safe_rows = [r for r in rows if r["mitigation_status"] == "mitigated"]
        for row in safe_rows:
            # Mitigated score should be 10% of base
            assert row["residual_risk_score"] < 2.0

    def test_vulnerable_has_open_status(self, sample_report):
        rows = Article9RiskRegister().generate(sample_report)
        vuln_rows = [r for r in rows if r["verdict"] == "VULNERABLE"]
        for row in vuln_rows:
            assert row["mitigation_status"] == "open"

    def test_to_csv_creates_valid_csv(self, sample_report, tmp_path):
        path = tmp_path / "risk-register.csv"
        result_path = Article9RiskRegister().to_csv(sample_report, path)
        assert result_path == path
        assert path.exists()

        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert len(rows) == 5
        assert "risk_id" in rows[0]

    def test_empty_report(self, empty_report):
        rows = Article9RiskRegister().generate(empty_report)
        assert rows == []

    def test_to_csv_empty_report(self, empty_report, tmp_path):
        path = tmp_path / "empty.csv"
        Article9RiskRegister().to_csv(empty_report, path)
        assert path.exists()
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        assert rows == []


# ---------------------------------------------------------------------------
# Article 11 - Technical Documentation
# ---------------------------------------------------------------------------


class TestArticle11TechDoc:
    def test_generate_returns_dict(self, sample_report):
        data = Article11TechDoc().generate(sample_report)
        assert isinstance(data, dict)

    def test_required_json_fields(self, sample_report):
        data = Article11TechDoc().generate(sample_report)
        required = {
            "system_description", "aastf_version", "intended_purpose",
            "known_limitations", "test_methodology", "scenario_coverage",
            "risk_assessment_summary",
        }
        assert required <= set(data.keys())

    def test_risk_assessment_summary_fields(self, sample_report):
        data = Article11TechDoc().generate(sample_report)
        summary = data["risk_assessment_summary"]
        assert "total_scenarios_tested" in summary
        assert "vulnerability_rate_percent" in summary
        assert "critical_findings" in summary
        assert "eu_ai_act_readiness" in summary

    def test_limitations_lists_vulnerable_categories(self, sample_report):
        data = Article11TechDoc().generate(sample_report)
        limitations = data["known_limitations"]
        assert isinstance(limitations, list)
        # ASI01 and ASI05 are vulnerable
        assert len(limitations) >= 2

    def test_scenario_coverage_counts_categories(self, sample_report):
        data = Article11TechDoc().generate(sample_report)
        coverage = data["scenario_coverage"]
        assert "ASI01" in coverage
        assert coverage["ASI01"] == 2

    def test_empty_report(self, empty_report):
        data = Article11TechDoc().generate(empty_report)
        assert data["known_limitations"] == []
        assert data["scenario_coverage"] == {}
        assert data["risk_assessment_summary"]["total_scenarios_tested"] == 0


# ---------------------------------------------------------------------------
# Article 12 - Automatic Logging
# ---------------------------------------------------------------------------


class TestArticle12AutoLog:
    def test_generate_returns_list_of_dicts(self, sample_report):
        entries = Article12AutoLog().generate(sample_report)
        assert isinstance(entries, list)
        # 5 results + 3 tool invocations = 8 entries
        assert len(entries) >= 5

    def test_entry_fields(self, sample_report):
        entries = Article12AutoLog().generate(sample_report)
        required = {
            "timestamp", "event_type", "scenario_id",
            "verdict", "retention_days",
        }
        for entry in entries:
            assert required <= set(entry.keys())

    def test_event_types(self, sample_report):
        entries = Article12AutoLog().generate(sample_report)
        event_types = {e["event_type"] for e in entries}
        assert "evaluation" in event_types

    def test_tool_call_entries(self, sample_report):
        entries = Article12AutoLog().generate(sample_report)
        tool_entries = [e for e in entries if e["event_type"] == "tool_call"]
        assert len(tool_entries) >= 1

    def test_decision_path_populated(self, sample_report):
        entries = Article12AutoLog().generate(sample_report)
        eval_entries = [e for e in entries if e["event_type"] == "evaluation"]
        asi01 = [e for e in eval_entries if e["scenario_id"] == "ASI01-001"][0]
        assert asi01["agent_decision_path"] == "send_email -> read_file"

    def test_no_tool_calls_path(self, sample_report):
        entries = Article12AutoLog().generate(sample_report)
        eval_entries = [e for e in entries if e["event_type"] == "evaluation"]
        asi01_002 = [e for e in eval_entries if e["scenario_id"] == "ASI01-002"][0]
        assert asi01_002["agent_decision_path"] == "no_tool_calls"

    def test_retention_days_default(self, sample_report):
        entries = Article12AutoLog().generate(sample_report)
        for entry in entries:
            assert entry["retention_days"] == 180

    def test_to_ndjson_creates_valid_ndjson(self, sample_report, tmp_path):
        path = tmp_path / "auto-log.ndjson"
        result_path = Article12AutoLog().to_ndjson(sample_report, path)
        assert result_path == path
        assert path.exists()

        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) >= 5
        for line in lines:
            parsed = json.loads(line)
            assert "scenario_id" in parsed

    def test_empty_report(self, empty_report):
        entries = Article12AutoLog().generate(empty_report)
        assert entries == []

    def test_to_ndjson_empty(self, empty_report, tmp_path):
        path = tmp_path / "empty.ndjson"
        Article12AutoLog().to_ndjson(empty_report, path)
        content = path.read_text(encoding="utf-8")
        assert content == ""


# ---------------------------------------------------------------------------
# Article 13 - Transparency Declaration
# ---------------------------------------------------------------------------


class TestArticle13TransparencyDeclaration:
    def test_generate_returns_dict(self, sample_report):
        data = Article13TransparencyDeclaration().generate(sample_report)
        assert isinstance(data, dict)

    def test_required_fields(self, sample_report):
        data = Article13TransparencyDeclaration().generate(sample_report)
        required = {
            "system_name", "capabilities_tested", "known_limitations",
            "ai_generated_content_disclosure",
            "human_oversight_mechanisms_tested", "test_summary",
        }
        assert required <= set(data.keys())

    def test_to_markdown_returns_string(self, sample_report):
        md = Article13TransparencyDeclaration().to_markdown(sample_report)
        assert isinstance(md, str)
        assert len(md) > 0

    def test_markdown_has_required_sections(self, sample_report):
        md = Article13TransparencyDeclaration().to_markdown(sample_report)
        assert "# Transparency Declaration" in md
        assert "## System Overview" in md
        assert "## Capabilities Tested" in md
        assert "## Known Limitations" in md
        assert "## AI-Generated Content Disclosure" in md
        assert "## Human Oversight Mechanisms Tested" in md
        assert "## Test Summary" in md

    def test_markdown_contains_disclaimer(self, sample_report):
        md = Article13TransparencyDeclaration().to_markdown(sample_report)
        assert "does not constitute legal advice" in md

    def test_empty_report_markdown(self, empty_report):
        md = Article13TransparencyDeclaration().to_markdown(empty_report)
        assert "No capabilities were tested" in md
        assert "No vulnerabilities were detected" in md

    def test_empty_report_generates(self, empty_report):
        data = Article13TransparencyDeclaration().generate(empty_report)
        assert data["capabilities_tested"] == []
        assert data["known_limitations"] == []


# ---------------------------------------------------------------------------
# Article 14 - Human Oversight Checklist
# ---------------------------------------------------------------------------


class TestArticle14OversightChecklist:
    def test_generate_returns_list(self, sample_report):
        checklist = Article14OversightChecklist().generate(sample_report)
        assert isinstance(checklist, list)

    def test_entry_has_required_fields(self, sample_report):
        checklist = Article14OversightChecklist().generate(sample_report)
        required = {
            "category", "category_name", "oversight_requirement",
            "scenarios_tested", "human_review_required",
            "escalation_threshold", "override_mechanism_tested",
        }
        for entry in checklist:
            assert required <= set(entry.keys())

    def test_vulnerable_category_requires_review(self, sample_report):
        checklist = Article14OversightChecklist().generate(sample_report)
        asi01 = [c for c in checklist if c["category"] == "ASI01"][0]
        assert asi01["human_review_required"] is True

    def test_safe_category_no_review(self, sample_report):
        checklist = Article14OversightChecklist().generate(sample_report)
        asi03 = [c for c in checklist if c["category"] == "ASI03"][0]
        assert asi03["human_review_required"] is False

    def test_critical_escalation_threshold(self):
        results = [
            _test_result(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, "ASI05-001"),
        ]
        findings = [
            _finding(ASICategory.ASI05, Severity.CRITICAL, Verdict.VULNERABLE, "ASI05-001"),
        ]
        report = _report(results=results, findings=findings, total_scenarios=1, vulnerable=1)
        checklist = Article14OversightChecklist().generate(report)
        asi05 = [c for c in checklist if c["category"] == "ASI05"][0]
        assert asi05["escalation_threshold"] == "immediate"

    def test_no_override_mechanism_when_asi10_absent(self, sample_report):
        checklist = Article14OversightChecklist().generate(sample_report)
        for entry in checklist:
            assert entry["override_mechanism_tested"] is False

    def test_override_mechanism_when_asi10_present(self):
        results = [
            _test_result(ASICategory.ASI10, Severity.HIGH, Verdict.SAFE, "ASI10-001"),
            _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.SAFE, "ASI01-001"),
        ]
        report = _report(results=results, total_scenarios=2, safe=2)
        checklist = Article14OversightChecklist().generate(report)
        for entry in checklist:
            assert entry["override_mechanism_tested"] is True

    def test_empty_report(self, empty_report):
        checklist = Article14OversightChecklist().generate(empty_report)
        assert checklist == []


# ---------------------------------------------------------------------------
# Article 15 - Test Matrix
# ---------------------------------------------------------------------------


class TestArticle15TestMatrix:
    def test_generate_returns_dict(self, sample_report):
        matrix = Article15TestMatrix().generate(sample_report)
        assert isinstance(matrix, dict)

    def test_three_domains_plus_overall(self, sample_report):
        matrix = Article15TestMatrix().generate(sample_report)
        assert "accuracy" in matrix
        assert "robustness" in matrix
        assert "cybersecurity" in matrix
        assert "overall" in matrix

    def test_domain_has_required_fields(self, sample_report):
        matrix = Article15TestMatrix().generate(sample_report)
        required = {"pass_rate", "scenarios_tested", "vulnerabilities_found", "coverage_score"}
        for domain in ["accuracy", "robustness", "cybersecurity"]:
            assert required <= set(matrix[domain].keys())

    def test_accuracy_categories(self, sample_report):
        matrix = Article15TestMatrix().generate(sample_report)
        acc = matrix["accuracy"]
        # ASI01 and ASI09 are accuracy categories
        assert "ASI01" in acc["categories_included"]
        assert "ASI09" in acc["categories_included"]

    def test_pass_rate_computation(self):
        results = [
            _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.SAFE, "ASI01-001"),
            _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.SAFE, "ASI01-002"),
            _test_result(ASICategory.ASI09, Severity.HIGH, Verdict.VULNERABLE, "ASI09-001"),
        ]
        report = _report(results=results, total_scenarios=3, safe=2, vulnerable=1)
        matrix = Article15TestMatrix().generate(report)
        # 2 safe out of 3 total accuracy results = 66.7%
        assert matrix["accuracy"]["pass_rate"] == 66.7

    def test_coverage_score(self):
        results = [
            _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.SAFE, "ASI01-001"),
        ]
        report = _report(results=results, total_scenarios=1, safe=1)
        matrix = Article15TestMatrix().generate(report)
        # Only ASI01 tested out of {ASI01, ASI09} = 50.0% coverage
        assert matrix["accuracy"]["coverage_score"] == 50.0

    def test_cybersecurity_categories(self, sample_report):
        matrix = Article15TestMatrix().generate(sample_report)
        cyber = matrix["cybersecurity"]
        expected = {"ASI02", "ASI03", "ASI04", "ASI05", "ASI07", "ASI10"}
        assert set(cyber["categories_included"]) == expected

    def test_empty_report(self, empty_report):
        matrix = Article15TestMatrix().generate(empty_report)
        for domain in ["accuracy", "robustness", "cybersecurity"]:
            assert matrix[domain]["pass_rate"] == 0.0
            assert matrix[domain]["scenarios_tested"] == 0
        assert matrix["overall"]["pass_rate"] == 0.0
        assert matrix["overall"]["coverage_score"] == 0.0

    def test_overall_aggregates_all(self, sample_report):
        matrix = Article15TestMatrix().generate(sample_report)
        overall = matrix["overall"]
        assert overall["scenarios_tested"] == 5
