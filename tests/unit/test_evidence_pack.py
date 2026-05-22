"""Unit tests for EU AI Act evidence pack bundler."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from aastf.compliance.evidence_pack import EvidencePackBuilder
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
    """Build a ScanReport with findings across multiple categories."""
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


def _read_manifest(zip_path: Path) -> dict:
    """Extract and parse manifest.json from a ZIP."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        manifest_name = [n for n in zf.namelist() if n.endswith("manifest.json")][0]
        return json.loads(zf.read(manifest_name))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEvidencePackBuild:
    def test_build_creates_zip(self, sample_report, tmp_path):
        output = tmp_path / "evidence.zip"
        result = EvidencePackBuilder().build(sample_report, output)
        assert result.exists()
        assert zipfile.is_zipfile(result)

    def test_zip_contains_expected_structure(self, sample_report, tmp_path):
        output = tmp_path / "evidence.zip"
        EvidencePackBuilder().build(sample_report, output)

        with zipfile.ZipFile(output, "r") as zf:
            names = zf.namelist()

        # Summary directory with EU AI Act reports
        assert any("summary/eu-ai-act-report.json" in n for n in names)
        assert any("summary/eu-ai-act-report.md" in n for n in names)
        assert any("manifest.json" in n for n in names)

        # Article directories
        assert any("art9/" in n for n in names)
        assert any("art11/" in n for n in names)
        assert any("art12/" in n for n in names)
        assert any("art13/" in n for n in names)
        assert any("art14/" in n for n in names)
        assert any("art15/" in n for n in names)

    def test_manifest_has_file_checksums(self, sample_report, tmp_path):
        output = tmp_path / "evidence.zip"
        EvidencePackBuilder().build(sample_report, output)
        manifest = _read_manifest(output)

        assert "files" in manifest
        files = manifest["files"]
        assert len(files) > 0
        # Each file record should have sha256 and size_bytes
        for key, record in files.items():
            assert "sha256" in record, f"File record for {key} missing sha256"
            assert "size_bytes" in record, f"File record for {key} missing size_bytes"
            assert len(record["sha256"]) == 64  # SHA-256 hex digest

    def test_manifest_has_conformity_score(self, sample_report, tmp_path):
        output = tmp_path / "evidence.zip"
        EvidencePackBuilder().build(sample_report, output)
        manifest = _read_manifest(output)

        assert "conformity_score" in manifest
        score = manifest["conformity_score"]
        assert isinstance(score, dict)
        assert "overall" in score
        assert "per_article" in score

    def test_manifest_has_articles_included(self, sample_report, tmp_path):
        output = tmp_path / "evidence.zip"
        EvidencePackBuilder().build(sample_report, output)
        manifest = _read_manifest(output)

        assert manifest["articles_included"] == ["11", "12", "13", "14", "15", "9"]

    def test_manifest_run_id(self, sample_report, tmp_path):
        output = tmp_path / "evidence.zip"
        EvidencePackBuilder().build(sample_report, output)
        manifest = _read_manifest(output)

        assert manifest["run_id"] == sample_report.run_id


class TestSelectiveArticles:
    def test_only_art9_and_art15(self, sample_report, tmp_path):
        output = tmp_path / "selective.zip"
        EvidencePackBuilder().build(sample_report, output, articles=["9", "15"])

        with zipfile.ZipFile(output, "r") as zf:
            names = zf.namelist()

        manifest = _read_manifest(output)

        # Should include art9 and art15 directories
        assert any("art9/" in n for n in names)
        assert any("art15/" in n for n in names)
        # Should NOT include art11, art12, art13, art14
        assert not any("art11/" in n for n in names)
        assert not any("art12/" in n for n in names)
        assert not any("art13/" in n for n in names)
        assert not any("art14/" in n for n in names)

        assert manifest["articles_included"] == ["15", "9"]

    def test_single_article(self, sample_report, tmp_path):
        output = tmp_path / "single.zip"
        EvidencePackBuilder().build(sample_report, output, articles=["12"])

        with zipfile.ZipFile(output, "r") as zf:
            names = zf.namelist()

        assert any("art12/" in n for n in names)
        assert not any("art9/" in n for n in names)


class TestConformityScore:
    def test_all_safe_nonzero_score(self, tmp_path):
        """When all tested categories are safe, overall score should be > 0."""
        results = []
        for cat in ASICategory:
            results.append(_test_result(cat, Severity.HIGH, Verdict.SAFE, f"{cat.value}-001"))
        report = _report(results=results, total_scenarios=10, safe=10)
        output = tmp_path / "all-safe.zip"
        EvidencePackBuilder().build(report, output)
        manifest = _read_manifest(output)

        assert manifest["conformity_score"]["overall"] > 0.0

    def test_vulnerable_reduces_score(self, tmp_path):
        """Vulnerable findings should reduce conformity score."""
        results_safe = []
        for cat in ASICategory:
            results_safe.append(_test_result(cat, Severity.HIGH, Verdict.SAFE, f"{cat.value}-001"))
        report_safe = _report(results=results_safe, total_scenarios=10, safe=10)

        results_vuln = list(results_safe)
        # Make ASI01 vulnerable
        results_vuln[0] = _test_result(ASICategory.ASI01, Severity.HIGH, Verdict.VULNERABLE, "ASI01-001")
        report_vuln = _report(
            results=results_vuln,
            total_scenarios=10, vulnerable=1, safe=9,
        )

        output_safe = tmp_path / "safe.zip"
        output_vuln = tmp_path / "vuln.zip"
        EvidencePackBuilder().build(report_safe, output_safe)
        EvidencePackBuilder().build(report_vuln, output_vuln)

        score_safe = _read_manifest(output_safe)["conformity_score"]["overall"]
        score_vuln = _read_manifest(output_vuln)["conformity_score"]["overall"]

        assert score_vuln < score_safe

    def test_per_article_scores_present(self, sample_report, tmp_path):
        output = tmp_path / "per-art.zip"
        EvidencePackBuilder().build(sample_report, output)
        manifest = _read_manifest(output)
        per_article = manifest["conformity_score"]["per_article"]
        # Should have entries for all included articles
        assert "art9" in per_article
        assert "art15" in per_article


class TestEmptyReportPack:
    def test_empty_report_creates_valid_zip(self, empty_report, tmp_path):
        output = tmp_path / "empty.zip"
        result = EvidencePackBuilder().build(empty_report, output)
        assert result.exists()
        assert zipfile.is_zipfile(result)

    def test_empty_report_has_manifest(self, empty_report, tmp_path):
        output = tmp_path / "empty.zip"
        EvidencePackBuilder().build(empty_report, output)

        with zipfile.ZipFile(output, "r") as zf:
            names = zf.namelist()
        assert any("manifest.json" in n for n in names)

    def test_creates_parent_directories(self, empty_report, tmp_path):
        output = tmp_path / "deep" / "nested" / "pack.zip"
        result = EvidencePackBuilder().build(empty_report, output)
        assert result.exists()

    def test_empty_conformity_zero(self, empty_report, tmp_path):
        output = tmp_path / "empty.zip"
        EvidencePackBuilder().build(empty_report, output)
        manifest = _read_manifest(output)
        assert manifest["conformity_score"]["overall"] == 0.0


class TestZipFileContents:
    def test_eu_ai_act_report_json_valid(self, sample_report, tmp_path):
        output = tmp_path / "content.zip"
        EvidencePackBuilder().build(sample_report, output)

        with zipfile.ZipFile(output, "r") as zf:
            report_name = [n for n in zf.namelist() if "eu-ai-act-report.json" in n][0]
            data = json.loads(zf.read(report_name))

        assert "report_metadata" in data
        assert "overall_readiness" in data

    def test_art9_csv_present(self, sample_report, tmp_path):
        output = tmp_path / "csv.zip"
        EvidencePackBuilder().build(sample_report, output)

        with zipfile.ZipFile(output, "r") as zf:
            csv_files = [n for n in zf.namelist() if "risk-register.csv" in n]
        assert len(csv_files) == 1

    def test_art12_ndjson_present(self, sample_report, tmp_path):
        output = tmp_path / "ndjson.zip"
        EvidencePackBuilder().build(sample_report, output)

        with zipfile.ZipFile(output, "r") as zf:
            ndjson_files = [n for n in zf.namelist() if "event-log.ndjson" in n]
        assert len(ndjson_files) == 1
