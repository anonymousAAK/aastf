"""Tests for AI-VSS scoring, CWE mapping, and CycloneDX/AIBOM export."""

from __future__ import annotations

import json

import pytest

from aastf.ai_vss import (
    CWE_MAPPING,
    CWE_NAMES,
    AIVSSScorer,
    AIVSSVector,
    CycloneDXExporter,
    severity_from_score,
)
from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    category: ASICategory = ASICategory.ASI01,
    severity: Severity = Severity.HIGH,
    verdict: Verdict = Verdict.VULNERABLE,
    scenario_id: str | None = None,
) -> VulnerabilityFinding:
    sid = scenario_id or f"{category.value}-001"
    return VulnerabilityFinding(
        scenario_id=sid,
        scenario_name=f"Test {category.value}",
        category=category,
        severity=severity,
        verdict=verdict,
        triggered_by="output_contains",
        description=f"Test finding for {category.value}",
        remediation="Apply recommended mitigations",
    )


def _make_report(findings: list[VulnerabilityFinding] | None = None) -> ScanReport:
    flist = findings or []
    return ScanReport(
        aastf_version="1.0.0",
        adapter="test",
        total_scenarios=len(flist) + 2,
        vulnerable=len(flist),
        findings=flist,
    )


# ---------------------------------------------------------------------------
# CWE Mapping completeness
# ---------------------------------------------------------------------------

class TestCWEMapping:
    """Verify CWE_MAPPING covers all ASI categories."""

    def test_all_10_categories_mapped(self) -> None:
        for cat in ASICategory:
            assert cat in CWE_MAPPING, f"Missing CWE mapping for {cat}"

    @pytest.mark.parametrize("cat", list(ASICategory))
    def test_each_category_has_at_least_one_cwe(self, cat: ASICategory) -> None:
        assert len(CWE_MAPPING[cat]) >= 1

    def test_asi01_maps_to_cwe_77_and_74(self) -> None:
        assert 77 in CWE_MAPPING[ASICategory.ASI01]
        assert 74 in CWE_MAPPING[ASICategory.ASI01]

    def test_asi02_maps_to_cwe_200_and_532(self) -> None:
        assert 200 in CWE_MAPPING[ASICategory.ASI02]
        assert 532 in CWE_MAPPING[ASICategory.ASI02]

    def test_asi05_maps_to_cwe_829_and_20(self) -> None:
        assert 829 in CWE_MAPPING[ASICategory.ASI05]
        assert 20 in CWE_MAPPING[ASICategory.ASI05]

    def test_asi10_maps_to_cwe_400_and_770(self) -> None:
        assert 400 in CWE_MAPPING[ASICategory.ASI10]
        assert 770 in CWE_MAPPING[ASICategory.ASI10]

    def test_all_cwes_have_names(self) -> None:
        for cat, ids in CWE_MAPPING.items():
            for cid in ids:
                assert cid in CWE_NAMES, f"CWE-{cid} (from {cat}) has no name entry"

    def test_cwe_ids_are_positive_integers(self) -> None:
        for cat, ids in CWE_MAPPING.items():
            for cid in ids:
                assert isinstance(cid, int) and cid > 0, f"Invalid CWE ID {cid} in {cat}"


# ---------------------------------------------------------------------------
# AIVSSVector model
# ---------------------------------------------------------------------------

class TestAIVSSVector:
    def test_default_values(self) -> None:
        v = AIVSSVector()
        assert v.base_score == 0.0
        assert v.severity == "NONE"
        assert v.attack_vector == "NETWORK"

    def test_vector_string_format(self) -> None:
        v = AIVSSVector(
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE",
            user_interaction="NONE",
            scope="CHANGED",
            confidentiality="HIGH",
            integrity="HIGH",
            availability="LOW",
            base_score=9.5,
            severity="CRITICAL",
        )
        vs = v.vector_string
        assert vs.startswith("AIVSS:1.0/")
        assert "AV:N" in vs
        assert "AC:L" in vs
        assert "PR:N" in vs
        assert "S:C" in vs
        assert "C:H" in vs

    def test_score_bounds_enforced(self) -> None:
        with pytest.raises(ValueError):
            AIVSSVector(base_score=11.0)
        with pytest.raises(ValueError):
            AIVSSVector(base_score=-1.0)

    def test_vector_string_local(self) -> None:
        v = AIVSSVector(attack_vector="LOCAL", scope="UNCHANGED")
        assert "AV:L" in v.vector_string
        assert "S:U" in v.vector_string


# ---------------------------------------------------------------------------
# severity_from_score
# ---------------------------------------------------------------------------

class TestSeverityFromScore:
    def test_none_at_zero(self) -> None:
        assert severity_from_score(0.0) == "NONE"

    def test_low(self) -> None:
        assert severity_from_score(1.0) == "LOW"
        assert severity_from_score(3.9) == "LOW"

    def test_medium(self) -> None:
        assert severity_from_score(4.0) == "MEDIUM"
        assert severity_from_score(6.9) == "MEDIUM"

    def test_high(self) -> None:
        assert severity_from_score(7.0) == "HIGH"
        assert severity_from_score(8.9) == "HIGH"

    def test_critical(self) -> None:
        assert severity_from_score(9.0) == "CRITICAL"
        assert severity_from_score(10.0) == "CRITICAL"

    def test_negative_is_none(self) -> None:
        assert severity_from_score(-0.5) == "NONE"


# ---------------------------------------------------------------------------
# AIVSSScorer
# ---------------------------------------------------------------------------

class TestAIVSSScorer:
    def setup_method(self) -> None:
        self.scorer = AIVSSScorer()

    @pytest.mark.parametrize("cat", list(ASICategory))
    def test_score_finding_all_categories(self, cat: ASICategory) -> None:
        finding = _make_finding(category=cat)
        vector = self.scorer.score_finding(finding)
        assert isinstance(vector, AIVSSVector)
        assert vector.base_score > 0.0
        assert vector.severity != "NONE"

    def test_safe_verdict_gets_zero_score(self) -> None:
        finding = _make_finding(verdict=Verdict.SAFE)
        vector = self.scorer.score_finding(finding)
        assert vector.base_score == 0.0
        assert vector.severity == "NONE"

    def test_inconclusive_verdict_gets_zero_score(self) -> None:
        finding = _make_finding(verdict=Verdict.INCONCLUSIVE)
        vector = self.scorer.score_finding(finding)
        assert vector.base_score == 0.0

    def test_error_verdict_gets_zero_score(self) -> None:
        finding = _make_finding(verdict=Verdict.ERROR)
        vector = self.scorer.score_finding(finding)
        assert vector.base_score == 0.0

    def test_refusal_echo_gets_reduced_score(self) -> None:
        vuln = _make_finding(verdict=Verdict.VULNERABLE)
        echo = _make_finding(verdict=Verdict.REFUSAL_ECHO)
        vuln_v = self.scorer.score_finding(vuln)
        echo_v = self.scorer.score_finding(echo)
        assert echo_v.base_score < vuln_v.base_score
        assert echo_v.base_score > 0.0

    def test_score_report_returns_tuples(self) -> None:
        findings = [_make_finding(ASICategory.ASI01), _make_finding(ASICategory.ASI05)]
        report = _make_report(findings)
        scored = self.scorer.score_report(report)
        assert len(scored) == 2
        for f, v in scored:
            assert isinstance(f, VulnerabilityFinding)
            assert isinstance(v, AIVSSVector)

    def test_score_report_empty(self) -> None:
        report = _make_report([])
        scored = self.scorer.score_report(report)
        assert scored == []

    def test_get_cwes(self) -> None:
        cwes = self.scorer.get_cwes(ASICategory.ASI01)
        assert 77 in cwes
        assert 74 in cwes

    def test_get_cwe_names(self) -> None:
        names = self.scorer.get_cwe_names(ASICategory.ASI01)
        assert any("Injection" in n for n in names)

    def test_asi05_scores_critical(self) -> None:
        # ASI05 (RCE) with all HIGHs on scope CHANGED should be critical
        finding = _make_finding(category=ASICategory.ASI05)
        vector = self.scorer.score_finding(finding)
        assert vector.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# CycloneDXExporter
# ---------------------------------------------------------------------------

class TestCycloneDXExporter:
    def setup_method(self) -> None:
        self.exporter = CycloneDXExporter()

    def test_export_bom_structure(self) -> None:
        report = _make_report([_make_finding()])
        bom = self.exporter.export_bom(report, "my-agent", "2.0.0")
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.5"
        assert bom["version"] == 1
        assert "metadata" in bom
        assert "components" in bom
        assert "vulnerabilities" in bom

    def test_export_bom_serial_number(self) -> None:
        report = _make_report([])
        bom = self.exporter.export_bom(report, "agent", "1.0")
        assert bom["serialNumber"].startswith("urn:uuid:")

    def test_export_bom_metadata_tool(self) -> None:
        report = _make_report([])
        bom = self.exporter.export_bom(report, "agent", "1.0")
        tools = bom["metadata"]["tools"]
        assert any(t["name"] == "aastf" for t in tools)

    def test_export_bom_component(self) -> None:
        report = _make_report([])
        bom = self.exporter.export_bom(report, "my-agent", "3.0.0")
        comp = bom["components"][0]
        assert comp["name"] == "my-agent"
        assert comp["version"] == "3.0.0"
        assert comp["type"] == "application"

    def test_export_bom_component_ref_purl(self) -> None:
        report = _make_report([])
        bom = self.exporter.export_bom(report, "my-agent", "1.0")
        ref = bom["components"][0]["bom-ref"]
        assert ref == "pkg:aastf/my-agent@1.0"

    def test_export_bom_properties(self) -> None:
        report = _make_report([])
        bom = self.exporter.export_bom(report, "agent", "1.0")
        prop_names = {p["name"] for p in bom["properties"]}
        assert "aastf:run_id" in prop_names
        assert "aastf:adapter" in prop_names
        assert "aastf:total_scenarios" in prop_names

    def test_export_vulnerabilities_count(self) -> None:
        findings = [_make_finding(ASICategory.ASI01), _make_finding(ASICategory.ASI02)]
        report = _make_report(findings)
        vulns = self.exporter.export_vulnerabilities(report)
        assert len(vulns) == 2

    def test_export_vulnerabilities_empty(self) -> None:
        report = _make_report([])
        vulns = self.exporter.export_vulnerabilities(report)
        assert vulns == []

    def test_vulnerability_entry_fields(self) -> None:
        finding = _make_finding(ASICategory.ASI01)
        report = _make_report([finding])
        vulns = self.exporter.export_vulnerabilities(report)
        v = vulns[0]
        assert v["id"] == finding.scenario_id
        assert v["description"] == finding.description
        assert v["recommendation"] == finding.remediation
        assert "ratings" in v
        assert "cwes" in v
        assert "source" in v
        assert "affects" in v

    def test_vulnerability_entry_cwes(self) -> None:
        finding = _make_finding(ASICategory.ASI01)
        report = _make_report([finding])
        vulns = self.exporter.export_vulnerabilities(report)
        assert 77 in vulns[0]["cwes"]
        assert 74 in vulns[0]["cwes"]

    def test_vulnerability_entry_ratings(self) -> None:
        finding = _make_finding(ASICategory.ASI01)
        report = _make_report([finding])
        vulns = self.exporter.export_vulnerabilities(report)
        ratings = vulns[0]["ratings"]
        aivss_rating = [r for r in ratings if r["method"] == "AI-VSS"]
        assert len(aivss_rating) == 1
        assert aivss_rating[0]["score"] > 0
        assert "vector" in aivss_rating[0]

    def test_vulnerability_entry_with_cvss(self) -> None:
        finding = _make_finding(ASICategory.ASI01)
        finding.cvss_score = 8.5
        report = _make_report([finding])
        vulns = self.exporter.export_vulnerabilities(report)
        ratings = vulns[0]["ratings"]
        cvss_rating = [r for r in ratings if r["method"] == "CVSSv3"]
        assert len(cvss_rating) == 1
        assert cvss_rating[0]["score"] == 8.5

    def test_vulnerability_entry_properties(self) -> None:
        finding = _make_finding(ASICategory.ASI01)
        report = _make_report([finding])
        vulns = self.exporter.export_vulnerabilities(report)
        prop_names = {p["name"] for p in vulns[0]["properties"]}
        assert "aastf:verdict" in prop_names
        assert "aastf:category" in prop_names
        assert "aastf:aivss_vector" in prop_names

    def test_vulnerability_entry_references(self) -> None:
        finding = _make_finding(ASICategory.ASI01)
        finding.references = ["https://example.com/ref1"]
        report = _make_report([finding])
        vulns = self.exporter.export_vulnerabilities(report)
        assert "references" in vulns[0]
        assert vulns[0]["references"][0]["id"] == "https://example.com/ref1"

    def test_vulnerability_entry_no_references_when_empty(self) -> None:
        finding = _make_finding(ASICategory.ASI01)
        finding.references = []
        report = _make_report([finding])
        vulns = self.exporter.export_vulnerabilities(report)
        assert "references" not in vulns[0]

    def test_to_json_valid(self) -> None:
        report = _make_report([_make_finding()])
        bom = self.exporter.export_bom(report, "agent", "1.0")
        json_str = self.exporter.to_json(bom)
        parsed = json.loads(json_str)
        assert parsed["bomFormat"] == "CycloneDX"

    def test_to_json_indented(self) -> None:
        report = _make_report([])
        bom = self.exporter.export_bom(report, "agent", "1.0")
        json_str = self.exporter.to_json(bom)
        assert "\n" in json_str  # indented output has newlines

    def test_bom_full_roundtrip(self) -> None:
        findings = [
            _make_finding(ASICategory.ASI01),
            _make_finding(ASICategory.ASI05, severity=Severity.CRITICAL),
            _make_finding(ASICategory.ASI10),
        ]
        report = _make_report(findings)
        bom = self.exporter.export_bom(report, "test-agent", "0.1.0")
        json_str = self.exporter.to_json(bom)
        parsed = json.loads(json_str)
        assert len(parsed["vulnerabilities"]) == 3
        assert parsed["components"][0]["name"] == "test-agent"
        assert parsed["metadata"]["tools"][0]["version"] == "1.0.0"
