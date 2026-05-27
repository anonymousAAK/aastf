"""Tests for MITRE ATT&CK / ATLAS mapping module."""

from __future__ import annotations

import pytest

from aastf.mitre import (
    ASI_TO_MITRE,
    EnrichedFinding,
    EnrichedReport,
    MITREEnricher,
    MITREMapping,
    to_sarif_tags,
)
from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity

# ---------------------------------------------------------------------------
# ASI_TO_MITRE completeness
# ---------------------------------------------------------------------------

class TestASIToMITRE:
    """Verify the mapping dict covers all ASI categories."""

    def test_all_10_categories_mapped(self) -> None:
        for cat in ASICategory:
            assert cat in ASI_TO_MITRE, f"Missing mapping for {cat}"

    @pytest.mark.parametrize("cat", list(ASICategory))
    def test_each_mapping_has_attack_technique(self, cat: ASICategory) -> None:
        mapping = ASI_TO_MITRE[cat]
        assert len(mapping.attack_techniques) >= 1

    @pytest.mark.parametrize("cat", list(ASICategory))
    def test_each_mapping_has_atlas_technique(self, cat: ASICategory) -> None:
        mapping = ASI_TO_MITRE[cat]
        assert len(mapping.atlas_techniques) >= 1

    @pytest.mark.parametrize("cat", list(ASICategory))
    def test_each_mapping_has_tactics(self, cat: ASICategory) -> None:
        mapping = ASI_TO_MITRE[cat]
        assert len(mapping.attack_tactics) >= 1
        assert len(mapping.atlas_tactics) >= 1

    def test_attack_technique_ids_format(self) -> None:
        for cat, mapping in ASI_TO_MITRE.items():
            for t in mapping.attack_techniques:
                assert t.startswith("T"), f"{cat}: bad ATT&CK ID {t}"

    def test_atlas_technique_ids_format(self) -> None:
        for cat, mapping in ASI_TO_MITRE.items():
            for t in mapping.atlas_techniques:
                assert t.startswith("AML.T"), f"{cat}: bad ATLAS ID {t}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    category: ASICategory = ASICategory.ASI01,
    severity: Severity = Severity.HIGH,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id="ASI01-001",
        scenario_name="Test prompt injection",
        category=category,
        severity=severity,
        verdict=Verdict.VULNERABLE,
        triggered_by="output_contains",
        description="Test finding",
        remediation="Add input filtering",
    )


def _make_report(findings: list[VulnerabilityFinding] | None = None) -> ScanReport:
    return ScanReport(
        aastf_version="0.9.0",
        adapter="test",
        total_scenarios=5,
        vulnerable=len(findings) if findings else 0,
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# MITREEnricher
# ---------------------------------------------------------------------------

class TestMITREEnricher:
    def setup_method(self) -> None:
        self.enricher = MITREEnricher()

    def test_get_attack_techniques(self) -> None:
        techs = self.enricher.get_attack_techniques(ASICategory.ASI01)
        assert "T1059" in techs

    def test_get_atlas_techniques(self) -> None:
        techs = self.enricher.get_atlas_techniques(ASICategory.ASI01)
        assert "AML.T0051" in techs

    def test_enrich_finding_adds_mitre_fields(self) -> None:
        finding = _make_finding(ASICategory.ASI03)
        enriched = self.enricher.enrich_finding(finding)
        assert isinstance(enriched, EnrichedFinding)
        assert "T1078" in enriched.mitre_attack
        assert "T1548" in enriched.mitre_attack
        assert "AML.T0051" in enriched.mitre_atlas
        assert "Privilege Escalation" in enriched.attack_tactics

    def test_enrich_finding_preserves_original_fields(self) -> None:
        finding = _make_finding(ASICategory.ASI02)
        enriched = self.enricher.enrich_finding(finding)
        assert enriched.scenario_id == finding.scenario_id
        assert enriched.category == finding.category
        assert enriched.verdict == finding.verdict

    def test_enrich_report_produces_summaries(self) -> None:
        findings = [
            _make_finding(ASICategory.ASI01),
            _make_finding(ASICategory.ASI01),
            _make_finding(ASICategory.ASI03),
        ]
        report = _make_report(findings)
        enriched = self.enricher.enrich_report(report)
        assert isinstance(enriched, EnrichedReport)
        # ASI01 maps to T1059 — two findings
        assert enriched.mitre_summary["T1059"] == 2
        # ASI03 maps to T1078 and T1548
        assert enriched.mitre_summary["T1078"] == 1
        assert enriched.mitre_summary["T1548"] == 1
        # ATLAS: ASI01 -> AML.T0051 x2, ASI03 -> AML.T0051 x1
        assert enriched.atlas_summary["AML.T0051"] == 3

    def test_enrich_report_tactic_coverage(self) -> None:
        findings = [_make_finding(ASICategory.ASI08)]
        report = _make_report(findings)
        enriched = self.enricher.enrich_report(report)
        assert enriched.tactic_coverage["Impact"] == 1

    def test_enrich_report_empty_findings(self) -> None:
        report = _make_report([])
        enriched = self.enricher.enrich_report(report)
        assert enriched.mitre_summary == {}
        assert enriched.atlas_summary == {}
        assert enriched.tactic_coverage == {}

    def test_unknown_category_get_attack_graceful(self) -> None:
        """get_attack_techniques should return [] for an unknown/unmapped category."""
        # We test by passing a valid category that exists in the enum;
        # all are mapped, so instead we monkeypatch.
        import aastf.mitre as mitre_mod

        original = dict(ASI_TO_MITRE)
        try:
            mitre_mod.ASI_TO_MITRE.pop(ASICategory.ASI10, None)  # type: ignore[arg-type]
            result = self.enricher.get_attack_techniques(ASICategory.ASI10)
            assert result == []
        finally:
            mitre_mod.ASI_TO_MITRE.update(original)

    def test_unknown_category_get_atlas_graceful(self) -> None:
        import aastf.mitre as mitre_mod

        original = dict(ASI_TO_MITRE)
        try:
            mitre_mod.ASI_TO_MITRE.pop(ASICategory.ASI10, None)  # type: ignore[arg-type]
            result = self.enricher.get_atlas_techniques(ASICategory.ASI10)
            assert result == []
        finally:
            mitre_mod.ASI_TO_MITRE.update(original)

    def test_unknown_category_enrich_finding_graceful(self) -> None:
        import aastf.mitre as mitre_mod

        original = dict(ASI_TO_MITRE)
        try:
            mitre_mod.ASI_TO_MITRE.pop(ASICategory.ASI10, None)  # type: ignore[arg-type]
            finding = _make_finding(ASICategory.ASI10)
            enriched = self.enricher.enrich_finding(finding)
            assert enriched.mitre_attack == []
            assert enriched.mitre_atlas == []
            assert enriched.attack_tactics == []
        finally:
            mitre_mod.ASI_TO_MITRE.update(original)


# ---------------------------------------------------------------------------
# SARIF tags
# ---------------------------------------------------------------------------

class TestSARIFTags:
    def test_sarif_tags_format(self) -> None:
        mapping = ASI_TO_MITRE[ASICategory.ASI01]
        tags = to_sarif_tags(mapping)
        assert "external/cwe/mitre-attack/T1059" in tags
        assert "external/cwe/mitre-atlas/AML.T0051" in tags
        assert "external/cwe/mitre-attack-tactic/execution" in tags
        assert "external/cwe/mitre-atlas-tactic/initial-access" in tags

    def test_sarif_tags_multi_technique(self) -> None:
        mapping = ASI_TO_MITRE[ASICategory.ASI08]
        tags = to_sarif_tags(mapping)
        assert "external/cwe/mitre-attack/T1499" in tags
        assert "external/cwe/mitre-attack/T1498" in tags

    def test_sarif_tags_empty_mapping(self) -> None:
        mapping = MITREMapping()
        tags = to_sarif_tags(mapping)
        assert tags == []

    def test_sarif_tags_all_prefixed(self) -> None:
        for cat in ASICategory:
            mapping = ASI_TO_MITRE[cat]
            tags = to_sarif_tags(mapping)
            for tag in tags:
                assert tag.startswith("external/cwe/mitre-")
