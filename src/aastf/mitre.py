"""MITRE ATT&CK and ATLAS mapping for AASTF findings."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from .models.result import ScanReport, VulnerabilityFinding
from .models.scenario import ASICategory


class MITREMapping(BaseModel):
    """Maps an ASI category to MITRE ATT&CK and ATLAS techniques/tactics."""

    attack_techniques: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)
    atlas_techniques: list[str] = Field(default_factory=list)
    atlas_tactics: list[str] = Field(default_factory=list)


ASI_TO_MITRE: dict[ASICategory, MITREMapping] = {
    ASICategory.ASI01: MITREMapping(
        attack_techniques=["T1059"],
        attack_tactics=["Execution"],
        atlas_techniques=["AML.T0051"],
        atlas_tactics=["Initial Access"],
    ),
    ASICategory.ASI02: MITREMapping(
        attack_techniques=["T1005"],
        attack_tactics=["Collection"],
        atlas_techniques=["AML.T0024"],
        atlas_tactics=["Exfiltration"],
    ),
    ASICategory.ASI03: MITREMapping(
        attack_techniques=["T1078", "T1548"],
        attack_tactics=["Privilege Escalation", "Defense Evasion"],
        atlas_techniques=["AML.T0051"],
        atlas_tactics=["Initial Access"],
    ),
    ASICategory.ASI04: MITREMapping(
        attack_techniques=["T1562"],
        attack_tactics=["Defense Evasion"],
        atlas_techniques=["AML.T0054"],
        atlas_tactics=["Impact"],
    ),
    ASICategory.ASI05: MITREMapping(
        attack_techniques=["T1204"],
        attack_tactics=["Execution"],
        atlas_techniques=["AML.T0043"],
        atlas_tactics=["ML Attack Staging"],
    ),
    ASICategory.ASI06: MITREMapping(
        attack_techniques=["T1569"],
        attack_tactics=["Execution"],
        atlas_techniques=["AML.T0040"],
        atlas_tactics=["ML Supply Chain Compromise"],
    ),
    ASICategory.ASI07: MITREMapping(
        attack_techniques=["T1552"],
        attack_tactics=["Credential Access"],
        atlas_techniques=["AML.T0044"],
        atlas_tactics=["ML Model Access"],
    ),
    ASICategory.ASI08: MITREMapping(
        attack_techniques=["T1499", "T1498"],
        attack_tactics=["Impact"],
        atlas_techniques=["AML.T0029"],
        atlas_tactics=["Impact"],
    ),
    ASICategory.ASI09: MITREMapping(
        attack_techniques=["T1195"],
        attack_tactics=["Initial Access"],
        atlas_techniques=["AML.T0040"],
        atlas_tactics=["ML Supply Chain Compromise"],
    ),
    ASICategory.ASI10: MITREMapping(
        attack_techniques=["T1053"],
        attack_tactics=["Execution", "Persistence"],
        atlas_techniques=["AML.T0048"],
        atlas_tactics=["Impact"],
    ),
}


class EnrichedFinding(VulnerabilityFinding):
    """A VulnerabilityFinding enriched with MITRE mappings."""

    mitre_attack: list[str] = Field(default_factory=list)
    mitre_atlas: list[str] = Field(default_factory=list)
    attack_tactics: list[str] = Field(default_factory=list)


class EnrichedReport(BaseModel):
    """A scan report enriched with MITRE technique/tactic summaries."""

    original_report: ScanReport
    mitre_summary: dict[str, int] = Field(default_factory=dict)
    atlas_summary: dict[str, int] = Field(default_factory=dict)
    tactic_coverage: dict[str, int] = Field(default_factory=dict)


def to_sarif_tags(mapping: MITREMapping) -> list[str]:
    """Convert a MITREMapping into SARIF-compatible tag strings."""
    tags: list[str] = []
    for t in mapping.attack_techniques:
        tags.append(f"external/cwe/mitre-attack/{t}")
    for t in mapping.atlas_techniques:
        tags.append(f"external/cwe/mitre-atlas/{t}")
    for tactic in mapping.attack_tactics:
        tags.append(f"external/cwe/mitre-attack-tactic/{tactic.lower().replace(' ', '-')}")
    for tactic in mapping.atlas_tactics:
        tags.append(f"external/cwe/mitre-atlas-tactic/{tactic.lower().replace(' ', '-')}")
    return tags


class MITREEnricher:
    """Enriches AASTF findings and reports with MITRE ATT&CK / ATLAS mappings."""

    def get_attack_techniques(self, category: ASICategory) -> list[str]:
        """Return ATT&CK technique IDs for the given ASI category."""
        mapping = ASI_TO_MITRE.get(category)
        if mapping is None:
            return []
        return list(mapping.attack_techniques)

    def get_atlas_techniques(self, category: ASICategory) -> list[str]:
        """Return ATLAS technique IDs for the given ASI category."""
        mapping = ASI_TO_MITRE.get(category)
        if mapping is None:
            return []
        return list(mapping.atlas_techniques)

    def enrich_finding(self, finding: VulnerabilityFinding) -> EnrichedFinding:
        """Add MITRE fields to a single VulnerabilityFinding."""
        mapping = ASI_TO_MITRE.get(finding.category)
        attack: list[str] = []
        atlas: list[str] = []
        tactics: list[str] = []
        if mapping is not None:
            attack = list(mapping.attack_techniques)
            atlas = list(mapping.atlas_techniques)
            tactics = list(mapping.attack_tactics)

        data: dict[str, Any] = finding.model_dump()
        data["mitre_attack"] = attack
        data["mitre_atlas"] = atlas
        data["attack_tactics"] = tactics
        return EnrichedFinding(**data)

    def enrich_report(self, report: ScanReport) -> EnrichedReport:
        """Enrich an entire ScanReport with MITRE summaries."""
        mitre_summary: dict[str, int] = {}
        atlas_summary: dict[str, int] = {}
        tactic_coverage: dict[str, int] = {}

        for finding in report.findings:
            mapping = ASI_TO_MITRE.get(finding.category)
            if mapping is None:
                continue
            for t in mapping.attack_techniques:
                mitre_summary[t] = mitre_summary.get(t, 0) + 1
            for t in mapping.atlas_techniques:
                atlas_summary[t] = atlas_summary.get(t, 0) + 1
            for tactic in mapping.attack_tactics:
                tactic_coverage[tactic] = tactic_coverage.get(tactic, 0) + 1

        return EnrichedReport(
            original_report=report,
            mitre_summary=mitre_summary,
            atlas_summary=atlas_summary,
            tactic_coverage=tactic_coverage,
        )
