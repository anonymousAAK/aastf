"""SARIF 2.1 reporter — GitHub Security tab native integration."""

from __future__ import annotations

import json
from pathlib import Path

from ..models.result import ScanReport, Verdict, VulnerabilityFinding
from ..models.scenario import Severity

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

def _verdict_sarif_level(finding: VulnerabilityFinding) -> str:
    """Map a finding's verdict and severity to a SARIF result level.

    VULNERABLE at CRITICAL/HIGH → "error"   (red in GitHub Security tab,
        Defender, Snyk — signals behavioural compromise requiring immediate fix)
    VULNERABLE at MEDIUM/LOW/INFO → "warning"
    REFUSAL_ECHO at any severity → "warning" (never "error"; the agent refused
        so there is no behavioural compromise — informational/sanitization risk only)
    """
    if finding.verdict == Verdict.REFUSAL_ECHO:
        return "warning"
    if finding.severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    return "warning"

_OWASP_URLS = {
    "ASI01": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi01",
    "ASI02": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi02",
    "ASI03": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi03",
    "ASI04": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi04",
    "ASI05": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi05",
    "ASI06": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi06",
    "ASI07": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi07",
    "ASI08": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi08",
    "ASI09": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi09",
    "ASI10": "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/#asi10",
}


class SARIFReporter:
    """Generates SARIF 2.1 output for GitHub Security tab integration."""

    def generate(self, report: ScanReport) -> dict:
        """Return SARIF document as a Python dict.

        VULNERABLE and REFUSAL_ECHO findings are both emitted.  SAFE findings
        are omitted (not actionable).  SARIF-consuming tools that don't know
        AASTF see standard error/warning levels; AASTF-aware tools can filter
        on the aastf.verdict extension property.
        """
        actionable = [
            f for f in report.findings
            if f.verdict in (Verdict.VULNERABLE, Verdict.REFUSAL_ECHO)
        ]
        return {
            "version": _SARIF_VERSION,
            "$schema": _SARIF_SCHEMA,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "aastf",
                        "version": report.aastf_version,
                        "informationUri": "https://github.com/anonymousAAK/aastf",
                        "rules": self._build_rules(report),
                    }
                },
                "results": [self._finding_to_result(f) for f in actionable],
                "properties": {
                    "aastf_risk_score": report.overall_risk_score,
                    "eu_ai_act_readiness": report.eu_ai_act_readiness,
                    "vulnerability_rate": report.vulnerability_rate,
                    "informational_risk_rate": report.informational_risk_rate,
                },
            }],
        }

    def generate_json(self, report: ScanReport) -> str:
        """Return SARIF document as a JSON string."""
        return json.dumps(self.generate(report), indent=2)

    def write(self, report: ScanReport, output_path: Path) -> Path:
        """Write SARIF report to output_path."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate_json(report), encoding="utf-8")
        return output_path

    def _build_rules(self, report: ScanReport) -> list[dict]:
        seen: set[str] = set()
        rules = []
        for result in report.results:
            rule_id = result.scenario_id
            if rule_id in seen:
                continue
            seen.add(rule_id)
            cat = result.category.value
            rules.append({
                "id": rule_id,
                "name": result.scenario_name.replace(" ", ""),
                "shortDescription": {"text": result.scenario_name},
                "helpUri": _OWASP_URLS.get(cat, "https://genai.owasp.org"),
                "properties": {
                    "category": cat,
                    "severity": result.severity.value,
                    "owasp_asi": cat,
                },
            })
        return rules

    def _finding_to_result(self, finding: VulnerabilityFinding) -> dict:
        return {
            "ruleId": finding.scenario_id,
            "level": _verdict_sarif_level(finding),
            "message": {
                "text": (
                    f"{finding.scenario_name}. "
                    f"Triggered by: {finding.triggered_by}. "
                    f"Remediation: {finding.remediation[:200]}"
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "agent/"},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "category": finding.category.value,
                "severity": finding.severity.value,
                "cvss_score": finding.cvss_score,
                "triggered_by": finding.triggered_by,
                "evidence": str(finding.evidence)[:500],
                # Extension properties — standard SARIF tools display level/ruleId;
                # AASTF-aware tools and workflows can filter on these fields.
                "aastf.verdict": finding.verdict.value,
                "aastf.matched_refusal_patterns": finding.evidence.get("matched_patterns", []),
            },
        }
