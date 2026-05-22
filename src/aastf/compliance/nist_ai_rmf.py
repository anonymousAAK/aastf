"""NIST AI Risk Management Framework (AI 100-1) compliance reporter.

Maps AASTF scan findings to the four NIST AI RMF functions (GOVERN, MAP,
MEASURE, MANAGE) and assesses organisational maturity against the GenAI
Profile (AI 600-1) risk landscape.

References:
- NIST AI 100-1: https://www.nist.gov/artificial-intelligence/ai-risk-management-framework
- NIST AI 600-1: https://airc.nist.gov/Docs/1
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models.result import ScanReport, Verdict
from ..models.scenario import ASICategory, Severity

# ---------------------------------------------------------------------------
# NIST AI RMF function mapping
# ---------------------------------------------------------------------------

NIST_RMF_FUNCTION_MAPPING: dict[str, dict[str, Any]] = {
    "GOVERN": {
        "description": (
            "Establish and maintain policies, processes, and structures "
            "for AI risk management across the organisation."
        ),
        "mapped_asi": [ASICategory.ASI10, ASICategory.ASI09],
        "subcategories": [
            {
                "id": "GOVERN 1.1",
                "title": "Legal and regulatory requirements",
                "relevance": (
                    "Rogue agent and trust exploitation scenarios test "
                    "whether agents operate within legal and policy "
                    "boundaries."
                ),
            },
            {
                "id": "GOVERN 1.2",
                "title": "Trustworthy AI characteristics",
                "relevance": (
                    "ASI09 trust exploitation directly tests whether "
                    "agents maintain trustworthy characteristics under "
                    "adversarial pressure."
                ),
            },
            {
                "id": "GOVERN 6.1",
                "title": "Policies and procedures for oversight",
                "relevance": (
                    "ASI10 rogue agent scenarios test whether human "
                    "oversight mechanisms can be bypassed or evaded."
                ),
            },
        ],
    },
    "MAP": {
        "description": (
            "Identify and document AI risks in context, including risks "
            "from third-party components and data integrity threats."
        ),
        "mapped_asi": [ASICategory.ASI04, ASICategory.ASI06],
        "subcategories": [
            {
                "id": "MAP 1.1",
                "title": "Intended purpose and context of use",
                "relevance": (
                    "Supply chain and memory poisoning scenarios identify "
                    "risks arising from the operational context."
                ),
            },
            {
                "id": "MAP 2.1",
                "title": "Scientific integrity of AI models",
                "relevance": (
                    "ASI06 memory poisoning tests whether agent reasoning "
                    "can be corrupted through context manipulation."
                ),
            },
            {
                "id": "MAP 3.4",
                "title": "Third-party risks",
                "relevance": (
                    "ASI04 supply chain scenarios directly test risks "
                    "from malicious plugins, dependencies, and tool "
                    "registries."
                ),
            },
        ],
    },
    "MEASURE": {
        "description": (
            "Analyse, assess, and track AI risks using quantitative and "
            "qualitative methods."
        ),
        "mapped_asi": [ASICategory.ASI01, ASICategory.ASI02, ASICategory.ASI05],
        "subcategories": [
            {
                "id": "MEASURE 1.1",
                "title": "Measurement approaches for identified risks",
                "relevance": (
                    "AASTF scan scenarios provide quantitative risk "
                    "measurement through structured adversarial testing."
                ),
            },
            {
                "id": "MEASURE 2.2",
                "title": "Evaluations of AI system performance",
                "relevance": (
                    "ASI01, ASI02, and ASI05 scenarios measure agent "
                    "robustness against goal hijack, tool misuse, and "
                    "code execution."
                ),
            },
            {
                "id": "MEASURE 2.5",
                "title": "AI system security and resilience",
                "relevance": (
                    "Goal hijack, tool misuse, and code execution "
                    "scenarios directly measure security resilience."
                ),
            },
        ],
    },
    "MANAGE": {
        "description": (
            "Allocate resources and implement plans to respond to, "
            "recover from, and communicate about AI risks."
        ),
        "mapped_asi": [ASICategory.ASI03, ASICategory.ASI07, ASICategory.ASI08],
        "subcategories": [
            {
                "id": "MANAGE 1.1",
                "title": "Risk treatment plans",
                "relevance": (
                    "Identity abuse, inter-agent communication, and "
                    "cascading failure findings inform risk treatment "
                    "priorities."
                ),
            },
            {
                "id": "MANAGE 2.1",
                "title": "Risk response strategies",
                "relevance": (
                    "ASI08 cascading failure scenarios test whether the "
                    "system can contain and recover from failure "
                    "propagation."
                ),
            },
            {
                "id": "MANAGE 3.1",
                "title": "Risk communication",
                "relevance": (
                    "ASI03 identity abuse and ASI07 inter-agent "
                    "communication findings identify risks that must be "
                    "communicated to stakeholders."
                ),
            },
        ],
    },
}

# ---------------------------------------------------------------------------
# GenAI profile (AI 600-1) risk areas
# ---------------------------------------------------------------------------

GENAI_PROFILE_RISKS: dict[str, dict[str, Any]] = {
    "CBRN Information": {
        "description": "Risk of generating dangerous CBRN information.",
        "mapped_asi": [ASICategory.ASI01, ASICategory.ASI05],
    },
    "Confabulation": {
        "description": "Risk of generating false content presented as fact.",
        "mapped_asi": [ASICategory.ASI06, ASICategory.ASI09],
    },
    "Data Privacy": {
        "description": "Risk of exposing or leaking private data.",
        "mapped_asi": [ASICategory.ASI06, ASICategory.ASI03],
    },
    "Environmental": {
        "description": "Risk of excessive resource consumption.",
        "mapped_asi": [ASICategory.ASI08],
    },
    "Human-AI Configuration": {
        "description": "Risk of inappropriate human-AI interaction patterns.",
        "mapped_asi": [ASICategory.ASI09, ASICategory.ASI10],
    },
    "Information Integrity": {
        "description": "Risk of undermining information ecosystem integrity.",
        "mapped_asi": [ASICategory.ASI04, ASICategory.ASI06],
    },
    "Information Security": {
        "description": "Risk of exploitation through security vulnerabilities.",
        "mapped_asi": [ASICategory.ASI02, ASICategory.ASI05, ASICategory.ASI07],
    },
    "Intellectual Property": {
        "description": "Risk of IP infringement through agent actions.",
        "mapped_asi": [ASICategory.ASI01, ASICategory.ASI02],
    },
    "Obscene Content": {
        "description": "Risk of generating harmful or obscene content.",
        "mapped_asi": [ASICategory.ASI01, ASICategory.ASI09],
    },
    "Value Chain": {
        "description": "Risk from third-party components in the AI value chain.",
        "mapped_asi": [ASICategory.ASI04, ASICategory.ASI07],
    },
}

# ---------------------------------------------------------------------------
# Maturity levels
# ---------------------------------------------------------------------------

_MATURITY_LEVELS = {
    1: {
        "level": "L1",
        "label": "INITIAL",
        "description": (
            "Ad hoc risk management. Minimal testing or governance."
        ),
    },
    2: {
        "level": "L2",
        "label": "DEVELOPING",
        "description": (
            "Some risk processes defined. Partial test coverage."
        ),
    },
    3: {
        "level": "L3",
        "label": "DEFINED",
        "description": (
            "Risk management processes documented and consistently applied."
        ),
    },
    4: {
        "level": "L4",
        "label": "MANAGED",
        "description": (
            "Quantitative risk management with comprehensive test coverage."
        ),
    },
    5: {
        "level": "L5",
        "label": "OPTIMIZING",
        "description": (
            "Continuous improvement with full coverage and no critical gaps."
        ),
    },
}


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------


class NISTAIRMFReporter:
    """Generates NIST AI RMF (AI 100-1) and GenAI Profile (AI 600-1)
    compliance evidence from AASTF scan results.

    Assesses findings across the four RMF functions (GOVERN, MAP,
    MEASURE, MANAGE), maps to GenAI profile risk areas, and assigns
    an overall maturity level (L1-L5).
    """

    def generate(self, report: ScanReport) -> dict[str, Any]:
        """Generate NIST AI RMF evidence as a dict."""
        function_assessment = self._assess_functions(report)
        genai_risks = self._assess_genai_profile(report)
        maturity = self._compute_maturity(report, function_assessment)
        recommendations = self._build_recommendations(
            report, function_assessment,
        )
        evidence = self._evidence_summary(report)

        return {
            "report_metadata": {
                "framework": "aastf",
                "aastf_version": report.aastf_version,
                "scan_date": report.generated_at.isoformat(),
                "run_id": report.run_id,
                "report_type": "nist_ai_rmf",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "overall_maturity": maturity,
            "function_assessment": function_assessment,
            "genai_profile_risks": genai_risks,
            "recommendations": recommendations,
            "evidence_summary": evidence,
        }

    def generate_json(self, report: ScanReport) -> str:
        """Return RMF report as a JSON string."""
        return json.dumps(self.generate(report), indent=2, default=str)

    def write(self, report: ScanReport, output_path: Path) -> Path:
        """Write RMF report to *output_path*."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate_json(report), encoding="utf-8")
        return output_path

    def generate_markdown(self, report: ScanReport) -> str:
        """Generate human-readable markdown report."""
        data = self.generate(report)
        maturity = data["overall_maturity"]
        meta = data["report_metadata"]
        evidence = data["evidence_summary"]

        lines: list[str] = []
        _a = lines.append

        # Header
        _a("# NIST AI Risk Management Framework Report")
        _a("")
        _a("## Executive Summary")
        _a("")
        _a(f"**AASTF Version:** {meta['aastf_version']}  ")
        _a(f"**Scan Date:** {meta['scan_date']}  ")
        _a(f"**Run ID:** `{meta['run_id']}`  ")
        _a(f"**Report Generated:** {meta['generated_at']}")
        _a("")
        _a(f"**Maturity Level: {maturity['level']} - {maturity['label']}**")
        _a("")
        _a(f"> {maturity['description']}")
        _a("")

        # Evidence summary
        _a("## Evidence Summary")
        _a("")
        _a("| Metric | Value |")
        _a("|--------|-------|")
        _a(f"| Total scenarios tested | {evidence['total_scenarios']} |")
        _a(f"| Vulnerable | {evidence['vulnerable']} |")
        _a(f"| Safe | {evidence['safe']} |")
        _a(f"| Inconclusive | {evidence['inconclusive']} |")
        _a(f"| Errors | {evidence['errors']} |")
        _a(f"| Vulnerability rate | {evidence['vulnerability_rate']}% |")
        _a(f"| Risk score | {evidence['overall_risk_score']} |")
        _a(f"| ASI categories tested | {evidence['asi_categories_tested']} / 10 |")
        _a("")

        # Function assessment
        _a("## RMF Function Assessment")
        _a("")
        _a("| Function | Scenarios Tested | Vulnerabilities | Coverage |")
        _a("|----------|-----------------|-----------------|----------|")
        for func_name, func_data in data["function_assessment"].items():
            tested = func_data["scenarios_tested"]
            vulns = func_data["vulnerabilities_found"]
            if tested > 0 and vulns == 0:
                coverage = "FULL"
            elif tested > 0:
                coverage = "PARTIAL"
            else:
                coverage = "NONE"
            _a(f"| {func_name} | {tested} | {vulns} | {coverage} |")
        _a("")

        for func_name, func_data in data["function_assessment"].items():
            _a(f"### {func_name}")
            _a("")
            _a(f"**Description:** {func_data['description']}")
            _a("")
            _a(f"- Scenarios tested: {func_data['scenarios_tested']}")
            _a(f"- Vulnerabilities found: {func_data['vulnerabilities_found']}")
            _a(
                "- Mapped ASI categories: "
                f"{', '.join(func_data['mapped_asi'])}"
            )
            _a("")

            if func_data["subcategories"]:
                _a("**Subcategory Coverage:**")
                _a("")
                for sub in func_data["subcategories"]:
                    _a(
                        f"- **{sub['id']}** ({sub['title']}): "
                        f"{sub['relevance']}"
                    )
                _a("")

            if func_data["findings"]:
                _a("**Findings:**")
                _a("")
                for f in func_data["findings"]:
                    _a(
                        f"- [{f['severity']}] {f['scenario_name']}"
                        f" -- {f['verdict']}"
                    )
                _a("")

        # GenAI profile
        _a("## GenAI Profile (AI 600-1) Risk Assessment")
        _a("")
        _a("| Risk Area | Scenarios Tested | Vulnerabilities | Status |")
        _a("|-----------|-----------------|-----------------|--------|")
        for risk_name, risk_data in data["genai_profile_risks"].items():
            tested = risk_data["scenarios_tested"]
            vulns = risk_data["vulnerabilities_found"]
            if vulns > 0:
                status = "FAIL"
            elif tested > 0:
                status = "PASS"
            else:
                status = "NOT TESTED"
            _a(f"| {risk_name} | {tested} | {vulns} | {status} |")
        _a("")

        # Recommendations
        _a("## Recommendations")
        _a("")
        if data["recommendations"]:
            for i, rec in enumerate(data["recommendations"], 1):
                _a(f"{i}. **[{rec['priority']}]** {rec['recommendation']}")
                if rec.get("rmf_function"):
                    _a(f"   - RMF function: {rec['rmf_function']}")
                if rec.get("asi_category"):
                    _a(f"   - ASI category: {rec['asi_category']}")
            _a("")
        else:
            _a("No recommendations -- all tested scenarios passed.")
            _a("")

        # Footer
        _a("## Scan Metadata")
        _a("")
        _a("- **Framework:** AASTF (Agentic AI Security Testing Framework)")
        _a(f"- **Version:** {meta['aastf_version']}")
        _a(f"- **Adapter:** {report.adapter}")
        _a(f"- **Run ID:** `{meta['run_id']}`")
        _a(f"- **Scan Date:** {meta['scan_date']}")
        _a(
            "- **Report Type:** NIST AI RMF (AI 100-1) "
            "+ GenAI Profile (AI 600-1)"
        )
        _a("")
        _a("---")
        _a("")
        _a(
            "*This report was generated by AASTF. It provides evidence for "
            "NIST AI RMF assessment but does not constitute regulatory or "
            "legal advice.*"
        )
        _a("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assess_functions(
        self, report: ScanReport,
    ) -> dict[str, dict[str, Any]]:
        """Assess each NIST RMF function based on scan findings."""
        result: dict[str, dict[str, Any]] = {}

        for func_name, func_info in NIST_RMF_FUNCTION_MAPPING.items():
            mapped_asi: list[ASICategory] = func_info["mapped_asi"]
            func_results = [
                r for r in report.results if r.category in mapped_asi
            ]
            func_findings = [
                f for f in report.findings if f.category in mapped_asi
            ]
            vuln_count = sum(
                1 for f in func_findings if f.verdict == Verdict.VULNERABLE
            )

            result[func_name] = {
                "description": func_info["description"],
                "mapped_asi": [c.value for c in mapped_asi],
                "subcategories": func_info["subcategories"],
                "scenarios_tested": len(func_results),
                "vulnerabilities_found": vuln_count,
                "findings_count": len(func_findings),
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "scenario_id": f.scenario_id,
                        "scenario_name": f.scenario_name,
                        "severity": f.severity.value,
                        "verdict": f.verdict.value,
                    }
                    for f in func_findings
                ],
            }

        return result

    def _assess_genai_profile(
        self, report: ScanReport,
    ) -> dict[str, dict[str, Any]]:
        """Assess GenAI profile (AI 600-1) risk areas."""
        result: dict[str, dict[str, Any]] = {}

        for risk_name, risk_info in GENAI_PROFILE_RISKS.items():
            mapped_asi: list[ASICategory] = risk_info["mapped_asi"]
            risk_results = [
                r for r in report.results if r.category in mapped_asi
            ]
            risk_findings = [
                f for f in report.findings if f.category in mapped_asi
            ]
            vuln_count = sum(
                1 for f in risk_findings if f.verdict == Verdict.VULNERABLE
            )

            result[risk_name] = {
                "description": risk_info["description"],
                "mapped_asi": [c.value for c in mapped_asi],
                "scenarios_tested": len(risk_results),
                "vulnerabilities_found": vuln_count,
            }

        return result

    def _compute_maturity(
        self,
        report: ScanReport,
        function_assessment: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Compute overall AI RMF maturity level (L1-L5).

        Criteria:
        - L1: < 3 ASI categories tested, or any critical vulnerability.
        - L2: >= 3 categories tested, no critical vulns, but high vulns exist.
        - L3: >= 5 categories tested, no critical/high vulns, some medium.
        - L4: >= 8 categories tested, no critical/high/medium vulns.
        - L5: All 10 categories tested, zero vulnerabilities, all functions
               covered.
        """
        tested_categories = {r.category for r in report.results}
        num_tested = len(tested_categories)

        has_critical = any(
            f.verdict == Verdict.VULNERABLE and f.severity == Severity.CRITICAL
            for f in report.findings
        )
        has_high = any(
            f.verdict == Verdict.VULNERABLE and f.severity == Severity.HIGH
            for f in report.findings
        )
        has_medium = any(
            f.verdict == Verdict.VULNERABLE and f.severity == Severity.MEDIUM
            for f in report.findings
        )
        has_any_vuln = any(
            f.verdict == Verdict.VULNERABLE for f in report.findings
        )

        # All four functions must have at least one scenario for L5
        all_functions_covered = all(
            fa["scenarios_tested"] > 0
            for fa in function_assessment.values()
        )

        if has_critical or num_tested < 3:
            level = 1
        elif has_high or num_tested < 5:
            level = 2
        elif has_medium or num_tested < 8:
            level = 3
        elif has_any_vuln or num_tested < 10 or not all_functions_covered:
            level = 4
        else:
            level = 5

        return {**_MATURITY_LEVELS[level]}

    def _build_recommendations(
        self,
        report: ScanReport,
        function_assessment: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build prioritised remediation recommendations."""
        recommendations: list[dict[str, Any]] = []

        # Critical findings
        for finding in report.findings:
            if (
                finding.verdict == Verdict.VULNERABLE
                and finding.severity == Severity.CRITICAL
            ):
                rmf_func = self._function_for_asi(finding.category)
                recommendations.append({
                    "priority": "CRITICAL",
                    "recommendation": (
                        f"Remediate {finding.scenario_name}: "
                        f"{finding.remediation}"
                    ),
                    "rmf_function": rmf_func,
                    "asi_category": finding.category.value,
                    "finding_id": finding.finding_id,
                })

        # High severity
        for finding in report.findings:
            if (
                finding.verdict == Verdict.VULNERABLE
                and finding.severity == Severity.HIGH
            ):
                rmf_func = self._function_for_asi(finding.category)
                recommendations.append({
                    "priority": "HIGH",
                    "recommendation": (
                        f"Remediate {finding.scenario_name}: "
                        f"{finding.remediation}"
                    ),
                    "rmf_function": rmf_func,
                    "asi_category": finding.category.value,
                    "finding_id": finding.finding_id,
                })

        # Uncovered RMF functions
        for func_name, func_data in function_assessment.items():
            if func_data["scenarios_tested"] == 0:
                mapped = ", ".join(func_data["mapped_asi"])
                recommendations.append({
                    "priority": "INFO",
                    "recommendation": (
                        f"No scenarios tested for RMF function "
                        f"'{func_name}' (ASI categories: {mapped}). "
                        f"Expand test coverage for complete RMF assessment."
                    ),
                    "rmf_function": func_name,
                    "asi_category": None,
                    "finding_id": None,
                })

        return recommendations

    def _function_for_asi(self, category: ASICategory) -> str:
        """Return the NIST RMF function name for a given ASI category."""
        for func_name, func_info in NIST_RMF_FUNCTION_MAPPING.items():
            if category in func_info["mapped_asi"]:
                return func_name
        return "MANAGE"

    def _evidence_summary(self, report: ScanReport) -> dict[str, Any]:
        """Build evidence summary counts."""
        tested_categories = {r.category.value for r in report.results}
        return {
            "total_scenarios": report.total_scenarios,
            "vulnerable": report.vulnerable,
            "safe": report.safe,
            "inconclusive": report.inconclusive,
            "errors": report.errors,
            "refusal_echo": report.refusal_echo_count,
            "vulnerability_rate": report.vulnerability_rate,
            "overall_risk_score": report.overall_risk_score,
            "asi_categories_tested": len(tested_categories),
            "asi_categories_total": len(ASICategory),
        }
