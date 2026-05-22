"""EU AI Act Article 50 compliance reporter.

Maps AASTF scan findings to EU AI Act articles and generates
compliance evidence reports for auditors and legal teams.

Article 50 (Transparency obligations) enforcement: 2 August 2026.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models.result import ScanReport, Verdict
from ..models.scenario import ASICategory, Severity
from ..scoring import eu_ai_act_readiness

# ---------------------------------------------------------------------------
# EU AI Act article mapping
# ---------------------------------------------------------------------------
# Each ASI category maps to one or more EU AI Act articles.
# Primary focus: Article 50 (transparency, enforced Aug 2 2026).
# Secondary: high-risk articles (Arts 9-15, enforced Dec 2027) included
# for forward-looking compliance posture.

_ArticleMapping = dict[str, Any]

EU_AI_ACT_ARTICLE_MAPPING: dict[str, list[_ArticleMapping]] = {
    ASICategory.ASI01: [
        {
            "article_number": "Art. 50(3)",
            "article_title": "AI-generated text disclosure",
            "requirement": "AI systems generating text shall be designed so output "
            "is marked as artificially generated, unless under human review.",
            "how_aastf_tests_it": "ASI01 (Agent Goal Hijack) tests whether adversarial "
            "prompts can override agent goals, including suppressing mandatory "
            "disclosure of AI-generated content.",
        },
        {
            "article_number": "Art. 9",
            "article_title": "Risk management system",
            "requirement": "High-risk AI systems shall have a risk management system "
            "established, implemented, documented and maintained.",
            "how_aastf_tests_it": "ASI01 goal hijack scenarios validate that the agent's "
            "risk controls resist adversarial override attempts.",
        },
        {
            "article_number": "Art. 14",
            "article_title": "Human oversight",
            "requirement": "High-risk AI systems shall be designed to be effectively "
            "overseen by natural persons during use.",
            "how_aastf_tests_it": "ASI01 tests whether agents can be hijacked to bypass "
            "human-in-the-loop controls.",
        },
    ],
    ASICategory.ASI02: [
        {
            "article_number": "Art. 15",
            "article_title": "Accuracy, robustness and cybersecurity",
            "requirement": "High-risk AI systems shall be resilient against attempts "
            "by unauthorised third parties to alter their use or performance "
            "by exploiting system vulnerabilities.",
            "how_aastf_tests_it": "ASI02 (Tool Misuse) tests whether agents can be tricked "
            "into calling unauthorised tools or APIs via poisoned inputs.",
        },
        {
            "article_number": "Art. 9",
            "article_title": "Risk management system",
            "requirement": "Residual risks shall be communicated to the deployer.",
            "how_aastf_tests_it": "ASI02 identifies tool-misuse attack surfaces that must "
            "be documented in the risk management system.",
        },
    ],
    ASICategory.ASI03: [
        {
            "article_number": "Art. 50(4)",
            "article_title": "Emotion recognition and biometric categorisation",
            "requirement": "Deployers of emotion recognition or biometric categorisation "
            "systems shall inform natural persons exposed thereto.",
            "how_aastf_tests_it": "ASI03 (Identity & Privilege Abuse) tests whether agents "
            "can be manipulated to impersonate users or escalate privileges, "
            "which directly undermines biometric/identity disclosure obligations.",
        },
        {
            "article_number": "Art. 13",
            "article_title": "Transparency and provision of information to deployers",
            "requirement": "High-risk AI systems shall be designed to ensure their "
            "operation is sufficiently transparent.",
            "how_aastf_tests_it": "ASI03 identity abuse scenarios test whether privilege "
            "escalation can bypass transparency controls.",
        },
    ],
    ASICategory.ASI04: [
        {
            "article_number": "Art. 15",
            "article_title": "Accuracy, robustness and cybersecurity",
            "requirement": "High-risk AI systems shall achieve an appropriate level "
            "of cybersecurity throughout their lifecycle.",
            "how_aastf_tests_it": "ASI04 (Supply Chain Vulnerabilities) tests whether "
            "malicious dependencies, plugins, or tool registries can "
            "compromise agent behaviour.",
        },
        {
            "article_number": "Art. 9",
            "article_title": "Risk management system",
            "requirement": "Risks from foreseeable misuse shall be identified and mitigated.",
            "how_aastf_tests_it": "ASI04 supply-chain scenarios identify risks from "
            "third-party components that must be assessed in the risk "
            "management system.",
        },
    ],
    ASICategory.ASI05: [
        {
            "article_number": "Art. 15",
            "article_title": "Accuracy, robustness and cybersecurity",
            "requirement": "AI systems shall be resilient against exploitation of "
            "system vulnerabilities by unauthorised third parties.",
            "how_aastf_tests_it": "ASI05 (Unexpected Code Execution) tests whether agents "
            "can be tricked into executing arbitrary code, representing "
            "a critical cybersecurity failure.",
        },
    ],
    ASICategory.ASI06: [
        {
            "article_number": "Art. 12",
            "article_title": "Record-keeping",
            "requirement": "High-risk AI systems shall technically allow for automatic "
            "recording of events (logs) throughout their lifetime.",
            "how_aastf_tests_it": "ASI06 (Memory & Context Poisoning) tests whether agent "
            "memory or context can be corrupted, which would compromise "
            "the integrity of logged events and records.",
        },
        {
            "article_number": "Art. 15",
            "article_title": "Accuracy, robustness and cybersecurity",
            "requirement": "AI systems shall maintain accuracy when operating in "
            "adversarial environments.",
            "how_aastf_tests_it": "ASI06 tests whether adversarial context injection can "
            "degrade agent accuracy and decision quality.",
        },
    ],
    ASICategory.ASI07: [
        {
            "article_number": "Art. 15",
            "article_title": "Accuracy, robustness and cybersecurity",
            "requirement": "Cybersecurity measures shall be proportionate to the risks.",
            "how_aastf_tests_it": "ASI07 (Insecure Inter-Agent Communication) tests whether "
            "agent-to-agent messages can be intercepted, spoofed, or "
            "tampered with.",
        },
        {
            "article_number": "Art. 11",
            "article_title": "Technical documentation",
            "requirement": "Technical documentation shall be drawn up before the system "
            "is placed on the market.",
            "how_aastf_tests_it": "ASI07 findings reveal inter-agent communication attack "
            "surfaces that must be documented.",
        },
    ],
    ASICategory.ASI08: [
        {
            "article_number": "Art. 15",
            "article_title": "Accuracy, robustness and cybersecurity",
            "requirement": "AI systems shall be designed to achieve appropriate levels "
            "of robustness.",
            "how_aastf_tests_it": "ASI08 (Cascading Failures) tests whether adversarial "
            "inputs can trigger runaway loops or resource exhaustion.",
        },
        {
            "article_number": "Art. 9",
            "article_title": "Risk management system",
            "requirement": "Known and reasonably foreseeable risks shall be identified "
            "and analysed.",
            "how_aastf_tests_it": "ASI08 cascading failure scenarios identify denial-of-service "
            "risks that must be included in risk assessments.",
        },
    ],
    ASICategory.ASI09: [
        {
            "article_number": "Art. 50(1)",
            "article_title": "Transparency for AI-generated content",
            "requirement": "Providers shall ensure AI systems designed to directly "
            "interact with natural persons are designed so that the "
            "natural person is informed they are interacting with an AI.",
            "how_aastf_tests_it": "ASI09 (Human-Agent Trust Exploitation) directly tests "
            "whether agents can be manipulated to suppress their AI "
            "identity or deceive users about their nature.",
        },
        {
            "article_number": "Art. 50(2)",
            "article_title": "Deepfake disclosure",
            "requirement": "Providers of AI systems generating synthetic audio, image, "
            "video or text content shall ensure the output is marked "
            "in a machine-readable format as artificially generated.",
            "how_aastf_tests_it": "ASI09 tests whether agents can be tricked into generating "
            "content without mandatory AI-generated disclosure markers.",
        },
        {
            "article_number": "Art. 50(3)",
            "article_title": "AI-generated text disclosure",
            "requirement": "Deployers using AI to generate text published to inform "
            "the public on matters of public interest shall disclose "
            "that the text was artificially generated.",
            "how_aastf_tests_it": "ASI09 trust exploitation scenarios test whether agents "
            "maintain transparency obligations under adversarial pressure.",
        },
        {
            "article_number": "Art. 13",
            "article_title": "Transparency and provision of information to deployers",
            "requirement": "High-risk AI systems shall be designed to ensure sufficient "
            "transparency for deployers to interpret output appropriately.",
            "how_aastf_tests_it": "ASI09 tests whether trust exploitation attacks can "
            "undermine deployer transparency requirements.",
        },
    ],
    ASICategory.ASI10: [
        {
            "article_number": "Art. 14",
            "article_title": "Human oversight",
            "requirement": "High-risk AI systems shall be effectively overseen by "
            "natural persons, including the ability to interrupt or "
            "stop the system.",
            "how_aastf_tests_it": "ASI10 (Rogue Agents) tests whether agents can operate "
            "outside intended boundaries, evade shutdown commands, or "
            "resist human override — directly challenging Art. 14 "
            "human oversight requirements.",
        },
        {
            "article_number": "Art. 9",
            "article_title": "Risk management system",
            "requirement": "The risk management system shall identify risks associated "
            "with the AI system.",
            "how_aastf_tests_it": "ASI10 rogue agent scenarios identify risks from autonomous "
            "agent behaviour that must be assessed and mitigated.",
        },
        {
            "article_number": "Art. 15",
            "article_title": "Accuracy, robustness and cybersecurity",
            "requirement": "AI systems shall be resilient against attempts to alter "
            "their intended purpose.",
            "how_aastf_tests_it": "ASI10 tests whether agents can escape their operational "
            "sandbox or override safety constraints.",
        },
    ],
}


# ---------------------------------------------------------------------------
# Readiness status display helpers
# ---------------------------------------------------------------------------

_READINESS_DISPLAY = {
    "compliant": {
        "label": "COMPLIANT",
        "description": "No critical or high-severity behavioural vulnerabilities detected. "
        "System meets minimum EU AI Act readiness threshold.",
    },
    "at_risk": {
        "label": "AT RISK",
        "description": "High-severity vulnerabilities or high-severity refusal-echo findings "
        "detected. Remediation required before production deployment.",
    },
    "non_compliant": {
        "label": "NON-COMPLIANT",
        "description": "Critical behavioural vulnerabilities detected. System does not meet "
        "EU AI Act requirements. Immediate remediation required.",
    },
}


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------


class EUAIActReporter:
    """Generates EU AI Act Article 50 compliance evidence from AASTF scan results.

    Primary focus: Article 50 transparency obligations (enforced 2 August 2026).
    Secondary: high-risk system articles (Arts 9-15, enforced December 2027)
    for forward-looking compliance posture assessment.
    """

    def generate(self, report: ScanReport) -> dict[str, Any]:
        """Generate EU AI Act compliance evidence as a dict."""
        readiness = eu_ai_act_readiness(report)
        article_50_assessment = self._assess_article_50(report)
        per_article = self._per_article_findings(report)
        asi_mapping = self._asi_to_article_mapping(report)
        recommendations = self._build_recommendations(report, readiness, per_article)
        evidence = self._evidence_summary(report)

        return {
            "report_metadata": {
                "framework": "aastf",
                "aastf_version": report.aastf_version,
                "scan_date": report.generated_at.isoformat(),
                "run_id": report.run_id,
                "report_type": "eu_ai_act_article_50",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "overall_readiness": {
                "status": readiness,
                **_READINESS_DISPLAY.get(readiness, _READINESS_DISPLAY["at_risk"]),
            },
            "article_50_assessment": article_50_assessment,
            "per_article_findings": per_article,
            "asi_to_article_mapping": asi_mapping,
            "recommendations": recommendations,
            "evidence_summary": evidence,
        }

    def generate_json(self, report: ScanReport) -> str:
        """Return compliance report as a JSON string."""
        return json.dumps(self.generate(report), indent=2, default=str)

    def write(self, report: ScanReport, output_path: Path) -> Path:
        """Write compliance report to output_path."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate_json(report), encoding="utf-8")
        return output_path

    def generate_markdown(self, report: ScanReport) -> str:
        """Generate human-readable markdown report suitable for auditors."""
        data = self.generate(report)
        readiness = data["overall_readiness"]
        meta = data["report_metadata"]
        a50 = data["article_50_assessment"]
        evidence = data["evidence_summary"]

        lines: list[str] = []
        _a = lines.append

        # Header
        _a("# EU AI Act Compliance Report")
        _a("")
        _a("## Executive Summary")
        _a("")
        _a(f"**AASTF Version:** {meta['aastf_version']}  ")
        _a(f"**Scan Date:** {meta['scan_date']}  ")
        _a(f"**Run ID:** `{meta['run_id']}`  ")
        _a(f"**Report Generated:** {meta['generated_at']}")
        _a("")
        _a(f"**EU AI Act Readiness: {readiness['label']}**")
        _a("")
        _a(f"> {readiness['description']}")
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

        # Article 50 assessment
        _a("## Article 50 Transparency Assessment")
        _a("")
        _a("**Enforcement Date:** 2 August 2026")
        _a("")

        for item in a50:
            status_icon = "PASS" if item["status"] == "pass" else "FAIL" if item["status"] == "fail" else "NOT TESTED"
            _a(f"### {item['article_number']}: {item['article_title']}")
            _a("")
            _a(f"**Status:** {status_icon}  ")
            _a(f"**Requirement:** {item['requirement']}")
            _a("")
            if item["findings"]:
                _a("**Findings:**")
                _a("")
                for f in item["findings"]:
                    _a(f"- [{f['severity']}] {f['scenario_name']} — {f['verdict']}")
                _a("")
            else:
                _a("No findings for this article.")
                _a("")

        # Per-article findings table
        _a("## Per-Article Findings")
        _a("")
        _a("| Article | Title | Findings | Vulnerable | Status |")
        _a("|---------|-------|----------|------------|--------|")
        for _article_key, article_data in data["per_article_findings"].items():
            vuln_count = sum(
                1 for f in article_data["findings"] if f["verdict"] == "VULNERABLE"
            )
            total = len(article_data["findings"])
            status = "PASS" if vuln_count == 0 and total > 0 else "FAIL" if vuln_count > 0 else "NOT TESTED"
            _a(
                f"| {article_data['article_number']} | {article_data['article_title']} "
                f"| {total} | {vuln_count} | {status} |"
            )
        _a("")

        # ASI category coverage matrix
        _a("## ASI Category Coverage Matrix")
        _a("")
        _a("| ASI Category | Name | Mapped Articles | Tested | Vulnerable |")
        _a("|-------------|------|-----------------|--------|------------|")
        for cat_key, cat_data in data["asi_to_article_mapping"].items():
            articles_str = ", ".join(cat_data["mapped_articles"])
            tested = cat_data["scenarios_tested"]
            vuln = cat_data["vulnerabilities_found"]
            _a(f"| {cat_key} | {cat_data['name']} | {articles_str} | {tested} | {vuln} |")
        _a("")

        # Recommendations
        _a("## Recommendations")
        _a("")
        if data["recommendations"]:
            for i, rec in enumerate(data["recommendations"], 1):
                _a(f"{i}. **[{rec['priority']}]** {rec['recommendation']}")
                if rec.get("article"):
                    _a(f"   - Related article: {rec['article']}")
                if rec.get("asi_category"):
                    _a(f"   - ASI category: {rec['asi_category']}")
            _a("")
        else:
            _a("No recommendations — all tested scenarios passed.")
            _a("")

        # Scan metadata
        _a("## Scan Metadata")
        _a("")
        _a("- **Framework:** AASTF (Agentic AI Security Testing Framework)")
        _a(f"- **Version:** {meta['aastf_version']}")
        _a(f"- **Adapter:** {report.adapter}")
        _a(f"- **Run ID:** `{meta['run_id']}`")
        _a(f"- **Scan Date:** {meta['scan_date']}")
        _a("- **Report Type:** EU AI Act Article 50 Compliance")
        _a("")
        _a("---")
        _a("")
        _a("*This report was generated by AASTF. It provides evidence for EU AI Act "
           "compliance assessment but does not constitute legal advice. Consult qualified "
           "legal counsel for formal compliance determination.*")
        _a("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assess_article_50(self, report: ScanReport) -> list[dict[str, Any]]:
        """Assess compliance with each Article 50 sub-article."""
        # Article 50 sub-articles and the ASI categories that test them
        article_50_items = [
            {
                "article_number": "Art. 50(1)",
                "article_title": "Transparency for AI-generated content",
                "requirement": "Providers shall ensure AI systems designed to directly "
                "interact with natural persons are designed so that the "
                "natural person is informed they are interacting with an AI.",
                "relevant_asi": [ASICategory.ASI09],
            },
            {
                "article_number": "Art. 50(2)",
                "article_title": "Deepfake disclosure",
                "requirement": "Providers of AI systems generating synthetic audio, image, "
                "video or text content shall ensure the output is marked "
                "in a machine-readable format as artificially generated.",
                "relevant_asi": [ASICategory.ASI09],
            },
            {
                "article_number": "Art. 50(3)",
                "article_title": "AI-generated text disclosure",
                "requirement": "Deployers using AI to generate text published to inform "
                "the public on matters of public interest shall disclose "
                "that the text was artificially generated.",
                "relevant_asi": [ASICategory.ASI01, ASICategory.ASI09],
            },
            {
                "article_number": "Art. 50(4)",
                "article_title": "Emotion recognition and biometric categorisation",
                "requirement": "Deployers of emotion recognition or biometric categorisation "
                "systems shall inform natural persons exposed thereto.",
                "relevant_asi": [ASICategory.ASI03],
            },
        ]

        assessed: list[dict[str, Any]] = []
        for item in article_50_items:
            relevant_findings = [
                f for f in report.findings
                if f.category in item["relevant_asi"]
            ]
            vulnerable_findings = [
                f for f in relevant_findings if f.verdict == Verdict.VULNERABLE
            ]

            if not relevant_findings:
                status = "not_tested"
            elif vulnerable_findings:
                status = "fail"
            else:
                status = "pass"

            assessed.append({
                "article_number": item["article_number"],
                "article_title": item["article_title"],
                "requirement": item["requirement"],
                "status": status,
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "scenario_id": f.scenario_id,
                        "scenario_name": f.scenario_name,
                        "severity": f.severity.value,
                        "verdict": f.verdict.value,
                    }
                    for f in relevant_findings
                ],
            })

        return assessed

    def _per_article_findings(self, report: ScanReport) -> dict[str, dict[str, Any]]:
        """Group findings by EU AI Act article."""
        # Collect all unique articles from the mapping
        articles: dict[str, dict[str, Any]] = {}

        for cat in ASICategory:
            mappings = EU_AI_ACT_ARTICLE_MAPPING.get(cat, [])
            for mapping in mappings:
                art_num = mapping["article_number"]
                if art_num not in articles:
                    articles[art_num] = {
                        "article_number": art_num,
                        "article_title": mapping["article_title"],
                        "requirement": mapping["requirement"],
                        "mapped_asi_categories": [],
                        "findings": [],
                    }
                if cat.value not in articles[art_num]["mapped_asi_categories"]:
                    articles[art_num]["mapped_asi_categories"].append(cat.value)

        # Map findings to articles
        for finding in report.findings:
            mappings = EU_AI_ACT_ARTICLE_MAPPING.get(finding.category, [])
            for mapping in mappings:
                art_num = mapping["article_number"]
                if art_num in articles:
                    articles[art_num]["findings"].append({
                        "finding_id": finding.finding_id,
                        "scenario_id": finding.scenario_id,
                        "scenario_name": finding.scenario_name,
                        "category": finding.category.value,
                        "severity": finding.severity.value,
                        "verdict": finding.verdict.value,
                        "cvss_score": finding.cvss_score,
                    })

        return articles

    def _asi_to_article_mapping(self, report: ScanReport) -> dict[str, dict[str, Any]]:
        """Build ASI category to article mapping with test coverage."""
        result: dict[str, dict[str, Any]] = {}

        for cat in ASICategory:
            mappings = EU_AI_ACT_ARTICLE_MAPPING.get(cat, [])
            mapped_articles = [m["article_number"] for m in mappings]

            # Count scenarios tested for this category
            cat_results = [r for r in report.results if r.category == cat]
            cat_findings = [f for f in report.findings if f.category == cat]
            vuln_count = sum(1 for f in cat_findings if f.verdict == Verdict.VULNERABLE)

            result[cat.value] = {
                "name": cat.display_name,
                "mapped_articles": mapped_articles,
                "scenarios_tested": len(cat_results),
                "vulnerabilities_found": vuln_count,
                "findings_count": len(cat_findings),
            }

        return result

    def _build_recommendations(
        self,
        report: ScanReport,
        readiness: str,
        per_article: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build prioritised remediation recommendations."""
        recommendations: list[dict[str, Any]] = []

        # Critical findings first
        critical_vulns = [
            f for f in report.findings
            if f.verdict == Verdict.VULNERABLE and f.severity == Severity.CRITICAL
        ]
        for finding in critical_vulns:
            recommendations.append({
                "priority": "CRITICAL",
                "recommendation": f"Remediate {finding.scenario_name}: {finding.remediation}",
                "article": self._primary_article_for_category(finding.category),
                "asi_category": finding.category.value,
                "finding_id": finding.finding_id,
            })

        # High severity
        high_vulns = [
            f for f in report.findings
            if f.verdict == Verdict.VULNERABLE and f.severity == Severity.HIGH
        ]
        for finding in high_vulns:
            recommendations.append({
                "priority": "HIGH",
                "recommendation": f"Remediate {finding.scenario_name}: {finding.remediation}",
                "article": self._primary_article_for_category(finding.category),
                "asi_category": finding.category.value,
                "finding_id": finding.finding_id,
            })

        # Refusal echo at critical/high
        echo_findings = [
            f for f in report.findings
            if f.verdict == Verdict.REFUSAL_ECHO
            and f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        for finding in echo_findings:
            recommendations.append({
                "priority": "MEDIUM",
                "recommendation": f"Sanitise refusal output for {finding.scenario_name}: "
                f"agent echoes adversarial payload in refusal text. "
                f"{finding.remediation}",
                "article": "Art. 15",
                "asi_category": finding.category.value,
                "finding_id": finding.finding_id,
            })

        # Untested ASI categories
        tested_categories = {r.category for r in report.results}
        untested = [cat for cat in ASICategory if cat not in tested_categories]
        for cat in untested:
            recommendations.append({
                "priority": "INFO",
                "recommendation": f"No scenarios tested for {cat.value} ({cat.display_name}). "
                f"Expand test coverage for complete compliance assessment.",
                "article": self._primary_article_for_category(cat),
                "asi_category": cat.value,
                "finding_id": None,
            })

        # Article 50 specific — if ASI09 not tested
        if ASICategory.ASI09 not in tested_categories:
            recommendations.append({
                "priority": "HIGH",
                "recommendation": "Article 50 transparency obligations cannot be assessed "
                "without ASI09 (Human-Agent Trust Exploitation) test coverage. "
                "Add ASI09 scenarios before the 2 August 2026 enforcement deadline.",
                "article": "Art. 50",
                "asi_category": "ASI09",
                "finding_id": None,
            })

        return recommendations

    def _primary_article_for_category(self, category: ASICategory) -> str:
        """Return the primary (first) article number for an ASI category."""
        mappings = EU_AI_ACT_ARTICLE_MAPPING.get(category, [])
        if mappings:
            return mappings[0]["article_number"]
        return "Art. 15"

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
