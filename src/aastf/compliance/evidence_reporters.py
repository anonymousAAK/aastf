"""Article-specific EU AI Act evidence reporters.

Each reporter class generates structured output from an AASTF ScanReport,
targeting a specific EU AI Act article's documentation requirements.

- Article9RiskRegister          — risk register as list[dict], CSV export
- Article11TechDoc              — technical documentation JSON
- Article12AutoLog              — automatic event log as NDJSON
- Article13TransparencyDeclaration — transparency declaration as Markdown
- Article14OversightChecklist   — human oversight checklist JSON
- Article15TestMatrix           — test matrix JSON with robustness scores
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ..models.result import ScanReport, TestResult, Verdict
from ..models.scenario import ASICategory, Severity
from .eu_ai_act import EU_AI_ACT_ARTICLE_MAPPING

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_VERDICT_TO_MITIGATION: dict[str, str] = {
    Verdict.VULNERABLE: "open",
    Verdict.SAFE: "mitigated",
    Verdict.REFUSAL_ECHO: "partial",
    Verdict.INCONCLUSIVE: "under_review",
    Verdict.ERROR: "error",
    Verdict.TOOL_POISONING: "open",
    Verdict.SCHEMA_POISONING: "open",
    Verdict.PREFERENCE_MANIPULATION: "open",
}

_SEVERITY_TO_RESIDUAL: dict[str, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 1.0,
}

_ACCURACY_CATEGORIES = {ASICategory.ASI01, ASICategory.ASI09}
_ROBUSTNESS_CATEGORIES = {ASICategory.ASI06, ASICategory.ASI08}
_CYBERSECURITY_CATEGORIES = {
    ASICategory.ASI02,
    ASICategory.ASI03,
    ASICategory.ASI04,
    ASICategory.ASI05,
    ASICategory.ASI07,
    ASICategory.ASI10,
}

_OVERSIGHT_REQUIREMENTS: dict[str, str] = {
    ASICategory.ASI01: "Monitor for goal hijacking; ensure agent objectives cannot be overridden by adversarial inputs.",
    ASICategory.ASI02: "Review tool invocations for unauthorised API calls or tool misuse patterns.",
    ASICategory.ASI03: "Verify identity controls; ensure privilege escalation attempts are blocked and logged.",
    ASICategory.ASI04: "Audit supply chain dependencies; verify integrity of plugins and tool registries.",
    ASICategory.ASI05: "Restrict code execution capabilities; review all generated code before execution.",
    ASICategory.ASI06: "Validate memory and context integrity; detect poisoned context injections.",
    ASICategory.ASI07: "Secure inter-agent communication channels; authenticate agent-to-agent messages.",
    ASICategory.ASI08: "Implement circuit breakers; monitor for cascading failure patterns and resource exhaustion.",
    ASICategory.ASI09: "Enforce AI disclosure requirements; verify transparency obligations under adversarial pressure.",
    ASICategory.ASI10: "Maintain kill-switch capability; ensure agents cannot evade shutdown or override commands.",
}

_ESCALATION_THRESHOLDS: dict[str, str] = {
    Severity.CRITICAL: "immediate",
    Severity.HIGH: "within_4_hours",
    Severity.MEDIUM: "within_24_hours",
    Severity.LOW: "weekly_review",
    Severity.INFO: "quarterly_review",
}


def _truncate(text: str, length: int = 200) -> str:
    s = str(text)
    return s[:length] + "..." if len(s) > length else s


def _primary_article(category: ASICategory) -> str:
    mappings = EU_AI_ACT_ARTICLE_MAPPING.get(category, [])
    return mappings[0]["article_number"] if mappings else "Art. 15"


def _category_counts(results: list[TestResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        key = r.category.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _results_for_categories(
    results: list[TestResult],
    categories: set[ASICategory],
) -> list[TestResult]:
    return [r for r in results if r.category in categories]


# ===================================================================
# Article reporters
# ===================================================================


class Article9RiskRegister:
    """Art. 9 risk register reporter."""

    def generate(self, report: ScanReport) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        timestamp = report.generated_at.isoformat()

        for i, result in enumerate(report.results, start=1):
            verdict_str = result.verdict.value if isinstance(result.verdict, Verdict) else str(result.verdict)
            severity_str = result.severity.value if isinstance(result.severity, Severity) else str(result.severity)

            mitigation = _VERDICT_TO_MITIGATION.get(verdict_str, "under_review")
            residual = _SEVERITY_TO_RESIDUAL.get(severity_str, 5.0)
            if mitigation == "mitigated":
                residual = round(residual * 0.1, 1)
            elif mitigation == "partial":
                residual = round(residual * 0.5, 1)

            rows.append({
                "risk_id": f"RISK-{i:04d}",
                "asi_category": result.category.value,
                "scenario_id": result.scenario_id,
                "scenario_name": result.scenario_name,
                "severity": severity_str,
                "verdict": verdict_str,
                "mitigation_status": mitigation,
                "residual_risk_score": residual,
                "last_tested": timestamp,
                "mapped_article": _primary_article(result.category),
            })

        return rows

    def to_csv(self, report: ScanReport, path: Path) -> Path:
        rows = self.generate(report)
        path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "risk_id", "asi_category", "scenario_id", "scenario_name",
            "severity", "verdict", "mitigation_status", "residual_risk_score",
            "last_tested", "mapped_article",
        ]

        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        return path


class Article11TechDoc:
    """Art. 11 technical documentation reporter."""

    def generate(self, report: ScanReport) -> dict[str, Any]:
        vuln_categories = sorted({
            r.category.display_name
            for r in report.results
            if r.verdict == Verdict.VULNERABLE
        })

        scenario_coverage = _category_counts(report.results)

        tools_tested: set[str] = set()
        for r in report.results:
            tools_tested.update(r.trace.tools_called())

        return {
            "system_description": f"Agentic AI system tested via {report.adapter} adapter",
            "aastf_version": report.aastf_version,
            "scan_date": report.generated_at.isoformat(),
            "framework_adapter": report.adapter,
            "scenario_pack_version": f"{report.total_scenarios} scenarios",
            "intended_purpose": "To be completed by the deployer — describe the intended purpose of the AI system.",
            "known_limitations": vuln_categories,
            "test_methodology": "OWASP ASI Top 10 adversarial testing via AASTF sandbox",
            "asi_categories_tested": sorted({r.category.value for r in report.results}),
            "tools_tested": sorted(tools_tested),
            "scenario_coverage": scenario_coverage,
            "risk_assessment_summary": {
                "total_scenarios_tested": report.total_scenarios,
                "vulnerability_rate_percent": report.vulnerability_rate,
                "overall_risk_score": report.overall_risk_score,
                "critical_findings": len(report.critical_findings),
                "eu_ai_act_readiness": report.eu_ai_act_readiness,
                "run_id": report.run_id,
            },
        }


class Article12AutoLog:
    """Art. 12 automatic logging reporter."""

    DEFAULT_RETENTION_DAYS: int = 180

    def generate(self, report: ScanReport) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []

        for result in report.results:
            timestamp = report.generated_at.isoformat()
            tool_names = result.trace.tools_called()
            decision_path = " -> ".join(tool_names) if tool_names else "no_tool_calls"

            # One entry per result (agent decision + evaluation)
            entries.append({
                "timestamp": timestamp,
                "event_type": "evaluation",
                "scenario_id": result.scenario_id,
                "tool_name": None,
                "inputs_summary": _truncate(result.scenario_name),
                "output_summary": _truncate(result.trace.final_output or ""),
                "verdict": result.verdict.value,
                "severity": result.severity.value,
                "agent_decision_path": decision_path,
                "retention_days": self.DEFAULT_RETENTION_DAYS,
            })

            # One entry per tool invocation
            for inv in result.trace.tool_invocations:
                entries.append({
                    "timestamp": timestamp,
                    "event_type": "tool_call",
                    "scenario_id": result.scenario_id,
                    "tool_name": inv.tool_name,
                    "inputs_summary": _truncate(str(inv.inputs)),
                    "output_summary": _truncate(str(inv.outputs)),
                    "verdict": result.verdict.value,
                    "severity": result.severity.value,
                    "agent_decision_path": decision_path,
                    "retention_days": self.DEFAULT_RETENTION_DAYS,
                })

        return entries

    def to_ndjson(self, report: ScanReport, path: Path) -> Path:
        entries = self.generate(report)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as fh:
            for entry in entries:
                fh.write(json.dumps(entry, default=str) + "\n")

        return path


class Article13TransparencyDeclaration:
    """Art. 13 transparency declaration reporter."""

    def generate(self, report: ScanReport) -> dict[str, Any]:
        tested_categories = sorted({r.category.display_name for r in report.results})
        vuln_categories = sorted({
            r.category.display_name
            for r in report.results
            if r.verdict == Verdict.VULNERABLE
        })

        oversight_tested = [
            r.scenario_name
            for r in report.results
            if r.category == ASICategory.ASI10
        ]

        return {
            "system_name": report.adapter,
            "capabilities_tested": tested_categories,
            "known_limitations": vuln_categories,
            "ai_generated_content_disclosure": (
                "This system may generate AI-produced content. Outputs are "
                "subject to adversarial robustness testing via AASTF to verify "
                "compliance with EU AI Act Article 50 transparency obligations. "
                "Users should be aware that AI-generated content may not always "
                "be explicitly marked under adversarial conditions."
            ),
            "human_oversight_mechanisms_tested": oversight_tested,
            "test_summary": {
                "total_scenarios": report.total_scenarios,
                "vulnerability_rate_percent": report.vulnerability_rate,
                "scan_date": report.generated_at.isoformat(),
                "aastf_version": report.aastf_version,
            },
        }

    def to_markdown(self, report: ScanReport) -> str:
        data = self.generate(report)
        lines: list[str] = []
        _a = lines.append

        _a(f"# Transparency Declaration: {data['system_name']}")
        _a("")
        _a("## System Overview")
        _a("")
        _a(f"This document describes the transparency properties of the **{data['system_name']}** "
           f"AI system, assessed using AASTF v{data['test_summary']['aastf_version']}.")
        _a("")

        _a("## Capabilities Tested")
        _a("")
        if data["capabilities_tested"]:
            for cap in data["capabilities_tested"]:
                _a(f"- {cap}")
        else:
            _a("No capabilities were tested in this scan.")
        _a("")

        _a("## Known Limitations")
        _a("")
        if data["known_limitations"]:
            _a("The following security categories had at least one vulnerable finding:")
            _a("")
            for lim in data["known_limitations"]:
                _a(f"- {lim}")
        else:
            _a("No vulnerabilities were detected in the tested scenarios.")
        _a("")

        _a("## AI-Generated Content Disclosure")
        _a("")
        _a(data["ai_generated_content_disclosure"])
        _a("")

        _a("## Human Oversight Mechanisms Tested")
        _a("")
        if data["human_oversight_mechanisms_tested"]:
            for mechanism in data["human_oversight_mechanisms_tested"]:
                _a(f"- {mechanism}")
        else:
            _a("No human oversight scenarios (ASI10) were included in this scan.")
        _a("")

        _a("## Test Summary")
        _a("")
        _a(f"- **Scenarios tested:** {data['test_summary']['total_scenarios']}")
        _a(f"- **Vulnerability rate:** {data['test_summary']['vulnerability_rate_percent']}%")
        _a(f"- **Scan date:** {data['test_summary']['scan_date']}")
        _a("")

        _a("---")
        _a("")
        _a("*Generated by AASTF. This document supports EU AI Act Art. 13 transparency "
           "requirements but does not constitute legal advice.*")
        _a("")

        return "\n".join(lines)


class Article14OversightChecklist:
    """Art. 14 human oversight checklist reporter."""

    def generate(self, report: ScanReport) -> list[dict[str, Any]]:
        category_results: dict[str, list[TestResult]] = {}
        for r in report.results:
            key = r.category.value
            category_results.setdefault(key, []).append(r)

        asi10_present = any(r.category == ASICategory.ASI10 for r in report.results)

        checklist: list[dict[str, Any]] = []

        for cat in ASICategory:
            results = category_results.get(cat.value, [])
            if not results:
                continue

            has_vulnerable = any(r.verdict == Verdict.VULNERABLE for r in results)

            vuln_severities = [
                r.severity for r in results if r.verdict == Verdict.VULNERABLE
            ]
            if vuln_severities:
                highest = max(vuln_severities, key=lambda s: s.numeric())
                threshold = _ESCALATION_THRESHOLDS.get(highest.value, "weekly_review")
            else:
                threshold = "quarterly_review"

            checklist.append({
                "category": cat.value,
                "category_name": cat.display_name,
                "oversight_requirement": _OVERSIGHT_REQUIREMENTS.get(cat.value, ""),
                "scenarios_tested": len(results),
                "human_review_required": has_vulnerable,
                "escalation_threshold": threshold,
                "override_mechanism_tested": asi10_present,
            })

        return checklist


class Article15TestMatrix:
    """Art. 15 test matrix reporter."""

    def generate(self, report: ScanReport) -> dict[str, Any]:
        domains = {
            "accuracy": _ACCURACY_CATEGORIES,
            "robustness": _ROBUSTNESS_CATEGORIES,
            "cybersecurity": _CYBERSECURITY_CATEGORIES,
        }

        matrix: dict[str, Any] = {}

        for domain_name, categories in domains.items():
            domain_results = _results_for_categories(report.results, categories)
            total = len(domain_results)
            safe = sum(1 for r in domain_results if r.verdict == Verdict.SAFE)
            vulnerable = sum(1 for r in domain_results if r.verdict == Verdict.VULNERABLE)

            pass_rate = round(safe / total * 100, 1) if total > 0 else 0.0

            tested_cats = {r.category for r in domain_results}
            coverage = round(len(tested_cats) / len(categories) * 100, 1) if categories else 0.0

            matrix[domain_name] = {
                "pass_rate": pass_rate,
                "scenarios_tested": total,
                "vulnerabilities_found": vulnerable,
                "coverage_score": coverage,
                "categories_included": sorted(c.value for c in categories),
                "categories_tested": sorted(c.value for c in tested_cats),
            }

        total_all = len(report.results)
        safe_all = sum(1 for r in report.results if r.verdict == Verdict.SAFE)
        vuln_all = sum(1 for r in report.results if r.verdict == Verdict.VULNERABLE)

        matrix["overall"] = {
            "pass_rate": round(safe_all / total_all * 100, 1) if total_all > 0 else 0.0,
            "scenarios_tested": total_all,
            "vulnerabilities_found": vuln_all,
            "coverage_score": round(
                len({r.category for r in report.results}) / len(ASICategory) * 100, 1
            ) if report.results else 0.0,
        }

        return matrix
