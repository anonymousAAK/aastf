"""Drift detection — compare consecutive ScanReports and surface regressions."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .models.result import ACTIONABLE_VERDICTS, ScanReport, Verdict
from .models.scenario import Severity


class DriftItem(BaseModel):
    """A single change between two scan runs."""

    scenario_id: str
    category: str
    previous_verdict: str
    current_verdict: str
    previous_severity: str | None = None
    current_severity: str | None = None
    description: str


class DriftReport(BaseModel):
    """Summary of all changes between a baseline and current scan."""

    new_vulnerabilities: list[DriftItem] = Field(default_factory=list)
    severity_upgrades: list[DriftItem] = Field(default_factory=list)
    score_regressions: list[DriftItem] = Field(default_factory=list)
    resolved: list[DriftItem] = Field(default_factory=list)
    overall_drift: Literal["improved", "stable", "regressed"] = "stable"

    def to_console(self) -> str:
        """Render a human-readable drift summary."""
        lines: list[str] = []
        lines.append(f"Overall drift: {self.overall_drift.upper()}")
        lines.append("")

        if self.new_vulnerabilities:
            lines.append(f"New vulnerabilities ({len(self.new_vulnerabilities)}):")
            for item in self.new_vulnerabilities:
                lines.append(f"  - {item.scenario_id}: {item.description}")

        if self.severity_upgrades:
            lines.append(f"Severity upgrades ({len(self.severity_upgrades)}):")
            for item in self.severity_upgrades:
                lines.append(f"  - {item.scenario_id}: {item.description}")

        if self.score_regressions:
            lines.append(f"Score regressions ({len(self.score_regressions)}):")
            for item in self.score_regressions:
                lines.append(f"  - {item.scenario_id}: {item.description}")

        if self.resolved:
            lines.append(f"Resolved ({len(self.resolved)}):")
            for item in self.resolved:
                lines.append(f"  - {item.scenario_id}: {item.description}")

        if not any([self.new_vulnerabilities, self.severity_upgrades,
                     self.score_regressions, self.resolved]):
            lines.append("No drift detected.")

        return "\n".join(lines)


# Drift treats every behavioural-compromise verdict AND REFUSAL_ECHO as a
# regression target. Sourced from the canonical set so multi-agent verdicts
# (INFECTION_PROPAGATED/COLLUSION/WATCHDOG_BYPASS) are not silently ignored.
_VULNERABLE_VERDICTS = set(ACTIONABLE_VERDICTS)

_SAFE_VERDICTS = {Verdict.SAFE}


def _is_vulnerable(verdict: Verdict) -> bool:
    return verdict in _VULNERABLE_VERDICTS


def _severity_numeric(sev: str | None) -> int:
    if sev is None:
        return 0
    try:
        return Severity(sev).numeric()
    except (ValueError, KeyError):
        return 0


class DriftDetector:
    """Compare two ScanReports and produce a DriftReport."""

    def __init__(self, baseline: ScanReport, current: ScanReport) -> None:
        self.baseline = baseline
        self.current = current

    def detect(self) -> DriftReport:
        """Run all drift checks and return a consolidated DriftReport."""
        report = DriftReport()

        # Index results by scenario_id
        baseline_results = {r.scenario_id: r for r in self.baseline.results}
        current_results = {r.scenario_id: r for r in self.current.results}

        all_ids = set(baseline_results.keys()) | set(current_results.keys())

        for sid in sorted(all_ids):
            base = baseline_results.get(sid)
            curr = current_results.get(sid)

            if curr is not None and base is None:
                # New scenario in current — if vulnerable, flag it
                if _is_vulnerable(curr.verdict):
                    report.new_vulnerabilities.append(DriftItem(
                        scenario_id=sid,
                        category=str(curr.category),
                        previous_verdict="N/A",
                        current_verdict=str(curr.verdict),
                        previous_severity=None,
                        current_severity=str(curr.severity),
                        description=f"New scenario {sid} is {curr.verdict}",
                    ))
                continue

            if base is not None and curr is None:
                # Scenario removed — skip
                continue

            # Both exist — compare
            assert base is not None and curr is not None

            # 1. New vulnerability (was safe/inconclusive, now vulnerable)
            if not _is_vulnerable(base.verdict) and _is_vulnerable(curr.verdict):
                report.new_vulnerabilities.append(DriftItem(
                    scenario_id=sid,
                    category=str(curr.category),
                    previous_verdict=str(base.verdict),
                    current_verdict=str(curr.verdict),
                    previous_severity=str(base.severity),
                    current_severity=str(curr.severity),
                    description=f"{sid} regressed from {base.verdict} to {curr.verdict}",
                ))

            # 2. Resolved (was vulnerable, now safe)
            if _is_vulnerable(base.verdict) and not _is_vulnerable(curr.verdict):
                report.resolved.append(DriftItem(
                    scenario_id=sid,
                    category=str(curr.category),
                    previous_verdict=str(base.verdict),
                    current_verdict=str(curr.verdict),
                    previous_severity=str(base.severity),
                    current_severity=str(curr.severity),
                    description=f"{sid} resolved from {base.verdict} to {curr.verdict}",
                ))

            # 3. Severity upgrade (both vulnerable but severity increased)
            if (_is_vulnerable(base.verdict) and _is_vulnerable(curr.verdict)
                    and _severity_numeric(str(curr.severity)) > _severity_numeric(str(base.severity))):
                report.severity_upgrades.append(DriftItem(
                    scenario_id=sid,
                    category=str(curr.category),
                    previous_verdict=str(base.verdict),
                    current_verdict=str(curr.verdict),
                    previous_severity=str(base.severity),
                    current_severity=str(curr.severity),
                    description=(
                        f"{sid} severity increased from {base.severity} to {curr.severity}"
                    ),
                ))

        # 4. Score regression — per-category risk score comparison
        for cat, base_summary in self.baseline.asi_summary.items():
            curr_summary = self.current.asi_summary.get(cat)
            if curr_summary is None:
                continue
            base_vuln = base_summary.get("vulnerable", 0)
            curr_vuln = curr_summary.get("vulnerable", 0)
            if curr_vuln > base_vuln:
                report.score_regressions.append(DriftItem(
                    scenario_id=cat,
                    category=cat,
                    previous_verdict=f"vulnerable={base_vuln}",
                    current_verdict=f"vulnerable={curr_vuln}",
                    previous_severity=None,
                    current_severity=None,
                    description=(
                        f"{cat} vulnerable count increased from {base_vuln} to {curr_vuln}"
                    ),
                ))

        # Also flag overall risk score regression
        if self.current.overall_risk_score > self.baseline.overall_risk_score:
            delta = self.current.overall_risk_score - self.baseline.overall_risk_score
            report.score_regressions.append(DriftItem(
                scenario_id="overall",
                category="overall",
                previous_verdict=f"risk_score={self.baseline.overall_risk_score:.1f}",
                current_verdict=f"risk_score={self.current.overall_risk_score:.1f}",
                previous_severity=None,
                current_severity=None,
                description=(
                    f"Overall risk score increased by {delta:.1f} "
                    f"({self.baseline.overall_risk_score:.1f} -> "
                    f"{self.current.overall_risk_score:.1f})"
                ),
            ))

        # Determine overall drift
        has_regressions = bool(
            report.new_vulnerabilities or report.severity_upgrades or report.score_regressions
        )
        has_improvements = bool(report.resolved)

        if has_regressions and not has_improvements:
            report.overall_drift = "regressed"
        elif has_improvements and not has_regressions:
            report.overall_drift = "improved"
        elif has_regressions and has_improvements:
            report.overall_drift = "regressed"
        else:
            report.overall_drift = "stable"

        return report

    def has_regressions(self) -> bool:
        """Quick check: did the agent get worse?"""
        report = self.detect()
        return report.overall_drift == "regressed"
