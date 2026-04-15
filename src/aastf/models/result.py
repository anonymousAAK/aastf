"""Test result and report models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from .scenario import ASICategory, Severity
from .trace import AgentTrace, ToolInvocation


class Verdict(StrEnum):
    VULNERABLE = "VULNERABLE"      # Attack succeeded — agent did the bad thing
    SAFE = "SAFE"                  # Agent correctly resisted the attack
    INCONCLUSIVE = "INCONCLUSIVE"  # Could not determine (no evaluator, ambiguous trace)
    ERROR = "ERROR"                # Framework error during scenario execution


class EvaluationResult(BaseModel):
    """Intermediate result returned by an evaluator — not the final report object."""

    verdict: Verdict
    triggered_by: str = ""  # which detection criterion fired
    evidence: dict[str, Any] = Field(default_factory=dict)
    relevant_invocations: list[ToolInvocation] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    """A confirmed security finding — only created when verdict is VULNERABLE."""

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    scenario_name: str
    category: ASICategory
    severity: Severity
    verdict: Verdict
    cvss_score: float | None = None  # 0.0–10.0, computed by scoring.py
    triggered_by: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    relevant_invocations: list[ToolInvocation] = Field(default_factory=list)
    description: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TestResult(BaseModel):
    """Result of running a single scenario against the agent."""

    result_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    scenario_name: str
    category: ASICategory
    severity: Severity
    verdict: Verdict
    finding: VulnerabilityFinding | None = None  # populated only when VULNERABLE
    trace: AgentTrace
    execution_time_ms: float = 0.0


class ScanReport(BaseModel):
    """Complete output of an AASTF scan run."""

    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    aastf_version: str
    adapter: str
    total_scenarios: int = 0
    vulnerable: int = 0
    safe: int = 0
    inconclusive: int = 0
    errors: int = 0
    overall_risk_score: float = 0.0  # 0–100
    eu_ai_act_readiness: Literal["compliant", "at_risk", "non_compliant"] = "at_risk"
    results: list[TestResult] = Field(default_factory=list)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    # per-category breakdown: {"ASI01": {"vulnerable": 2, "safe": 3, ...}, ...}
    asi_summary: dict[str, dict[str, int]] = Field(default_factory=dict)

    @property
    def vulnerability_rate(self) -> float:
        """Percentage of scenarios where agent was VULNERABLE."""
        if self.total_scenarios == 0:
            return 0.0
        return round(self.vulnerable / self.total_scenarios * 100, 1)

    @property
    def critical_findings(self) -> list[VulnerabilityFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]
