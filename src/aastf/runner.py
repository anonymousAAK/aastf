"""
Runner — orchestrates a full AASTF scan.

Flow:
  1. Load scenarios from registry
  2. Start sandbox server
  3. Build harness (framework adapter)
  4. For each scenario: run harness → evaluate → collect result
  5. Compute scores, build report
  6. Stop sandbox
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .exceptions import AdapterNotFoundError
from .models.config import FrameworkConfig
from .models.result import (
    EvaluationResult,
    ScanReport,
    TestResult,
    Verdict,
    VulnerabilityFinding,
)
from .models.scenario import ASICategory, AttackScenario
from .models.trace import AgentTrace
from .sandbox.server import SandboxServer
from .scenarios.evaluators import get_evaluator
from .scenarios.registry import ScenarioRegistry
from .scoring import annotate_findings, compute_risk_score, eu_ai_act_readiness


class Runner:
    """Executes a full AASTF scan against a target agent."""

    def __init__(self, config: FrameworkConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------ public

    async def run(self) -> ScanReport:
        """Execute the scan and return a complete ScanReport."""
        scenarios = self._load_scenarios()
        report = ScanReport(
            aastf_version=__version__,
            adapter=self._config.adapter,
            total_scenarios=len(scenarios),
        )

        sandbox = SandboxServer()
        await sandbox.start()

        try:
            harness = self._build_harness(sandbox)
            for scenario in scenarios:
                result = await self._run_one(harness, scenario)
                self._accumulate(report, result)
        finally:
            await sandbox.stop()

        # Finalise scores
        annotate_findings(report.findings)
        report.overall_risk_score = compute_risk_score(report)
        report.eu_ai_act_readiness = eu_ai_act_readiness(report)  # type: ignore[assignment]
        report.asi_summary = self._build_asi_summary(report)

        # Record to trend tracker
        try:
            from .reporting.trend_tracker import TrendTracker
            TrendTracker().record(report)
        except Exception:
            pass  # Trend tracking is non-critical — never fail a scan due to DB issues

        return report

    # ----------------------------------------------------------------- private

    def _load_scenarios(self) -> list[AttackScenario]:
        registry = ScenarioRegistry().load_builtin()
        for d in self._config.scenario_dirs:
            registry.load_directory(Path(d))

        categories = (
            [ASICategory(c) for c in self._config.categories]
            if self._config.categories
            else None
        )
        return registry.filter(
            categories=categories,
            exclude_ids=self._config.exclude_scenarios,
        )

    def _load_agent_factory(self):  # type: ignore[return]
        """Import and return the agent factory callable from dotted path."""
        agent_module_path = self._config.agent_factory
        if ":" not in agent_module_path:
            raise ValueError(
                f"agent_factory must be 'module.path:callable', got: {agent_module_path!r}"
            )
        module_path, _, attr = agent_module_path.rpartition(":")
        try:
            module = importlib.import_module(module_path)
        except ModuleNotFoundError as e:
            raise AdapterNotFoundError(
                f"Cannot import agent module {module_path!r}: {e}"
            ) from e
        if not hasattr(module, attr):
            raise AdapterNotFoundError(
                f"Module {module_path!r} has no attribute {attr!r}"
            )
        return getattr(module, attr)

    def _build_harness(self, sandbox: SandboxServer):  # type: ignore[return]
        factory = self._load_agent_factory()
        adapter = self._config.adapter

        if adapter == "langgraph":
            from .harness.adapters.langgraph import LangGraphHarness
            return LangGraphHarness(
                factory, sandbox,
                timeout=self._config.timeout_seconds,
                max_iterations=self._config.max_iterations,
            )
        elif adapter == "crewai":
            from .harness.adapters.crewai import CrewAIHarness
            return CrewAIHarness(factory, sandbox, timeout=self._config.timeout_seconds)
        elif adapter == "openai_agents":
            from .harness.adapters.openai_agents import OpenAIAgentsHarness
            return OpenAIAgentsHarness(factory, sandbox, timeout=self._config.timeout_seconds)
        elif adapter == "pydantic_ai":
            from .harness.adapters.pydantic_ai import PydanticAIHarness
            return PydanticAIHarness(factory, sandbox, timeout=self._config.timeout_seconds)
        elif adapter == "anthropic":
            from .harness.adapters.anthropic_agent import AnthropicAgentHarness
            # For anthropic adapter, agent_factory string encodes the model:
            # "anthropic:claude-opus-4-6" or just use default
            model = self._config.agent_factory if "claude" in self._config.agent_factory else "claude-haiku-4-5-20251001"
            return AnthropicAgentHarness(
                sandbox,
                model=model,
                timeout=self._config.timeout_seconds,
                max_iterations=self._config.max_iterations,
            )
        raise AdapterNotFoundError(
            f"Unknown adapter: {adapter!r}. "
            "Supported: langgraph, crewai, openai_agents, pydantic_ai, anthropic"
        )

    async def _run_one(self, harness: Any, scenario: AttackScenario) -> TestResult:
        t0 = datetime.now(UTC)
        try:
            trace = await harness.run_scenario(scenario)
        except Exception as e:
            trace = AgentTrace(
                scenario_id=scenario.id,
                adapter=self._config.adapter,
                error=str(e),
            )
            return TestResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                verdict=Verdict.ERROR,
                trace=trace,
                execution_time_ms=(datetime.now(UTC) - t0).total_seconds() * 1000,
            )

        evaluator = get_evaluator(scenario.category)
        if evaluator is None:
            return TestResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                verdict=Verdict.INCONCLUSIVE,
                trace=trace,
                execution_time_ms=(datetime.now(UTC) - t0).total_seconds() * 1000,
            )

        eval_result: EvaluationResult = evaluator.evaluate(scenario, trace)
        finding: VulnerabilityFinding | None = None

        if eval_result.verdict == Verdict.VULNERABLE:
            finding = VulnerabilityFinding(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                verdict=Verdict.VULNERABLE,
                triggered_by=eval_result.triggered_by,
                evidence=eval_result.evidence,
                relevant_invocations=eval_result.relevant_invocations,
                description=scenario.description,
                remediation=scenario.remediation,
                references=scenario.references,
            )

        return TestResult(
            scenario_id=scenario.id,
            scenario_name=scenario.name,
            category=scenario.category,
            severity=scenario.severity,
            verdict=eval_result.verdict,
            finding=finding,
            trace=trace,
            execution_time_ms=(datetime.now(UTC) - t0).total_seconds() * 1000,
        )

    def _accumulate(self, report: ScanReport, result: TestResult) -> None:
        report.results.append(result)
        if result.verdict == Verdict.VULNERABLE:
            report.vulnerable += 1
            if result.finding:
                report.findings.append(result.finding)
        elif result.verdict == Verdict.SAFE:
            report.safe += 1
        elif result.verdict == Verdict.ERROR:
            report.errors += 1
        else:
            report.inconclusive += 1

    def _build_asi_summary(self, report: ScanReport) -> dict[str, dict[str, int]]:
        summary: dict[str, dict[str, int]] = {}
        for r in report.results:
            cat = r.category.value
            if cat not in summary:
                summary[cat] = {"vulnerable": 0, "safe": 0, "inconclusive": 0, "error": 0}
            summary[cat][r.verdict.value.lower()] += 1
        return summary
