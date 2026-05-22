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
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .cache import ResponseCache
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

    def __init__(
        self,
        config: FrameworkConfig,
        cache: ResponseCache | None = None,
    ) -> None:
        self._config = config
        self._cache = cache or ResponseCache(enabled=False)

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

        # Log cache performance
        if self._cache.enabled:
            logging.getLogger(__name__).info(
                "Cache: %d hits, %d misses", self._cache.hits, self._cache.misses,
            )

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
            logging.getLogger(__name__).warning("Trend tracking failed", exc_info=True)

        return report

    # ----------------------------------------------------------------- private

    def _load_scenarios(self) -> list[AttackScenario]:
        registry = ScenarioRegistry().load_builtin()
        for d in self._config.scenario_dirs:
            registry.load_directory(Path(d))

        categories = (
            [ASICategory(c) for c in self._config.categories] if self._config.categories else None
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
            raise AdapterNotFoundError(f"Cannot import agent module {module_path!r}: {e}") from e
        if not hasattr(module, attr):
            raise AdapterNotFoundError(f"Module {module_path!r} has no attribute {attr!r}")
        return getattr(module, attr)

    def _build_harness(self, sandbox: SandboxServer):  # type: ignore[return]
        factory = self._load_agent_factory()
        adapter = self._config.adapter

        if adapter == "langgraph":
            from .harness.adapters.langgraph import LangGraphHarness

            return LangGraphHarness(
                factory,
                sandbox,
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
        elif adapter == "mcp":
            from .harness.adapters.mcp import MCPHarness

            return MCPHarness(factory, sandbox, timeout=self._config.timeout_seconds)
        raise AdapterNotFoundError(
            f"Unknown adapter: {adapter!r}. "
            "Supported: langgraph, crewai, openai_agents, pydantic_ai, mcp"
        )

    async def _run_one(self, harness: Any, scenario: AttackScenario) -> TestResult:
        t0 = datetime.now(timezone.utc)

        # Check cache first
        cached_trace = self._cache.get(scenario, self._config.adapter)
        if cached_trace is not None:
            logging.getLogger(__name__).info(
                "[cached] %s — using cached response", scenario.id,
            )
            trace = cached_trace
            # Skip harness execution; jump straight to evaluation
            return self._evaluate(scenario, trace, t0)

        try:
            trace = await harness.run_scenario(scenario)
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            # Truncate to avoid leaking full stack traces into reports
            if len(error_msg) > 500:
                error_msg = error_msg[:500] + "... (truncated)"
            trace = AgentTrace(
                scenario_id=scenario.id,
                adapter=self._config.adapter,
                error=error_msg,
            )
            return TestResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                verdict=Verdict.ERROR,
                trace=trace,
                execution_time_ms=(datetime.now(timezone.utc) - t0).total_seconds() * 1000,
            )

        # Cache the successful trace
        self._cache.put(scenario, self._config.adapter, trace)

        return self._evaluate(scenario, trace, t0)

    def _evaluate(
        self, scenario: AttackScenario, trace: AgentTrace, t0: datetime,
    ) -> TestResult:
        """Evaluate a trace against scenario detection criteria."""
        evaluator = get_evaluator(scenario.category)
        if evaluator is None:
            logging.getLogger(__name__).warning(
                "No evaluator registered for category %s", scenario.category
            )
            return TestResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                verdict=Verdict.INCONCLUSIVE,
                trace=trace,
                execution_time_ms=(datetime.now(timezone.utc) - t0).total_seconds() * 1000,
            )

        eval_result: EvaluationResult = evaluator.evaluate(scenario, trace)

        # BUG-08 fix: apply tool_not_called check when evaluator returns SAFE
        if eval_result.verdict == Verdict.SAFE:
            not_called_result = evaluator._check_tool_not_called(scenario, trace)
            if not_called_result is not None:
                eval_result = not_called_result

        # custom_evaluator: dynamic import removed (code-injection risk).
        # The schema field is kept for forward compatibility but is a no-op.
        if eval_result.verdict == Verdict.SAFE and scenario.detection.custom_evaluator:
            logging.getLogger(__name__).warning(
                "custom_evaluator is not yet supported (scenario %s); ignoring.",
                scenario.id,
            )

        finding: VulnerabilityFinding | None = None

        if eval_result.verdict in (
            Verdict.VULNERABLE,
            Verdict.REFUSAL_ECHO,
            Verdict.TOOL_POISONING,
            Verdict.SCHEMA_POISONING,
            Verdict.PREFERENCE_MANIPULATION,
        ):
            finding = VulnerabilityFinding(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                verdict=eval_result.verdict,
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
            execution_time_ms=(datetime.now(timezone.utc) - t0).total_seconds() * 1000,
        )

    def _accumulate(self, report: ScanReport, result: TestResult) -> None:
        """Accumulate one TestResult into the running ScanReport.

        Design note — which verdicts append to report.findings:
        VULNERABLE and REFUSAL_ECHO both appear in findings because users need
        to see them and take remediation action.  SAFE findings are excluded
        (non-actionable noise that would bloat reports).  ERROR and INCONCLUSIVE
        do not produce VulnerabilityFinding objects so they are never appended.
        """
        report.results.append(result)
        if result.verdict in (
            Verdict.VULNERABLE,
            Verdict.TOOL_POISONING,
            Verdict.SCHEMA_POISONING,
            Verdict.PREFERENCE_MANIPULATION,
        ):
            report.vulnerable += 1
            if result.finding:
                report.findings.append(result.finding)
        elif result.verdict == Verdict.REFUSAL_ECHO:
            report.refusal_echo_count += 1
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
                summary[cat] = {
                    "vulnerable": 0,
                    "refusal_echo": 0,
                    "safe": 0,
                    "inconclusive": 0,
                    "error": 0,
                }
            verdict_key = r.verdict.value.lower()
            # MCP-specific verdicts count as vulnerable in the summary
            if verdict_key in ("tool_poisoning", "schema_poisoning", "preference_manipulation"):
                verdict_key = "vulnerable"
            summary[cat][verdict_key] += 1
        return summary
