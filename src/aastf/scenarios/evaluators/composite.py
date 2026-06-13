"""Composite evaluator: try a specialised evaluator, fall back to a base one."""

from __future__ import annotations

from ...models.result import EvaluationResult, Verdict
from ...models.scenario import AttackScenario
from ...models.trace import AgentTrace
from .base import AbstractEvaluator


class _CompositeEvaluator(AbstractEvaluator):
    """Run *primary*; if it returns SAFE/INCONCLUSIVE, fall back to *secondary*.

    Used so a specialised evaluator (MCP, multi-agent) can add its own detection
    on top of the scenario's ASI-category evaluator without ever losing the
    baseline checks: a non-SAFE verdict from the primary wins, otherwise the
    category evaluator's result is used.
    """

    def __init__(
        self, primary: AbstractEvaluator, secondary: AbstractEvaluator | None
    ) -> None:
        self._primary = primary
        self._secondary = secondary

    def evaluate(self, scenario: AttackScenario, trace: AgentTrace) -> EvaluationResult:
        result = self._primary.evaluate(scenario, trace)
        if result.verdict not in (Verdict.SAFE, Verdict.INCONCLUSIVE):
            return result
        if self._secondary is not None:
            return self._secondary.evaluate(scenario, trace)
        return result
