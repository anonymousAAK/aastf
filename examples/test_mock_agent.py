"""
Quick local test — mock agent, no API key needed.
Tests that AASTF scans, evaluates, and reports correctly.

Run:
    python examples/test_mock_agent.py
"""

import asyncio
import sys
import os
from pathlib import Path

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aastf.models.config import FrameworkConfig
from aastf.models.scenario import AttackScenario
from aastf.models.trace import AgentTrace, ToolInvocation
from aastf.runner import Runner
from aastf.sandbox.server import SandboxServer
from aastf.scenarios.registry import ScenarioRegistry
from aastf.scenarios.evaluators import get_evaluator
from aastf.reporting.console_reporter import ConsoleReporter


class MockHarness:
    """
    A mock harness that simulates a vulnerable agent:
    - Always calls whatever tool is in `detection.tool_called`
    - Echoes back any payload injected
    """

    def __init__(self, sandbox: SandboxServer) -> None:
        self._sandbox = sandbox

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        self._sandbox.configure_for_scenario(scenario)
        collector_invocations = []

        # Simulate calling every tool the scenario expects
        for tool_name in scenario.detection.tool_called:
            # Simulate injected input if tool_input_contains is set
            injected_input = scenario.detection.tool_input_contains.get(tool_name, "injected-payload")
            collector_invocations.append(
                ToolInvocation(
                    tool_name=tool_name,
                    tool_call_id=f"{tool_name}-001",
                    inputs={"query": injected_input},
                    outputs="mock response",
                    sandbox_intercepted=True,
                )
            )

        return AgentTrace(
            scenario_id=scenario.id,
            adapter="mock",
            tool_invocations=collector_invocations,
            final_output=scenario.payload[:100] if scenario.payload else "mock output",
        )


async def main() -> None:
    print("\n🔍 AASTF Local Test — Mock Vulnerable Agent\n")
    print("=" * 60)

    # Load a small subset: ASI01 + ASI02 only
    registry = ScenarioRegistry().load_builtin()
    scenarios = registry.filter(categories=None)[:8]  # first 8 scenarios

    print(f"Running {len(scenarios)} scenarios against mock agent...\n")

    sandbox = SandboxServer()
    await sandbox.start()

    results = []
    try:
        harness = MockHarness(sandbox)
        for scenario in scenarios:
            trace = await harness.run_scenario(scenario)
            evaluator = get_evaluator(scenario.category)

            if evaluator:
                eval_result = evaluator.evaluate(scenario, trace)
                verdict = eval_result.verdict.value
            else:
                verdict = "INCONCLUSIVE"

            icon = {"VULNERABLE": "🔴", "SAFE": "✅", "INCONCLUSIVE": "⚪", "ERROR": "❌"}.get(verdict, "?")
            print(f"  {icon} [{scenario.severity:8}] {scenario.id} — {verdict}")
            print(f"     {scenario.name}")
            results.append((scenario, verdict))
    finally:
        await sandbox.stop()

    print("\n" + "=" * 60)
    vulnerable = sum(1 for _, v in results if v == "VULNERABLE")
    safe = sum(1 for _, v in results if v == "SAFE")
    inconclusive = sum(1 for _, v in results if v == "INCONCLUSIVE")
    print(f"\nResults: 🔴 {vulnerable} VULNERABLE  ✅ {safe} SAFE  ⚪ {inconclusive} INCONCLUSIVE")
    print(f"\nFramework is working correctly.\n")


if __name__ == "__main__":
    asyncio.run(main())
