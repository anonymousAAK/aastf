"""
Shared fixtures for adversarial / audit test suite.

All fixtures work with synthetic traces — no LLM API keys, no network.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aastf.models.result import Verdict
from aastf.models.scenario import (
    ASICategory,
    AttackScenario,
    DetectionCriteria,
    InjectionPoint,
    Severity,
)
from aastf.models.trace import AgentTrace, ToolInvocation

# ---------------------------------------------------------------------------
# Scenario factory helpers
# ---------------------------------------------------------------------------


def make_scenario(
    cat: ASICategory = ASICategory.ASI01,
    sid: str | None = None,
    tool_called: list[str] | None = None,
    tool_not_called: list[str] | None = None,
    tool_input_contains: dict[str, str] | None = None,
    output_contains: list[str] | None = None,
    output_not_contains: list[str] | None = None,
    loop_iterations_exceed: int | None = None,
    tool_call_count_exceeds: int | None = None,
    available_tools: list[str] | None = None,
    severity: Severity = Severity.HIGH,
) -> AttackScenario:
    num = cat.value[3:]  # "01" → "01"
    return AttackScenario(
        id=sid or f"{cat.value}-001",
        name="Adversarial test scenario",
        category=cat,
        severity=severity,
        description="Synthetic scenario for adversarial testing.",
        attack_vector="test",
        inject_into=InjectionPoint.USER_MESSAGE,
        payload="inject",
        available_tools=available_tools or [],
        detection=DetectionCriteria(
            tool_called=tool_called or [],
            tool_not_called=tool_not_called or [],
            tool_input_contains=tool_input_contains or {},
            output_contains=output_contains or [],
            output_not_contains=output_not_contains or [],
            loop_iterations_exceed=loop_iterations_exceed,
            tool_call_count_exceeds=tool_call_count_exceeds,
        ),
        expected_behavior="safe",
        remediation="fix it",
    )


def make_trace(
    tools: list[str] | None = None,
    tool_inputs: dict[str, dict] | None = None,
    output: str | None = None,
    iterations: int = 0,
    scenario_id: str = "ASI01-001",
    error: str | None = None,
) -> AgentTrace:
    invocations = []
    if tools:
        for i, name in enumerate(tools):
            inp = (tool_inputs or {}).get(name, {})
            invocations.append(
                ToolInvocation(
                    tool_name=name,
                    inputs=inp,
                    sequence=i,
                    sandbox_intercepted=True,
                )
            )
    return AgentTrace(
        scenario_id=scenario_id,
        adapter="test",
        tool_invocations=invocations,
        final_output=output,
        iteration_count=iterations,
        error=error,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_trace() -> AgentTrace:
    return make_trace()


@pytest.fixture
def tmp_scenario_dir(tmp_path: Path) -> Path:
    """Empty temp directory for custom scenario loading tests."""
    d = tmp_path / "scenarios"
    d.mkdir()
    return d


MINIMAL_VALID_YAML = textwrap.dedent("""\
    id: ASI01-001
    name: "Test scenario"
    category: ASI01
    severity: HIGH
    description: "Test"
    attack_vector: "test"
    inject_into: user_message
    payload: "inject"
    detection: {}
    expected_behavior: "safe"
    remediation: "fix"
    tags: [test]
    references: ["https://example.com"]
""")
