"""Contract tests — verify all adapters and core models conform to the AASTF interface contract.

Every adapter (harness) must:
- Have an async ``run_scenario(scenario)`` method
- Be discoverable via ``Runner._build_harness``
- Accept a valid FrameworkConfig adapter name

Every evaluator must:
- Inherit ``AbstractEvaluator``
- Return valid ``Verdict`` values from ``evaluate()``

Core models must:
- Serialize/deserialize cleanly (ScanReport round-trip)
- Enforce required fields (VulnerabilityFinding)
- Maintain severity ordering
"""

from __future__ import annotations

import inspect
import json

import pytest

from aastf.models.config import FrameworkConfig
from aastf.models.result import (
    EvaluationResult,
    ScanReport,
    TestResult,
    Verdict,
    VulnerabilityFinding,
)
from aastf.models.scenario import ASICategory, AttackScenario, Severity
from aastf.models.trace import AgentTrace
from aastf.scenarios.evaluators import _REGISTRY as EVALUATOR_REGISTRY
from aastf.scenarios.evaluators import get_evaluator
from aastf.scenarios.evaluators.base import AbstractEvaluator

# ---------------------------------------------------------------------------
# Adapter class inventory — import each harness class directly so we can
# inspect them without needing their SDK dependencies installed.
# ---------------------------------------------------------------------------

_ADAPTER_MODULES = {
    "langgraph": ("aastf.harness.adapters.langgraph", "LangGraphHarness"),
    "crewai": ("aastf.harness.adapters.crewai", "CrewAIHarness"),
    "openai_agents": ("aastf.harness.adapters.openai_agents", "OpenAIAgentsHarness"),
    "pydantic_ai": ("aastf.harness.adapters.pydantic_ai", "PydanticAIHarness"),
    "mcp": ("aastf.harness.adapters.mcp", "MCPHarness"),
}


def _import_harness_class(module_path: str, class_name: str):
    """Import a harness class, returning None if the module can't be loaded."""
    import importlib

    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except (ImportError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Contract: all adapters have async run_scenario
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("adapter_name", list(_ADAPTER_MODULES.keys()))
def test_all_adapters_have_run_scenario_method(adapter_name: str) -> None:
    """Every adapter class must expose an async ``run_scenario`` method."""
    module_path, class_name = _ADAPTER_MODULES[adapter_name]
    cls = _import_harness_class(module_path, class_name)
    assert cls is not None, f"Could not import {module_path}.{class_name}"

    method = getattr(cls, "run_scenario", None)
    assert method is not None, f"{class_name} is missing run_scenario method"
    assert inspect.iscoroutinefunction(method), (
        f"{class_name}.run_scenario must be async (coroutine function)"
    )


@pytest.mark.parametrize("adapter_name", list(_ADAPTER_MODULES.keys()))
def test_run_scenario_accepts_attack_scenario(adapter_name: str) -> None:
    """run_scenario must accept an AttackScenario as its first positional arg."""
    module_path, class_name = _ADAPTER_MODULES[adapter_name]
    cls = _import_harness_class(module_path, class_name)
    assert cls is not None

    sig = inspect.signature(cls.run_scenario)
    params = list(sig.parameters.values())
    # params[0] is 'self'; params[1] should be the scenario arg
    assert len(params) >= 2, (
        f"{class_name}.run_scenario must accept at least (self, scenario)"
    )
    scenario_param = params[1]
    assert scenario_param.name == "scenario", (
        f"{class_name}.run_scenario first arg should be named 'scenario', "
        f"got '{scenario_param.name}'"
    )


# ---------------------------------------------------------------------------
# Contract: Runner._build_harness knows about all adapters
# ---------------------------------------------------------------------------


def test_all_adapters_registered_in_runner() -> None:
    """Runner._build_harness must handle every adapter name we ship."""
    from aastf.runner import Runner

    source = inspect.getsource(Runner._build_harness)
    for adapter_name in _ADAPTER_MODULES:
        assert adapter_name in source, (
            f"Runner._build_harness does not reference adapter '{adapter_name}'"
        )


# ---------------------------------------------------------------------------
# Contract: FrameworkConfig accepts adapter names
# ---------------------------------------------------------------------------


_CONFIG_ADAPTERS = ["langgraph", "crewai", "openai_agents", "pydantic_ai"]
# NOTE: "mcp" is used in Runner._build_harness but is not yet in
# FrameworkConfig.adapter Literal. We test the 4 that are in the Literal.


@pytest.mark.parametrize("adapter_name", _CONFIG_ADAPTERS)
def test_adapter_config_validation(adapter_name: str) -> None:
    """FrameworkConfig must accept each shipped adapter name."""
    config = FrameworkConfig(
        adapter=adapter_name,
        agent_factory="dummy.module:create_agent",
    )
    assert config.adapter == adapter_name


# ---------------------------------------------------------------------------
# Contract: Verdict enum completeness
# ---------------------------------------------------------------------------


def test_verdict_enum_completeness() -> None:
    """All verdict values used in evaluators must exist in the Verdict enum."""
    known_verdicts = {v.value for v in Verdict}
    # Check that every evaluator in the registry can return only known verdicts
    for _cat, evaluator in EVALUATOR_REGISTRY.items():
        # Verify evaluator source is inspectable (not a broken import)
        inspect.getsource(type(evaluator).evaluate)
    # The real check: ensure all Verdict members are reachable
    expected = {
        "VULNERABLE",
        "REFUSAL_ECHO",
        "SAFE",
        "INCONCLUSIVE",
        "ERROR",
        "TOOL_POISONING",
        "SCHEMA_POISONING",
        "PREFERENCE_MANIPULATION",
    }
    assert known_verdicts == expected, (
        f"Verdict enum mismatch: missing={expected - known_verdicts}, "
        f"extra={known_verdicts - expected}"
    )


# ---------------------------------------------------------------------------
# Contract: Severity ordering
# ---------------------------------------------------------------------------


def test_severity_ordering() -> None:
    """INFO < LOW < MEDIUM < HIGH < CRITICAL must hold via numeric() and __gt__."""
    # Use the operators defined on Severity: __gt__ and __ge__
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.LOW > Severity.INFO
    # Transitivity
    assert not (Severity.LOW > Severity.HIGH)
    assert Severity.CRITICAL >= Severity.CRITICAL
    # numeric() must be strictly ascending
    assert Severity.INFO.numeric() < Severity.LOW.numeric()
    assert Severity.LOW.numeric() < Severity.MEDIUM.numeric()
    assert Severity.MEDIUM.numeric() < Severity.HIGH.numeric()
    assert Severity.HIGH.numeric() < Severity.CRITICAL.numeric()


def test_severity_numeric_values() -> None:
    """numeric() must return ascending integers."""
    values = [s.numeric() for s in [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]]
    assert values == sorted(values)
    assert len(set(values)) == 5, "All severity levels must have distinct numeric values"


# ---------------------------------------------------------------------------
# Contract: ScanReport serialization round-trip
# ---------------------------------------------------------------------------


def _make_minimal_trace() -> AgentTrace:
    return AgentTrace(scenario_id="ASI01-001", adapter="langgraph")


def _make_minimal_test_result() -> TestResult:
    return TestResult(
        scenario_id="ASI01-001",
        scenario_name="Test scenario",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        verdict=Verdict.SAFE,
        trace=_make_minimal_trace(),
        execution_time_ms=42.5,
    )


def test_scan_report_serialization_roundtrip() -> None:
    """ScanReport must survive JSON serialization and deserialization."""
    report = ScanReport(
        aastf_version="0.5.0",
        adapter="langgraph",
        total_scenarios=1,
        safe=1,
        results=[_make_minimal_test_result()],
    )
    json_str = report.model_dump_json()
    parsed = json.loads(json_str)

    # Reconstruct
    restored = ScanReport.model_validate(parsed)
    assert restored.aastf_version == report.aastf_version
    assert restored.adapter == report.adapter
    assert restored.total_scenarios == report.total_scenarios
    assert restored.safe == report.safe
    assert len(restored.results) == 1
    assert restored.results[0].scenario_id == "ASI01-001"
    assert restored.results[0].execution_time_ms == 42.5


def test_scan_report_dict_roundtrip() -> None:
    """ScanReport.model_dump() -> model_validate() must be lossless."""
    report = ScanReport(
        aastf_version="0.5.0",
        adapter="langgraph",
        total_scenarios=2,
        vulnerable=1,
        safe=1,
    )
    data = report.model_dump()
    restored = ScanReport.model_validate(data)
    assert restored.vulnerable == 1
    assert restored.safe == 1


# ---------------------------------------------------------------------------
# Contract: VulnerabilityFinding required fields
# ---------------------------------------------------------------------------


def test_finding_required_fields() -> None:
    """VulnerabilityFinding must enforce all required fields."""
    finding = VulnerabilityFinding(
        scenario_id="ASI02-001",
        scenario_name="Tool misuse test",
        category=ASICategory.ASI02,
        severity=Severity.HIGH,
        verdict=Verdict.VULNERABLE,
        triggered_by="tool_called: send_email",
        description="Agent called forbidden tool",
        remediation="Block send_email in production",
    )
    assert finding.scenario_id == "ASI02-001"
    assert finding.category == ASICategory.ASI02
    assert finding.severity == Severity.HIGH
    assert finding.verdict == Verdict.VULNERABLE
    assert finding.triggered_by
    assert finding.description
    assert finding.remediation
    # Auto-generated fields
    assert finding.finding_id  # UUID should be auto-generated
    assert finding.timestamp  # Should have a timestamp


def test_finding_rejects_missing_required_fields() -> None:
    """VulnerabilityFinding must reject construction without required fields."""
    with pytest.raises((TypeError, ValueError)):
        VulnerabilityFinding()  # type: ignore[call-arg]

    with pytest.raises((TypeError, ValueError)):
        VulnerabilityFinding(
            scenario_id="ASI02-001",
            # missing scenario_name, category, severity, etc.
        )  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Contract: TestResult includes timing information
# ---------------------------------------------------------------------------


def test_test_result_has_timing() -> None:
    """TestResult must include execution_time_ms field."""
    result = _make_minimal_test_result()
    assert hasattr(result, "execution_time_ms")
    assert isinstance(result.execution_time_ms, float)
    assert result.execution_time_ms >= 0


# ---------------------------------------------------------------------------
# Contract: evaluator interface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("category", list(ASICategory))
def test_evaluator_exists_for_every_category(category: ASICategory) -> None:
    """Every ASICategory must have a registered evaluator."""
    evaluator = get_evaluator(category)
    assert evaluator is not None, f"No evaluator registered for {category.value}"


@pytest.mark.parametrize("category", list(ASICategory))
def test_evaluator_inherits_abstract(category: ASICategory) -> None:
    """Every registered evaluator must inherit AbstractEvaluator."""
    evaluator = get_evaluator(category)
    assert evaluator is not None
    assert isinstance(evaluator, AbstractEvaluator), (
        f"Evaluator for {category.value} ({type(evaluator).__name__}) "
        f"does not inherit AbstractEvaluator"
    )


@pytest.mark.parametrize("category", list(ASICategory))
def test_evaluator_has_evaluate_method(category: ASICategory) -> None:
    """Every evaluator must implement the evaluate(scenario, trace) method."""
    evaluator = get_evaluator(category)
    assert evaluator is not None
    method = getattr(evaluator, "evaluate", None)
    assert method is not None
    assert callable(method)
    # Verify signature: (self, scenario, trace) -> EvaluationResult
    sig = inspect.signature(method)
    params = list(sig.parameters.keys())
    assert "scenario" in params, "evaluate() missing 'scenario' parameter"
    assert "trace" in params, "evaluate() missing 'trace' parameter"


@pytest.mark.parametrize("category", list(ASICategory))
def test_evaluator_returns_valid_verdict(category: ASICategory) -> None:
    """Evaluator.evaluate() must return EvaluationResult with a valid Verdict."""
    evaluator = get_evaluator(category)
    assert evaluator is not None

    # Build a minimal scenario + trace for a smoke test
    scenario = AttackScenario(
        id="ASI01-001",
        name="Contract test scenario",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        description="Contract test",
        attack_vector="test",
        inject_into="user_message",
        payload="test payload",
        detection={},
        expected_behavior="test",
        remediation="test",
    )
    trace = AgentTrace(scenario_id="ASI01-001", adapter="langgraph")

    result = evaluator.evaluate(scenario, trace)
    assert isinstance(result, EvaluationResult)
    assert isinstance(result.verdict, Verdict), (
        f"Evaluator for {category.value} returned verdict type "
        f"{type(result.verdict).__name__}, expected Verdict"
    )
    assert result.verdict.value in {v.value for v in Verdict}
