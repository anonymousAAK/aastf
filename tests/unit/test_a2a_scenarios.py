"""Tests for A2A (Agent-to-Agent) protocol scenario YAML validation."""
from __future__ import annotations

from pathlib import Path

import pytest

from aastf.models.scenario import ASICategory, AttackScenario, Severity
from aastf.scenarios.loader import load_scenario

SCENARIO_DIR = (
    Path(__file__).parent.parent.parent
    / "src"
    / "aastf"
    / "scenarios"
    / "builtin"
    / "a2a01"
)

EXPECTED_IDS = [
    "A2A01-001",
    "A2A01-002",
    "A2A01-003",
    "A2A01-004",
    "A2A01-005",
    "A2A01-006",
    "A2A01-007",
]

VALID_CATEGORIES = {c.value for c in ASICategory}
VALID_SEVERITIES = {s.value for s in Severity}


def _collect_a2a_yamls() -> list[Path]:
    if not SCENARIO_DIR.exists():
        return []
    return sorted(SCENARIO_DIR.glob("A2A01-*.yaml"))


_A2A_YAMLS = _collect_a2a_yamls()


@pytest.fixture(
    params=(
        _A2A_YAMLS
        if _A2A_YAMLS
        else [pytest.param(None, marks=pytest.mark.skip("No A2A scenarios found"))]
    ),
    ids=lambda p: p.stem if p else "none",
)
def a2a_yaml(request: pytest.FixtureRequest) -> Path:
    return request.param


# --- Individual parametrized tests ---


def test_a2a_scenario_loads(a2a_yaml: Path) -> None:
    """Each A2A scenario YAML loads and validates as AttackScenario."""
    scenario = load_scenario(a2a_yaml)
    assert isinstance(scenario, AttackScenario)


def test_a2a_scenario_has_required_fields(a2a_yaml: Path) -> None:
    """Each A2A scenario has all required fields populated."""
    scenario = load_scenario(a2a_yaml)
    assert scenario.id
    assert scenario.name
    assert scenario.description
    assert scenario.attack_vector
    assert scenario.payload
    assert scenario.expected_behavior
    assert scenario.remediation
    assert scenario.cwe_ids, f"{scenario.id} missing cwe_ids"
    assert scenario.nist_ai_rmf, f"{scenario.id} missing nist_ai_rmf"


def test_a2a_scenario_valid_category(a2a_yaml: Path) -> None:
    """Each A2A scenario uses a valid ASICategory."""
    scenario = load_scenario(a2a_yaml)
    assert scenario.category.value in VALID_CATEGORIES, (
        f"{scenario.id} has invalid category {scenario.category}"
    )


def test_a2a_scenario_valid_severity(a2a_yaml: Path) -> None:
    """Each A2A scenario uses HIGH or CRITICAL severity."""
    scenario = load_scenario(a2a_yaml)
    assert scenario.severity.value in {"HIGH", "CRITICAL"}, (
        f"{scenario.id} severity must be HIGH or CRITICAL, got {scenario.severity}"
    )


def test_a2a_scenario_has_detection(a2a_yaml: Path) -> None:
    """Each A2A scenario has at least one detection criterion."""
    scenario = load_scenario(a2a_yaml)
    d = scenario.detection
    has_detection = (
        d.tool_called
        or d.tool_not_called
        or d.tool_input_contains
        or d.output_contains
        or d.output_not_contains
        or d.tool_call_count_exceeds is not None
        or d.loop_iterations_exceed is not None
    )
    assert has_detection, f"{scenario.id} has no detection criteria"


def test_a2a_scenario_has_a2a_tag(a2a_yaml: Path) -> None:
    """Each A2A scenario has the 'a2a' tag."""
    scenario = load_scenario(a2a_yaml)
    assert "a2a" in scenario.tags, f"{scenario.id} missing 'a2a' tag"


def test_a2a_scenario_has_references(a2a_yaml: Path) -> None:
    """Each A2A scenario has at least one reference."""
    scenario = load_scenario(a2a_yaml)
    assert len(scenario.references) >= 1, f"{scenario.id} has no references"


# --- Aggregate tests ---


def test_all_seven_a2a_scenarios_exist() -> None:
    """All 7 expected A2A scenario files exist and load."""
    yamls = _collect_a2a_yamls()
    loaded_ids = []
    for y in yamls:
        scenario = load_scenario(y)
        loaded_ids.append(scenario.id)
    assert sorted(loaded_ids) == sorted(EXPECTED_IDS), (
        f"Expected {EXPECTED_IDS}, got {loaded_ids}"
    )


def test_no_duplicate_a2a_ids() -> None:
    """No duplicate scenario IDs across A2A scenarios."""
    yamls = _collect_a2a_yamls()
    ids = [load_scenario(y).id for y in yamls]
    assert len(ids) == len(set(ids)), f"Duplicate IDs found: {ids}"
