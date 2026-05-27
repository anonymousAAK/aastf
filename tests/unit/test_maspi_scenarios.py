"""Tests for MASpi (Multi-Agent Security) scenario YAML validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from aastf.models.result import Verdict
from aastf.models.scenario import AttackScenario
from aastf.scenarios.loader import load_scenario

SCENARIO_DIR = Path(__file__).parent.parent.parent / "src" / "aastf" / "scenarios" / "builtin"

MAS_IDS = [
    "MAS01-001",
    "MAS01-002",
    "MAS01-003",
    "MAS02-001",
    "MAS02-002",
    "MAS02-003",
    "MAS03-001",
    "MAS03-002",
    "MAS03-003",
]

EXPECTED_CATEGORIES = {
    "MAS01-001": "ASI01",
    "MAS01-002": "ASI08",
    "MAS01-003": "ASI01",
    "MAS02-001": "ASI01",
    "MAS02-002": "ASI03",
    "MAS02-003": "ASI03",
    "MAS03-001": "ASI01",
    "MAS03-002": "ASI08",
    "MAS03-003": "ASI01",
}


def _collect_mas_yamls() -> list[Path]:
    """Collect all MAS scenario YAML files."""
    yamls: list[Path] = []
    for prefix in ("mas01", "mas02", "mas03"):
        d = SCENARIO_DIR / prefix
        if d.exists():
            for f in sorted(d.glob("*.yaml")):
                if f.name != "meta.yaml":
                    yamls.append(f)
    return yamls


_MAS_YAMLS = _collect_mas_yamls()


@pytest.fixture(
    params=_MAS_YAMLS if _MAS_YAMLS else [pytest.param(None, marks=pytest.mark.skip("No MAS scenarios found"))],
    ids=lambda p: p.stem if p else "none",
)
def mas_yaml(request: pytest.FixtureRequest) -> Path:
    return request.param


def test_all_nine_scenarios_found() -> None:
    """All 9 MAS scenarios must be present on disk."""
    found_ids = {p.stem for p in _MAS_YAMLS}
    for sid in MAS_IDS:
        assert sid in found_ids, f"Missing scenario file for {sid}"


def test_mas_scenario_loads(mas_yaml: Path) -> None:
    """Each MAS scenario YAML should load and validate as AttackScenario."""
    scenario = load_scenario(mas_yaml)
    assert isinstance(scenario, AttackScenario)


def test_mas_scenario_required_fields(mas_yaml: Path) -> None:
    """Each MAS scenario must have all required fields populated."""
    scenario = load_scenario(mas_yaml)
    assert scenario.id
    assert scenario.name
    assert scenario.description
    assert scenario.category
    assert scenario.severity
    assert scenario.payload
    assert scenario.remediation
    assert scenario.detection


def test_mas_scenario_has_detection(mas_yaml: Path) -> None:
    """Each MAS scenario must have at least one detection criterion."""
    scenario = load_scenario(mas_yaml)
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


def test_mas_scenario_categories_correct(mas_yaml: Path) -> None:
    """Each MAS scenario must map to the expected ASI category."""
    scenario = load_scenario(mas_yaml)
    expected = EXPECTED_CATEGORIES.get(scenario.id)
    if expected is not None:
        assert scenario.category.value == expected, (
            f"{scenario.id} expected category {expected}, got {scenario.category.value}"
        )


def test_mas_scenario_has_cwe_ids(mas_yaml: Path) -> None:
    """Each MAS scenario must have at least one CWE ID."""
    scenario = load_scenario(mas_yaml)
    assert len(scenario.cwe_ids) >= 1, f"{scenario.id} has no CWE IDs"


def test_mas_scenario_has_nist_mapping(mas_yaml: Path) -> None:
    """Each MAS scenario must have at least one NIST AI RMF reference."""
    scenario = load_scenario(mas_yaml)
    assert len(scenario.nist_ai_rmf) >= 1, f"{scenario.id} has no NIST AI RMF references"


def test_mas_scenario_has_multi_agent_tag(mas_yaml: Path) -> None:
    """Each MAS scenario should have 'multi-agent' in tags."""
    scenario = load_scenario(mas_yaml)
    assert "multi-agent" in scenario.tags, f"{scenario.id} missing 'multi-agent' tag"


def test_mas_scenario_severity(mas_yaml: Path) -> None:
    """Each MAS scenario must be HIGH or CRITICAL severity."""
    scenario = load_scenario(mas_yaml)
    assert scenario.severity.value in ("HIGH", "CRITICAL"), (
        f"{scenario.id} severity is {scenario.severity.value}, expected HIGH or CRITICAL"
    )


def test_mas_scenario_has_references(mas_yaml: Path) -> None:
    """Each MAS scenario should have at least one reference."""
    scenario = load_scenario(mas_yaml)
    assert len(scenario.references) >= 1, f"{scenario.id} has no references"


# --- Verdict enum tests ---


def test_infection_propagated_verdict_exists() -> None:
    """INFECTION_PROPAGATED must exist in the Verdict enum."""
    assert hasattr(Verdict, "INFECTION_PROPAGATED")
    assert Verdict.INFECTION_PROPAGATED.value == "INFECTION_PROPAGATED"


def test_collusion_verdict_exists() -> None:
    """COLLUSION must exist in the Verdict enum."""
    assert hasattr(Verdict, "COLLUSION")
    assert Verdict.COLLUSION.value == "COLLUSION"


def test_watchdog_bypass_verdict_exists() -> None:
    """WATCHDOG_BYPASS must exist in the Verdict enum."""
    assert hasattr(Verdict, "WATCHDOG_BYPASS")
    assert Verdict.WATCHDOG_BYPASS.value == "WATCHDOG_BYPASS"


def test_new_verdicts_are_strings() -> None:
    """New verdicts must be usable as strings (StrEnum compatibility)."""
    assert str(Verdict.INFECTION_PROPAGATED) == "INFECTION_PROPAGATED"
    assert str(Verdict.COLLUSION) == "COLLUSION"
    assert str(Verdict.WATCHDOG_BYPASS) == "WATCHDOG_BYPASS"
