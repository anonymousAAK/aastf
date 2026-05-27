"""Tests for ASI08 cascading-failure and ASI05 tool-output-poisoning deep-dive scenarios."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aastf.models.scenario import AttackScenario
from aastf.scenarios.loader import load_scenario

SCENARIO_DIR = Path(__file__).parent.parent.parent / "src" / "aastf" / "scenarios" / "builtin"

ASI08_IDS = [f"ASI08-{n:03d}" for n in range(6, 11)]
ASI05_IDS = [f"ASI05-{n:03d}" for n in range(8, 13)]
ALL_IDS = ASI08_IDS + ASI05_IDS

CWE_PATTERN = re.compile(r"^CWE-\d+$")


def _load(scenario_id: str) -> AttackScenario:
    prefix = scenario_id[:5].lower()  # e.g. "asi08"
    path = SCENARIO_DIR / prefix / f"{scenario_id}.yaml"
    return load_scenario(path)


# ── Parametrised fixtures ──────────────────────────────────────────────


@pytest.fixture(params=ALL_IDS, ids=lambda s: s)
def scenario(request: pytest.FixtureRequest) -> AttackScenario:
    return _load(request.param)


@pytest.fixture(params=ASI08_IDS, ids=lambda s: s)
def asi08_scenario(request: pytest.FixtureRequest) -> AttackScenario:
    return _load(request.param)


@pytest.fixture(params=ASI05_IDS, ids=lambda s: s)
def asi05_scenario(request: pytest.FixtureRequest) -> AttackScenario:
    return _load(request.param)


# ── All-scenario tests ────────────────────────────────────────────────


def test_scenario_loads_and_validates(scenario: AttackScenario) -> None:
    """Each new scenario YAML should load and validate as AttackScenario."""
    assert isinstance(scenario, AttackScenario)


def test_required_fields_present(scenario: AttackScenario) -> None:
    """Required metadata fields must be non-empty."""
    assert scenario.id
    assert scenario.name
    assert scenario.description.strip()
    assert scenario.category
    assert scenario.severity
    assert scenario.attack_vector
    assert scenario.payload.strip()
    assert scenario.expected_behavior.strip()
    assert scenario.remediation.strip()
    assert scenario.tags
    assert scenario.references


def test_cwe_ids_present_and_formatted(scenario: AttackScenario) -> None:
    """Each scenario must have at least one properly-formatted CWE ID."""
    assert len(scenario.cwe_ids) >= 1, f"{scenario.id} has no CWE IDs"
    for cwe in scenario.cwe_ids:
        assert CWE_PATTERN.match(cwe), f"{scenario.id}: malformed CWE ID {cwe!r}"


def test_nist_ai_rmf_present(scenario: AttackScenario) -> None:
    """Each scenario must reference at least one NIST AI RMF control."""
    assert len(scenario.nist_ai_rmf) >= 1, f"{scenario.id} has no NIST AI RMF mappings"


def test_has_detection_criteria(scenario: AttackScenario) -> None:
    """Each scenario must have at least one detection criterion."""
    d = scenario.detection
    has_detection = (
        d.tool_called
        or d.tool_not_called
        or d.tool_input_contains
        or d.output_contains
        or d.output_not_contains
        or d.tool_call_count_exceeds is not None
        or d.loop_iterations_exceed is not None
        or d.custom_evaluator is not None
    )
    assert has_detection, f"{scenario.id} has no detection criteria"


# ── Category-specific tests ───────────────────────────────────────────


def test_asi08_category(asi08_scenario: AttackScenario) -> None:
    """ASI08 scenarios must have category ASI08."""
    assert asi08_scenario.category == "ASI08", (
        f"{asi08_scenario.id} has category {asi08_scenario.category}, expected ASI08"
    )


def test_asi05_category(asi05_scenario: AttackScenario) -> None:
    """ASI05 scenarios must have category ASI05."""
    assert asi05_scenario.category == "ASI05", (
        f"{asi05_scenario.id} has category {asi05_scenario.category}, expected ASI05"
    )


def test_asi08_has_cascading_tag(asi08_scenario: AttackScenario) -> None:
    """ASI08 deep-dive scenarios should carry the 'cascading-failure' tag."""
    assert "cascading-failure" in asi08_scenario.tags, (
        f"{asi08_scenario.id} missing 'cascading-failure' tag"
    )


def test_asi05_has_poisoning_tag(asi05_scenario: AttackScenario) -> None:
    """ASI05 deep-dive scenarios should carry the 'tool-output-poisoning' tag."""
    assert "tool-output-poisoning" in asi05_scenario.tags, (
        f"{asi05_scenario.id} missing 'tool-output-poisoning' tag"
    )


# ── Uniqueness ────────────────────────────────────────────────────────


def test_no_duplicate_ids() -> None:
    """All new scenario IDs must be unique."""
    loaded_ids = [_load(sid).id for sid in ALL_IDS]
    assert len(loaded_ids) == len(set(loaded_ids)), (
        f"Duplicate IDs found: {[x for x in loaded_ids if loaded_ids.count(x) > 1]}"
    )
