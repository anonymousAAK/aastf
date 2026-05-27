"""Scenario contract tests — verify all builtin YAML scenarios conform to the schema.

Every scenario YAML must:
- Parse into a valid AttackScenario
- Have all required fields
- Follow the ID naming convention (ASI##-###, MCP##-###, CVE##-###)
- Have no duplicate IDs
- Map to a valid ASICategory and Severity
- Have valid CWE ID format (CWE-NNN)
- Have valid NIST AI RMF reference format
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from aastf.models.scenario import ASICategory, AttackScenario, Severity
from aastf.scenarios.registry import ScenarioRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_BUILTIN_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "aastf" / "scenarios" / "builtin"


@pytest.fixture(scope="module")
def all_scenarios() -> list[AttackScenario]:
    """Load every builtin scenario once for the entire module."""
    registry = ScenarioRegistry().load_builtin()
    scenarios = registry.all()
    assert len(scenarios) > 0, "No builtin scenarios found — check BUILTIN_DIR"
    return scenarios


@pytest.fixture(scope="module")
def scenario_ids(all_scenarios: list[AttackScenario]) -> list[str]:
    return [s.id for s in all_scenarios]


# ---------------------------------------------------------------------------
# Schema compliance: every YAML parses into a valid AttackScenario
# ---------------------------------------------------------------------------


def test_all_builtin_scenarios_load(all_scenarios: list[AttackScenario]) -> None:
    """All builtin YAML files must parse into valid AttackScenario objects."""
    # If load_builtin() succeeded without raising, all files are valid.
    assert len(all_scenarios) >= 50, (
        f"Expected at least 50 builtin scenarios, got {len(all_scenarios)}"
    )


# ---------------------------------------------------------------------------
# Required fields present on every scenario
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = [
    "id",
    "name",
    "category",
    "severity",
    "description",
    "attack_vector",
    "inject_into",
    "payload",
    "detection",
    "expected_behavior",
    "remediation",
]


@pytest.mark.parametrize("field", _REQUIRED_FIELDS)
def test_required_fields_present(
    all_scenarios: list[AttackScenario], field: str
) -> None:
    """Every scenario must have a non-empty value for each required field."""
    for s in all_scenarios:
        value = getattr(s, field)
        if isinstance(value, str):
            assert value.strip(), (
                f"Scenario {s.id}: required field '{field}' is empty"
            )
        else:
            assert value is not None, (
                f"Scenario {s.id}: required field '{field}' is None"
            )


# ---------------------------------------------------------------------------
# ID naming convention
# ---------------------------------------------------------------------------

_ID_PATTERN = re.compile(r"^(ASI|MCP|CVE|A2A|MAS)\d{2}-\d{3}$")


def test_all_ids_follow_naming_convention(
    all_scenarios: list[AttackScenario],
) -> None:
    """Every scenario ID must match ASI##-###, MCP##-###, or CVE##-### format."""
    for s in all_scenarios:
        assert _ID_PATTERN.match(s.id), (
            f"Scenario ID {s.id!r} does not match required pattern "
            f"(ASI##-###, MCP##-###, or CVE##-###)"
        )


# ---------------------------------------------------------------------------
# No duplicate IDs
# ---------------------------------------------------------------------------


def test_no_duplicate_scenario_ids(scenario_ids: list[str]) -> None:
    """Every scenario ID must be unique across the entire builtin registry."""
    counts = Counter(scenario_ids)
    duplicates = {sid: count for sid, count in counts.items() if count > 1}
    assert not duplicates, f"Duplicate scenario IDs found: {duplicates}"


# ---------------------------------------------------------------------------
# Category mapping
# ---------------------------------------------------------------------------

_VALID_CATEGORIES = {c.value for c in ASICategory}


def test_every_category_maps_to_valid_enum(
    all_scenarios: list[AttackScenario],
) -> None:
    """Every scenario's category must be a valid ASICategory enum member."""
    for s in all_scenarios:
        assert isinstance(s.category, ASICategory), (
            f"Scenario {s.id}: category {s.category!r} is not an ASICategory"
        )
        assert s.category.value in _VALID_CATEGORIES


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = {s.value for s in Severity}


def test_every_severity_maps_to_valid_enum(
    all_scenarios: list[AttackScenario],
) -> None:
    """Every scenario's severity must be a valid Severity enum member."""
    for s in all_scenarios:
        assert isinstance(s.severity, Severity), (
            f"Scenario {s.id}: severity {s.severity!r} is not a Severity"
        )
        assert s.severity.value in _VALID_SEVERITIES


# ---------------------------------------------------------------------------
# CWE ID format
# ---------------------------------------------------------------------------

_CWE_PATTERN = re.compile(r"^CWE-\d+$")


def test_cwe_ids_valid_format(all_scenarios: list[AttackScenario]) -> None:
    """Every CWE ID must match the CWE-\\d+ format."""
    for s in all_scenarios:
        for cwe in s.cwe_ids:
            assert _CWE_PATTERN.match(cwe), (
                f"Scenario {s.id}: invalid CWE ID format {cwe!r} "
                f"(expected CWE-\\d+, e.g. CWE-74)"
            )


# ---------------------------------------------------------------------------
# NIST AI RMF reference format
# ---------------------------------------------------------------------------

# NIST AI RMF references follow the pattern: FUNCTION-X.Y
# Functions: GOVERN, MAP, MEASURE, MANAGE
_NIST_PATTERN = re.compile(r"^(GOVERN|MAP|MEASURE|MANAGE)-\d+\.\d+$")


def test_nist_ai_rmf_valid_format(all_scenarios: list[AttackScenario]) -> None:
    """Every NIST AI RMF reference must match FUNCTION-X.Y format."""
    for s in all_scenarios:
        for ref in s.nist_ai_rmf:
            assert _NIST_PATTERN.match(ref), (
                f"Scenario {s.id}: invalid NIST AI RMF reference {ref!r} "
                f"(expected GOVERN|MAP|MEASURE|MANAGE-X.Y)"
            )


# ---------------------------------------------------------------------------
# Cross-check: scenario ID prefix matches category
# ---------------------------------------------------------------------------


def test_asi_id_prefix_matches_category(
    all_scenarios: list[AttackScenario],
) -> None:
    """For ASI-prefixed scenarios, the ID prefix must match the category."""
    for s in all_scenarios:
        if s.id.startswith("ASI"):
            prefix = s.id.split("-")[0]  # e.g. "ASI01"
            assert s.category.value == prefix, (
                f"Scenario {s.id}: ID prefix {prefix} does not match "
                f"category {s.category.value}"
            )


# ---------------------------------------------------------------------------
# Detection criteria: at least one criterion defined
# ---------------------------------------------------------------------------


def test_detection_has_at_least_one_criterion(
    all_scenarios: list[AttackScenario],
) -> None:
    """Every scenario must define at least one detection criterion."""
    for s in all_scenarios:
        d = s.detection
        has_criterion = (
            bool(d.tool_called)
            or bool(d.tool_not_called)
            or bool(d.tool_input_contains)
            or d.tool_call_count_exceeds is not None
            or bool(d.output_contains)
            or bool(d.output_not_contains)
            or d.loop_iterations_exceed is not None
            or d.custom_evaluator is not None
        )
        assert has_criterion, (
            f"Scenario {s.id}: detection criteria is empty — "
            f"at least one criterion must be defined"
        )


# ---------------------------------------------------------------------------
# Payload is non-trivial
# ---------------------------------------------------------------------------


def test_payload_is_non_trivial(all_scenarios: list[AttackScenario]) -> None:
    """Every scenario payload must be at least 10 characters (meaningful content)."""
    for s in all_scenarios:
        assert len(s.payload.strip()) >= 10, (
            f"Scenario {s.id}: payload is too short ({len(s.payload.strip())} chars)"
        )


# ---------------------------------------------------------------------------
# Description and remediation are non-trivial
# ---------------------------------------------------------------------------


def test_description_is_non_trivial(all_scenarios: list[AttackScenario]) -> None:
    """Every scenario description must be at least 20 characters."""
    for s in all_scenarios:
        assert len(s.description.strip()) >= 20, (
            f"Scenario {s.id}: description is too short"
        )


def test_remediation_is_non_trivial(all_scenarios: list[AttackScenario]) -> None:
    """Every scenario remediation must be at least 20 characters."""
    for s in all_scenarios:
        assert len(s.remediation.strip()) >= 20, (
            f"Scenario {s.id}: remediation is too short"
        )


# ---------------------------------------------------------------------------
# All 10 ASI categories are covered by at least one scenario
# ---------------------------------------------------------------------------


def test_all_asi_categories_covered(all_scenarios: list[AttackScenario]) -> None:
    """There must be at least one scenario for every ASICategory."""
    covered = {s.category for s in all_scenarios}
    for cat in ASICategory:
        assert cat in covered, (
            f"ASICategory {cat.value} has no builtin scenarios"
        )
