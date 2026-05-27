"""Tests for ASI06 memory attack scenario YAML validation (ASI06-011 through ASI06-016)."""
from __future__ import annotations

from pathlib import Path

import pytest

from aastf.models.scenario import AttackScenario
from aastf.scenarios.loader import load_scenario

ASI06_DIR = Path(__file__).parent.parent.parent / "src" / "aastf" / "scenarios" / "builtin" / "asi06"

NEW_MEMORY_SCENARIO_IDS = [
    "ASI06-011",
    "ASI06-012",
    "ASI06-013",
    "ASI06-014",
    "ASI06-015",
    "ASI06-016",
]

REQUIRED_FIELDS = [
    "id",
    "name",
    "description",
    "category",
    "severity",
    "attack_vector",
    "inject_into",
    "payload",
    "detection",
    "expected_behavior",
    "remediation",
    "tags",
    "cwe_ids",
    "nist_ai_rmf",
    "references",
]


def _collect_new_memory_yamls() -> list[Path]:
    """Collect only the new memory attack scenario YAMLs."""
    return sorted(ASI06_DIR / f"{sid}.yaml" for sid in NEW_MEMORY_SCENARIO_IDS)


def _collect_all_asi06_yamls() -> list[Path]:
    """Collect all ASI06 scenario YAMLs."""
    if not ASI06_DIR.exists():
        return []
    return sorted(f for f in ASI06_DIR.glob("*.yaml") if f.name != "meta.yaml")


_NEW_YAMLS = _collect_new_memory_yamls()


@pytest.fixture(
    params=_NEW_YAMLS,
    ids=lambda p: p.stem,
)
def memory_yaml(request: pytest.FixtureRequest) -> Path:
    return request.param


class TestMemoryAttackScenariosLoad:
    """Each new memory attack scenario YAML should load and validate."""

    def test_loads_and_validates(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert isinstance(scenario, AttackScenario)

    def test_id_starts_with_asi06(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert scenario.id.startswith("ASI06"), f"{scenario.id} does not start with ASI06"

    def test_category_is_asi06(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert str(scenario.category) == "ASI06", f"{scenario.id} category is {scenario.category}"

    def test_severity_is_high_or_critical(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert str(scenario.severity) in (
            "HIGH",
            "CRITICAL",
        ), f"{scenario.id} severity is {scenario.severity}"

    def test_tags_include_memory(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert "memory" in scenario.tags, f"{scenario.id} missing 'memory' tag"

    def test_tags_include_persistence(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert "persistence" in scenario.tags, f"{scenario.id} missing 'persistence' tag"

    def test_cwe_ids_present(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert len(scenario.cwe_ids) > 0, f"{scenario.id} has no CWE IDs"

    def test_nist_ai_rmf_present(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert len(scenario.nist_ai_rmf) > 0, f"{scenario.id} has no NIST AI RMF mappings"

    def test_has_detection_criteria(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
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

    def test_has_references(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert len(scenario.references) > 0, f"{scenario.id} has no references"

    def test_has_payload_variants(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        assert len(scenario.payload_variants) > 0, f"{scenario.id} has no payload variants"


class TestMemoryAttackRequiredFields:
    """Verify all required fields are present via the Pydantic model."""

    def test_required_fields_present(self, memory_yaml: Path) -> None:
        scenario = load_scenario(memory_yaml)
        for field in REQUIRED_FIELDS:
            value = getattr(scenario, field, None)
            assert value is not None, f"{scenario.id} missing required field: {field}"
            if isinstance(value, (str,)):
                assert len(value.strip()) > 0, f"{scenario.id} has empty field: {field}"
            elif isinstance(value, (list,)):
                assert len(value) > 0, f"{scenario.id} has empty list field: {field}"


class TestNoDuplicateIDs:
    """Ensure new scenario IDs do not collide with existing ones."""

    def test_no_duplicate_ids(self) -> None:
        all_yamls = _collect_all_asi06_yamls()
        ids_seen: dict[str, str] = {}
        for yaml_path in all_yamls:
            scenario = load_scenario(yaml_path)
            assert scenario.id not in ids_seen, (
                f"Duplicate ID {scenario.id} found in {yaml_path.name} "
                f"and {ids_seen[scenario.id]}"
            )
            ids_seen[scenario.id] = yaml_path.name

    def test_new_ids_are_expected(self) -> None:
        """Verify the new scenarios have the expected IDs."""
        for yaml_path in _NEW_YAMLS:
            scenario = load_scenario(yaml_path)
            assert scenario.id in NEW_MEMORY_SCENARIO_IDS, (
                f"Unexpected ID {scenario.id} in {yaml_path.name}"
            )

    def test_all_six_scenarios_exist(self) -> None:
        """All 6 new memory attack scenarios must exist."""
        for sid in NEW_MEMORY_SCENARIO_IDS:
            path = ASI06_DIR / f"{sid}.yaml"
            assert path.exists(), f"Missing scenario file: {path}"
