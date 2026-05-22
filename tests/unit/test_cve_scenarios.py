"""Tests for CVE scenario YAML validation."""
from pathlib import Path

import pytest

from aastf.models.scenario import AttackScenario
from aastf.scenarios.loader import load_scenario

CVE_SCENARIO_DIR = Path(__file__).parent.parent.parent / "src" / "aastf" / "scenarios" / "builtin" / "cve01"


def _collect_cve_yamls():
    if not CVE_SCENARIO_DIR.exists():
        return []
    return sorted(f for f in CVE_SCENARIO_DIR.glob("*.yaml") if f.name != "meta.yaml")


_CVE_YAMLS = _collect_cve_yamls()


@pytest.fixture(
    params=_CVE_YAMLS if _CVE_YAMLS else [pytest.param(None, marks=pytest.mark.skip("No CVE scenarios found"))],
    ids=lambda p: p.stem if p else "none",
)
def cve_yaml(request):
    return request.param


def test_cve_scenario_loads(cve_yaml):
    """Each CVE scenario YAML should load and validate."""
    scenario = load_scenario(cve_yaml)
    assert isinstance(scenario, AttackScenario)
    assert scenario.id.startswith("CVE")


def test_cve_scenario_has_detection(cve_yaml):
    """Each CVE scenario must have at least one detection criterion."""
    scenario = load_scenario(cve_yaml)
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


def test_cve_scenario_has_cve_tag(cve_yaml):
    """Each CVE scenario should have 'cve' tag."""
    scenario = load_scenario(cve_yaml)
    assert "cve" in scenario.tags, f"{scenario.id} missing 'cve' tag"
