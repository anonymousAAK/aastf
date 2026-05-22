"""Tests for MCP scenario YAML validation."""
from pathlib import Path

import pytest

from aastf.models.scenario import AttackScenario
from aastf.scenarios.loader import load_scenario

SCENARIO_DIR = Path(__file__).parent.parent.parent / "src" / "aastf" / "scenarios" / "builtin"


def _collect_mcp_yamls():
    """Collect all scenario YAML files that have 'mcp' in their tags.

    MCP scenarios live in asi0X directories with ASI IDs but carry the 'mcp' tag.
    We identify them by loading and checking tags, but for parametrize we use a
    cheaper heuristic: scenario IDs >= 006 were added as MCP scenarios.
    """
    yamls = []
    if not SCENARIO_DIR.exists():
        return yamls
    for d in SCENARIO_DIR.iterdir():
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.yaml")):
            if f.name == "meta.yaml":
                continue
            # Load and check for mcp tag
            try:
                scenario = load_scenario(f)
                if "mcp" in scenario.tags:
                    yamls.append(f)
            except Exception:
                continue
    return yamls


_MCP_YAMLS = _collect_mcp_yamls()


@pytest.fixture(
    params=_MCP_YAMLS if _MCP_YAMLS else [pytest.param(None, marks=pytest.mark.skip("No MCP scenarios found"))],
    ids=lambda p: p.stem if p else "none",
)
def mcp_yaml(request):
    return request.param


def test_mcp_scenario_loads(mcp_yaml):
    """Each MCP scenario YAML should load and validate as AttackScenario."""
    scenario = load_scenario(mcp_yaml)
    assert isinstance(scenario, AttackScenario)


def test_mcp_scenario_has_detection(mcp_yaml):
    """Each MCP scenario must have at least one detection criterion."""
    scenario = load_scenario(mcp_yaml)
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


def test_mcp_scenario_has_tags(mcp_yaml):
    """Each MCP scenario should have 'mcp' in tags."""
    scenario = load_scenario(mcp_yaml)
    assert "mcp" in scenario.tags, f"{scenario.id} missing 'mcp' tag"


def test_mcp_scenario_has_references(mcp_yaml):
    """Each MCP scenario should have at least one reference."""
    scenario = load_scenario(mcp_yaml)
    assert len(scenario.references) >= 1, f"{scenario.id} has no references"
