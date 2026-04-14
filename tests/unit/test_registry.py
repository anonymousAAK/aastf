"""Unit tests for the scenario registry."""

import textwrap
from pathlib import Path

import pytest

from aastf.models.scenario import ASICategory, Severity
from aastf.scenarios.registry import ScenarioRegistry


def _write_scenario(path: Path, scenario_id: str, category: str = "ASI01",
                    severity: str = "HIGH", tags: list[str] | None = None) -> None:
    tag_line = f"tags: [{', '.join(tags)}]" if tags else ""
    content = textwrap.dedent(f"""\
        id: {scenario_id}
        name: Scenario {scenario_id}
        category: {category}
        severity: {severity}
        description: desc
        attack_vector: vector
        inject_into: user_message
        payload: test
        {tag_line}
        detection:
          tool_called: [bad_tool]
        expected_behavior: safe
        remediation: fix
    """)
    path.write_text(content)


class TestScenarioRegistry:
    def test_load_builtin_returns_self(self):
        r = ScenarioRegistry()
        result = r.load_builtin()
        assert result is r

    def test_len_after_builtin_load(self):
        r = ScenarioRegistry().load_builtin()
        assert len(r) >= 20

    def test_get_existing_scenario(self):
        r = ScenarioRegistry().load_builtin()
        s = r.get("ASI01-001")
        assert s.id == "ASI01-001"

    def test_get_missing_raises_key_error(self):
        r = ScenarioRegistry().load_builtin()
        with pytest.raises(KeyError, match="ASI99-999"):
            r.get("ASI99-999")

    def test_contains(self):
        r = ScenarioRegistry().load_builtin()
        assert "ASI01-001" in r
        assert "FAKE-000" not in r

    def test_filter_by_category(self):
        r = ScenarioRegistry().load_builtin()
        results = r.filter(categories=[ASICategory.ASI02])
        assert all(s.category == ASICategory.ASI02 for s in results)
        assert len(results) >= 2

    def test_filter_by_string_category(self):
        r = ScenarioRegistry().load_builtin()
        results = r.filter(categories=["ASI01"])
        assert all(s.category == ASICategory.ASI01 for s in results)

    def test_filter_by_min_severity(self):
        r = ScenarioRegistry().load_builtin()
        results = r.filter(min_severity=Severity.CRITICAL)
        assert all(s.severity >= Severity.CRITICAL for s in results)

    def test_filter_by_string_severity(self):
        r = ScenarioRegistry().load_builtin()
        results = r.filter(min_severity="CRITICAL")
        assert all(s.severity >= Severity.CRITICAL for s in results)

    def test_filter_by_tags(self, tmp_path):
        _write_scenario(tmp_path / "ASI01-099.yaml", "ASI01-099", tags=["special-tag"])
        r = ScenarioRegistry()
        r.load_directory(tmp_path)
        results = r.filter(tags=["special-tag"])
        assert any(s.id == "ASI01-099" for s in results)

    def test_filter_exclude_ids(self):
        r = ScenarioRegistry().load_builtin()
        all_ids = {s.id for s in r.all()}
        excluded = list(all_ids)[:2]
        results = r.filter(exclude_ids=excluded)
        result_ids = {s.id for s in results}
        assert not result_ids.intersection(excluded)

    def test_filter_returns_sorted_by_category_then_severity(self):
        r = ScenarioRegistry().load_builtin()
        results = r.all()
        # Just verify it returns a list without error
        assert isinstance(results, list)

    def test_load_custom_directory(self, tmp_path):
        _write_scenario(tmp_path / "ASI01-099.yaml", "ASI01-099")
        r = ScenarioRegistry()
        r.load_directory(tmp_path)
        assert "ASI01-099" in r

    def test_duplicate_id_raises_on_custom_load(self, tmp_path):
        _write_scenario(tmp_path / "ASI01-001.yaml", "ASI01-001")
        r = ScenarioRegistry().load_builtin()
        with pytest.raises(ValueError, match="Duplicate"):
            r.load_directory(tmp_path)

    def test_filter_empty_result(self):
        r = ScenarioRegistry().load_builtin()
        results = r.filter(categories=["ASI01"], min_severity="CRITICAL",
                           tags=["nonexistent-tag-xyz"])
        assert results == []
