"""Unit tests for the YAML scenario loader."""

import textwrap
from pathlib import Path

import pytest

from aastf.exceptions import ScenarioValidationError
from aastf.scenarios.loader import load_directory, load_scenario, render_payload


class TestLoadScenario:
    def test_loads_valid_yaml(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""\
            id: ASI01-001
            name: Test Scenario
            category: ASI01
            severity: HIGH
            description: desc
            attack_vector: vector
            inject_into: user_message
            payload: "inject me"
            detection:
              tool_called: [send_email]
            expected_behavior: "do nothing bad"
            remediation: "fix it"
        """)
        f = tmp_path / "test.yaml"
        f.write_text(yaml_content)
        s = load_scenario(f)
        assert s.id == "ASI01-001"
        assert s.name == "Test Scenario"

    def test_raises_on_missing_required_field(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""\
            id: ASI01-001
            name: Missing Fields
            category: ASI01
        """)
        f = tmp_path / "bad.yaml"
        f.write_text(yaml_content)
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)

    def test_raises_on_malformed_yaml(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("id: [unclosed bracket")
        with pytest.raises(ScenarioValidationError, match="YAML parse error"):
            load_scenario(f)

    def test_raises_on_invalid_id_format(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""\
            id: INVALID-001
            name: Bad ID
            category: ASI01
            severity: HIGH
            description: desc
            attack_vector: vector
            inject_into: user_message
            payload: test
            detection:
              tool_called: [bad_tool]
            expected_behavior: safe
            remediation: fix
        """)
        f = tmp_path / "bad_id.yaml"
        f.write_text(yaml_content)
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)

    def test_raises_on_nonexistent_file(self, tmp_path: Path):
        with pytest.raises(ScenarioValidationError, match="Cannot read file"):
            load_scenario(tmp_path / "does_not_exist.yaml")

    def test_raises_on_yaml_list_instead_of_mapping(self, tmp_path: Path):
        f = tmp_path / "list.yaml"
        f.write_text("- item1\n- item2\n")
        with pytest.raises(ScenarioValidationError, match="YAML mapping"):
            load_scenario(f)


class TestRenderPayload:
    def test_renders_simple_template(self):
        result = render_payload("Hello {{ name }}", {"name": "world"})
        assert result == "Hello world"

    def test_renders_without_context(self):
        result = render_payload("No variables here")
        assert result == "No variables here"

    def test_raises_on_undefined_variable(self):
        from jinja2 import UndefinedError
        with pytest.raises(UndefinedError):
            render_payload("{{ undefined_var }}")


class TestLoadDirectory:
    def _write_scenario(self, path: Path, scenario_id: str, name: str = "Test") -> None:
        content = textwrap.dedent(f"""\
            id: {scenario_id}
            name: {name}
            category: ASI01
            severity: HIGH
            description: desc
            attack_vector: vector
            inject_into: user_message
            payload: test
            detection:
              tool_called: [bad_tool]
            expected_behavior: safe
            remediation: fix
        """)
        path.write_text(content)

    def test_loads_all_yaml_in_directory(self, tmp_path: Path):
        self._write_scenario(tmp_path / "ASI01-001.yaml", "ASI01-001", "First")
        self._write_scenario(tmp_path / "ASI01-002.yaml", "ASI01-002", "Second")
        scenarios = load_directory(tmp_path)
        assert len(scenarios) == 2

    def test_skips_meta_yaml(self, tmp_path: Path):
        self._write_scenario(tmp_path / "ASI01-001.yaml", "ASI01-001")
        (tmp_path / "meta.yaml").write_text("category: ASI01\nname: Goal Hijack\n")
        scenarios = load_directory(tmp_path)
        assert len(scenarios) == 1

    def test_loads_recursively(self, tmp_path: Path):
        sub = tmp_path / "sub"
        sub.mkdir()
        self._write_scenario(tmp_path / "ASI01-001.yaml", "ASI01-001")
        self._write_scenario(sub / "ASI01-002.yaml", "ASI01-002")
        scenarios = load_directory(tmp_path)
        assert len(scenarios) == 2

    def test_raises_on_nonexistent_directory(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_directory(tmp_path / "nonexistent")

    def test_raises_on_file_not_directory(self, tmp_path: Path):
        f = tmp_path / "file.yaml"
        f.write_text("")
        with pytest.raises(NotADirectoryError):
            load_directory(f)


class TestBuiltinScenarios:
    """Validate that all shipped scenarios pass schema validation."""

    def test_builtin_dir_loads_without_error(self):
        registry_module = __import__(
            "aastf.scenarios.registry", fromlist=["ScenarioRegistry"]
        )
        registry = registry_module.ScenarioRegistry().load_builtin()
        assert len(registry) >= 20  # at minimum 20 built-in scenarios

    def test_all_builtin_ids_are_unique(self):
        from aastf.scenarios.registry import ScenarioRegistry
        registry = ScenarioRegistry().load_builtin()
        ids = [s.id for s in registry.all()]
        assert len(ids) == len(set(ids)), "Duplicate scenario IDs found"

    def test_all_builtin_have_remediation(self):
        from aastf.scenarios.registry import ScenarioRegistry
        registry = ScenarioRegistry().load_builtin()
        for s in registry.all():
            assert s.remediation.strip(), f"{s.id} has empty remediation"

    def test_each_asi_category_has_at_least_two_scenarios(self):
        from aastf.models.scenario import ASICategory
        from aastf.scenarios.registry import ScenarioRegistry
        registry = ScenarioRegistry().load_builtin()
        for cat in ASICategory:
            cat_scenarios = registry.filter(categories=[cat])
            assert len(cat_scenarios) >= 2, f"{cat.value} has fewer than 2 scenarios"
