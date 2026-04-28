"""
Category C — Schema & Input Fuzzing.

Hypotheses:
  C1. Malformed YAML raises ScenarioValidationError, not an unhandled exception.
  C2. yaml.safe_load is used (!!python/object tags are rejected safely).
  C3. Schema-valid but semantically nonsensical scenarios are accepted or cleanly rejected.
  C4. Scenario ID with wrong format is rejected with a clear error.
  C5. Missing required fields are rejected by Pydantic.
  C6. Unknown category value is rejected.
  C7. Extremely large payload does not crash the loader.
  C8. Path traversal attempt in scenario_dir does not cause catastrophic failure.
  C9. YAML with BOM, CRLF line endings, or tab indentation is handled gracefully.
  C10. Duplicate scenario IDs in a directory are detected.
  C11. Scenario with all-empty detection criteria is valid and evaluates to SAFE.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aastf.exceptions import ScenarioValidationError
from aastf.scenarios.loader import load_scenario
from aastf.scenarios.registry import ScenarioRegistry

from .conftest import MINIMAL_VALID_YAML


# --------------------------------------------------------------------------- C1
class TestMalformedYAML:
    """C1: Malformed YAML raises ScenarioValidationError."""

    def test_unclosed_string_raises(self, tmp_path: Path):
        """Hypothesis: Unclosed quote in YAML raises ScenarioValidationError."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text('id: "ASI01-001\nname: unclosed', encoding="utf-8")
        with pytest.raises(ScenarioValidationError) as exc_info:
            load_scenario(bad_yaml)
        assert "YAML parse error" in str(exc_info.value)

    def test_scalar_not_mapping_raises(self, tmp_path: Path):
        """Hypothesis: YAML file containing a bare scalar raises ScenarioValidationError."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("just a string", encoding="utf-8")
        with pytest.raises(ScenarioValidationError) as exc_info:
            load_scenario(bad_yaml)
        assert "mapping" in str(exc_info.value).lower()

    def test_list_not_mapping_raises(self, tmp_path: Path):
        """Hypothesis: YAML file with top-level list raises ScenarioValidationError."""
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ScenarioValidationError) as exc_info:
            load_scenario(bad_yaml)
        assert "mapping" in str(exc_info.value).lower()

    def test_empty_file_raises(self, tmp_path: Path):
        """Hypothesis: Empty YAML file raises ScenarioValidationError."""
        bad_yaml = tmp_path / "empty.yaml"
        bad_yaml.write_text("", encoding="utf-8")
        with pytest.raises(ScenarioValidationError):
            load_scenario(bad_yaml)

    def test_nonexistent_file_raises(self, tmp_path: Path):
        """Hypothesis: Nonexistent file raises ScenarioValidationError."""
        with pytest.raises(ScenarioValidationError, match="Cannot read file"):
            load_scenario(tmp_path / "does_not_exist.yaml")


# --------------------------------------------------------------------------- C2
class TestYAMLDeserializationSafety:
    """C2: yaml.safe_load is used — !!python/object tags must NOT execute code."""

    def test_python_object_tag_does_not_execute(self, tmp_path: Path):
        """
        Hypothesis: !!python/object construct in YAML is rejected safely.
        With yaml.safe_load, this raises a YAMLError, not arbitrary code execution.
        """
        malicious_yaml = tmp_path / "malicious.yaml"
        malicious_yaml.write_text(
            "!!python/object/apply:os.system ['echo pwned']",
            encoding="utf-8",
        )
        with pytest.raises(ScenarioValidationError) as exc_info:
            load_scenario(malicious_yaml)
        # Must be a YAML parse error, not silent execution
        assert "YAML parse error" in str(exc_info.value)

    def test_python_object_new_tag_rejected(self, tmp_path: Path):
        """Hypothesis: !!python/object/new construct is rejected safely."""
        malicious = tmp_path / "malicious2.yaml"
        malicious.write_text(
            "!!python/object/new:subprocess.Popen\n- [id]\n",
            encoding="utf-8",
        )
        with pytest.raises(ScenarioValidationError):
            load_scenario(malicious)


# --------------------------------------------------------------------------- C3
class TestSemanticallySurprising:
    """C3: Semantically surprising but schema-valid scenarios."""

    def test_scenario_with_no_detection_criteria_is_valid(self, tmp_path: Path):
        """Hypothesis: A scenario with empty detection{} loads successfully."""
        f = tmp_path / "nodect.yaml"
        f.write_text(MINIMAL_VALID_YAML, encoding="utf-8")
        scenario = load_scenario(f)
        assert scenario is not None

    def test_scenario_with_huge_tool_call_limit_is_valid(self, tmp_path: Path):
        """Hypothesis: tool_call_count_exceeds=999999 loads without error."""
        yaml_content = MINIMAL_VALID_YAML.replace(
            "detection: {}", "detection:\n  tool_call_count_exceeds: 999999"
        )
        f = tmp_path / "huge_limit.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        scenario = load_scenario(f)
        assert scenario.detection.tool_call_count_exceeds == 999999

    def test_scenario_with_negative_loop_limit_is_rejected(self, tmp_path: Path):
        """
        Hypothesis (BUG-12 FIXED): Pydantic now rejects negative loop_iterations_exceed
        with a validation error. Nonsensical negative thresholds are caught at load time.
        """
        yaml_content = MINIMAL_VALID_YAML.replace(
            "detection: {}", "detection:\n  loop_iterations_exceed: -1"
        )
        f = tmp_path / "neg_limit.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)


# --------------------------------------------------------------------------- C4
class TestIDValidation:
    """C4: Scenario ID format validation."""

    @pytest.mark.parametrize("bad_id", [
        "ASI1-001",       # only 1 digit after ASI
        "ASI012-001",     # 3 digits after ASI
        "ASI01-01",       # only 2 digits after dash
        "ASI01-0001",     # 4 digits after dash
        "asi01-001",      # lowercase
        "ASI01_001",      # underscore instead of dash
        "ASI01-001-extra", # extra suffix
        "",               # empty
        "TOTALLY_WRONG",  # gibberish
    ])
    def test_invalid_id_rejected(self, tmp_path: Path, bad_id: str):
        """Hypothesis: Invalid scenario IDs raise ScenarioValidationError."""
        yaml_content = MINIMAL_VALID_YAML.replace("ASI01-001", bad_id)
        f = tmp_path / "bad_id.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)

    def test_valid_id_accepted(self, tmp_path: Path):
        """Hypothesis: Valid ID format ASI##-### is accepted."""
        f = tmp_path / "good.yaml"
        f.write_text(MINIMAL_VALID_YAML, encoding="utf-8")
        s = load_scenario(f)
        assert s.id == "ASI01-001"


# --------------------------------------------------------------------------- C5
class TestMissingRequiredFields:
    """C5: Missing required fields are rejected."""

    @pytest.mark.parametrize("missing_field", [
        "name",
        "category",
        "severity",
        "description",
        "attack_vector",
        "inject_into",
        "payload",
        "expected_behavior",
        "remediation",
    ])
    def test_missing_required_field_raises(self, tmp_path: Path, missing_field: str):
        """Hypothesis: Each required field, when absent, raises ScenarioValidationError."""
        lines = MINIMAL_VALID_YAML.splitlines()
        filtered = [
            line for line in lines
            if not line.strip().startswith(missing_field + ":")
        ]
        f = tmp_path / f"missing_{missing_field}.yaml"
        f.write_text("\n".join(filtered), encoding="utf-8")
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)


# --------------------------------------------------------------------------- C6
class TestInvalidEnumValues:
    """C6: Invalid enum values are rejected."""

    def test_invalid_category_raises(self, tmp_path: Path):
        """Hypothesis: Unknown category value raises ScenarioValidationError."""
        yaml_content = MINIMAL_VALID_YAML.replace("ASI01", "ASI99")
        # Note: ID also changes to ASI99-001 which won't match the pattern
        # so we need to handle the ID check too
        yaml_content = yaml_content.replace("id: ASI99-001", "id: ASI01-001")
        f = tmp_path / "bad_cat.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)

    def test_invalid_severity_raises(self, tmp_path: Path):
        """Hypothesis: Unknown severity value raises ScenarioValidationError."""
        yaml_content = MINIMAL_VALID_YAML.replace("severity: HIGH", "severity: EXTREME")
        f = tmp_path / "bad_sev.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)

    def test_invalid_inject_into_raises(self, tmp_path: Path):
        """Hypothesis: Unknown inject_into value raises ScenarioValidationError."""
        yaml_content = MINIMAL_VALID_YAML.replace("inject_into: user_message", "inject_into: banana")
        f = tmp_path / "bad_inject.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        with pytest.raises(ScenarioValidationError):
            load_scenario(f)


# --------------------------------------------------------------------------- C7
class TestLargePayloads:
    """C7: Extremely large payloads do not crash the loader."""

    def test_10kb_payload_loads(self, tmp_path: Path):
        """Hypothesis: A 10KB payload string loads without error."""
        big_payload = "A" * 10240
        yaml_content = MINIMAL_VALID_YAML.replace('payload: "inject"', f'payload: "{big_payload}"')
        f = tmp_path / "big_payload.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        scenario = load_scenario(f)
        assert len(scenario.payload) == 10240

    def test_100_detection_strings_loads(self, tmp_path: Path):
        """Hypothesis: 100 output_contains strings load and evaluate without error."""
        strings = [f"pattern_{i}" for i in range(100)]
        yaml_list = "\n".join(f"  - '{s}'" for s in strings)
        yaml_content = MINIMAL_VALID_YAML.replace(
            "detection: {}",
            f"detection:\n  output_contains:\n{yaml_list}"
        )
        f = tmp_path / "many_patterns.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        scenario = load_scenario(f)
        assert len(scenario.detection.output_contains) == 100


# --------------------------------------------------------------------------- C8
class TestPathTraversal:
    """C8: Path traversal in scenario_dir does not cause catastrophic failure."""

    def test_load_directory_rejects_nonexistent_path(self):
        """Hypothesis: load_directory raises FileNotFoundError for nonexistent path."""
        from aastf.scenarios.loader import load_directory
        with pytest.raises(FileNotFoundError):
            load_directory(Path("/this/path/does/not/exist/xyz"))

    def test_load_directory_rejects_file_not_dir(self, tmp_path: Path):
        """Hypothesis: load_directory raises NotADirectoryError for a file path."""
        from aastf.scenarios.loader import load_directory
        f = tmp_path / "a_file.txt"
        f.write_text("hello", encoding="utf-8")
        with pytest.raises(NotADirectoryError):
            load_directory(f)

    def test_load_directory_rejects_dotdot_traversal(self):
        """
        Hypothesis (BUG-07 FIXED): load_directory rejects paths containing '..'
        with a ValueError to prevent path traversal attacks.
        """
        from aastf.scenarios.loader import load_directory
        with pytest.raises(ValueError, match="traversal"):
            load_directory(Path("../../../etc"))

    def test_load_directory_rejects_dotdot_in_components(self):
        """Hypothesis: Path with '..' in the middle is also rejected."""
        from aastf.scenarios.loader import load_directory
        with pytest.raises(ValueError, match="traversal"):
            load_directory(Path("scenarios/../../../etc/passwd"))


# --------------------------------------------------------------------------- C9
class TestEncodingVariants:
    """C9: YAML with BOM, CRLF, or unicode loads gracefully."""

    def test_utf8_bom_loads(self, tmp_path: Path):
        """Hypothesis: UTF-8 BOM at start of file is handled correctly."""
        f = tmp_path / "bom.yaml"
        # Write UTF-8 BOM + valid YAML
        f.write_bytes(b"\xef\xbb\xbf" + MINIMAL_VALID_YAML.encode("utf-8"))
        # yaml.safe_load handles UTF-8 BOM transparently
        scenario = load_scenario(f)
        assert scenario.id == "ASI01-001"

    def test_crlf_line_endings_load(self, tmp_path: Path):
        """Hypothesis: Windows CRLF line endings in YAML are handled correctly."""
        crlf_yaml = MINIMAL_VALID_YAML.replace("\n", "\r\n")
        f = tmp_path / "crlf.yaml"
        f.write_bytes(crlf_yaml.encode("utf-8"))
        scenario = load_scenario(f)
        assert scenario.id == "ASI01-001"

    def test_unicode_in_payload_loads(self, tmp_path: Path):
        """Hypothesis: Unicode characters in payload are preserved."""
        yaml_content = MINIMAL_VALID_YAML.replace(
            'payload: "inject"',
            'payload: "Ignore: \u5c31\u662f\u4e00\u4e2a\u6d4b\u8bd5 \U0001F600"'
        )
        f = tmp_path / "unicode.yaml"
        f.write_text(yaml_content, encoding="utf-8")
        scenario = load_scenario(f)
        assert "\U0001F600" in scenario.payload


# --------------------------------------------------------------------------- C10
class TestDuplicateIDs:
    """C10: Duplicate scenario IDs within a loaded directory are detected."""

    def test_duplicate_ids_in_registry_raise(self, tmp_path: Path):
        """Hypothesis: Two files with the same ID in a user-supplied directory raise ValueError."""
        # First file
        f1 = tmp_path / "a.yaml"
        f1.write_text(MINIMAL_VALID_YAML, encoding="utf-8")
        # Second file with same ID
        f2 = tmp_path / "b.yaml"
        f2.write_text(MINIMAL_VALID_YAML, encoding="utf-8")

        registry = ScenarioRegistry()
        with pytest.raises((ValueError, Exception)):
            # Either the loader or registry should detect the duplicate
            registry.load_directory(tmp_path)


# --------------------------------------------------------------------------- C11
class TestNegativeLoopLimit:
    """
    C11 (BUG-12 FIXED): Pydantic now rejects negative loop_iterations_exceed values.
    """

    def test_negative_loop_limit_raises_validation_error(self):
        """
        Hypothesis (BUG-12 FIXED): DetectionCriteria with negative loop_iterations_exceed
        now raises a Pydantic ValidationError — fail-fast at model construction time.
        """
        from pydantic import ValidationError

        from aastf.models.scenario import DetectionCriteria

        with pytest.raises(ValidationError):
            DetectionCriteria(loop_iterations_exceed=-1)

    def test_negative_tool_call_count_raises_validation_error(self):
        """
        Hypothesis (BUG-12 FIXED): DetectionCriteria with negative tool_call_count_exceeds
        raises a Pydantic ValidationError.
        """
        from pydantic import ValidationError

        from aastf.models.scenario import DetectionCriteria

        with pytest.raises(ValidationError):
            DetectionCriteria(tool_call_count_exceeds=-5)

    def test_zero_threshold_is_valid(self):
        """Hypothesis: Zero is a valid (if unusual) threshold."""
        from aastf.models.scenario import DetectionCriteria
        c = DetectionCriteria(loop_iterations_exceed=0)
        assert c.loop_iterations_exceed == 0


# Need to import Verdict here
