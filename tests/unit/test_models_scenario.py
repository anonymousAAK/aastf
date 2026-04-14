"""Unit tests for scenario models."""

import pytest
from pydantic import ValidationError

from aastf.models.scenario import (
    ASICategory,
    AttackScenario,
    DetectionCriteria,
    InjectionPoint,
    Severity,
    ToolResponseConfig,
)


def _make_scenario(**overrides) -> AttackScenario:
    defaults = dict(
        id="ASI01-001",
        name="Test scenario",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        description="Test description",
        attack_vector="Test vector",
        inject_into=InjectionPoint.USER_MESSAGE,
        payload="test payload",
        detection=DetectionCriteria(tool_called=["bad_tool"]),
        expected_behavior="Agent should do nothing bad.",
        remediation="Fix it.",
    )
    defaults.update(overrides)
    return AttackScenario(**defaults)


class TestASICategory:
    def test_all_ten_categories_exist(self):
        categories = list(ASICategory)
        assert len(categories) == 10

    def test_display_names_all_populated(self):
        for cat in ASICategory:
            assert len(cat.display_name) > 0

    def test_category_values(self):
        assert ASICategory.ASI01.value == "ASI01"
        assert ASICategory.ASI10.value == "ASI10"


class TestSeverity:
    def test_numeric_ordering(self):
        assert Severity.CRITICAL.numeric() > Severity.HIGH.numeric()
        assert Severity.HIGH.numeric() > Severity.MEDIUM.numeric()
        assert Severity.MEDIUM.numeric() > Severity.LOW.numeric()
        assert Severity.LOW.numeric() > Severity.INFO.numeric()

    def test_comparison_operators(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.MEDIUM >= Severity.LOW

    def test_all_five_levels(self):
        assert len(list(Severity)) == 5


class TestAttackScenario:
    def test_valid_scenario_loads(self):
        s = _make_scenario()
        assert s.id == "ASI01-001"
        assert s.category == ASICategory.ASI01
        assert s.severity == Severity.HIGH

    def test_id_format_valid(self):
        for cat_num in ["01", "02", "10"]:
            s = _make_scenario(id=f"ASI{cat_num}-001", category=ASICategory(f"ASI{cat_num}"))
            assert s.id.startswith("ASI")

    def test_id_format_invalid_rejected(self):
        with pytest.raises(ValidationError, match="ASI##-###"):
            _make_scenario(id="INVALID-001")

    def test_id_format_wrong_separator(self):
        with pytest.raises(ValidationError):
            _make_scenario(id="ASI01_001")

    def test_id_format_missing_leading_zero(self):
        with pytest.raises(ValidationError):
            _make_scenario(id="ASI1-001")

    def test_default_author(self):
        s = _make_scenario()
        assert s.author == "aastf-core"

    def test_default_version(self):
        s = _make_scenario()
        assert s.version == "1.0"

    def test_empty_lists_default(self):
        s = _make_scenario()
        assert s.tags == []
        assert s.references == []
        assert s.payload_variants == []
        assert s.available_tools == []

    def test_tool_response_config_embedded(self):
        s = _make_scenario(
            tool_responses=[
                ToolResponseConfig(
                    tool_name="web_search",
                    response_payload={"results": []},
                    response_mode="success",
                )
            ]
        )
        assert len(s.tool_responses) == 1
        assert s.tool_responses[0].tool_name == "web_search"

    def test_serialization_round_trip(self):
        s = _make_scenario()
        data = s.model_dump()
        s2 = AttackScenario.model_validate(data)
        assert s2.id == s.id
        assert s2.category == s.category
        assert s2.severity == s.severity

    def test_json_round_trip(self):
        s = _make_scenario()
        json_str = s.model_dump_json()
        s2 = AttackScenario.model_validate_json(json_str)
        assert s2.id == s.id


class TestDetectionCriteria:
    def test_all_fields_optional(self):
        d = DetectionCriteria()
        assert d.tool_called == []
        assert d.tool_not_called == []
        assert d.tool_input_contains == {}
        assert d.tool_call_count_exceeds is None
        assert d.loop_iterations_exceed is None
        assert d.custom_evaluator is None

    def test_tool_called_list(self):
        d = DetectionCriteria(tool_called=["send_email", "delete_file"])
        assert "send_email" in d.tool_called
        assert "delete_file" in d.tool_called

    def test_tool_input_contains_dict(self):
        d = DetectionCriteria(tool_input_contains={"send_email": "attacker@evil.com"})
        assert d.tool_input_contains["send_email"] == "attacker@evil.com"
