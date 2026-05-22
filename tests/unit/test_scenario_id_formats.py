"""Tests for scenario ID format validation."""
import pytest
from pydantic import ValidationError

from aastf.models.scenario import (
    ASICategory,
    AttackScenario,
    DetectionCriteria,
    InjectionPoint,
    Severity,
)


def _minimal_scenario(id_val):
    return AttackScenario(
        id=id_val,
        name="Test",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        description="test",
        attack_vector="test",
        inject_into=InjectionPoint.USER_MESSAGE,
        payload="test",
        detection=DetectionCriteria(),
        expected_behavior="test",
        remediation="test",
    )


@pytest.mark.parametrize("id_val", [
    "ASI01-001", "ASI10-999", "MCP01-001", "MCP06-008", "CVE01-001", "CVE01-008",
])
def test_valid_scenario_ids(id_val):
    s = _minimal_scenario(id_val)
    assert s.id == id_val


@pytest.mark.parametrize("id_val", [
    "INVALID", "ASI1-001", "MCP1-001", "asi01-001", "ASI01001", "XXX01-001",
])
def test_invalid_scenario_ids(id_val):
    with pytest.raises(ValidationError):
        _minimal_scenario(id_val)
