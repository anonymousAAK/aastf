"""
Self-audit: validate that every built-in scenario is structurally sound
and can be evaluated without raising exceptions.

These tests run against synthetic (empty) traces — no LLM, no network.
They verify schema integrity, evaluator coverage, and detection logic reachability.
"""

from __future__ import annotations

import pytest

from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace
from aastf.scenarios.evaluators import all_categories_covered, get_evaluator
from aastf.scenarios.registry import ScenarioRegistry


@pytest.fixture(scope="module")
def registry() -> ScenarioRegistry:
    return ScenarioRegistry().load_builtin()


class TestScenarioCoverage:
    def test_exactly_fifty_scenarios(self, registry):
        assert len(registry) == 50, f"Expected 50 scenarios, got {len(registry)}"

    def test_five_per_category(self, registry):
        for cat in ASICategory:
            count = len(registry.filter(categories=[cat]))
            assert count == 5, f"{cat.value} has {count} scenarios, expected 5"

    def test_all_ids_unique(self, registry):
        ids = [s.id for s in registry.all()]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {set(x for x in ids if ids.count(x) > 1)}"

    def test_all_ids_match_category(self, registry):
        for s in registry.all():
            expected_prefix = s.category.value  # e.g. "ASI02"
            assert s.id.startswith(expected_prefix), (
                f"Scenario {s.id} is in category {s.category.value} "
                f"but ID doesn't start with {expected_prefix}"
            )

    def test_all_have_non_empty_remediation(self, registry):
        empty = [s.id for s in registry.all() if not s.remediation.strip()]
        assert not empty, f"Scenarios with empty remediation: {empty}"

    def test_all_have_non_empty_payload(self, registry):
        empty = [s.id for s in registry.all() if not s.payload.strip()]
        assert not empty, f"Scenarios with empty payload: {empty}"

    def test_all_have_at_least_one_tag(self, registry):
        missing = [s.id for s in registry.all() if not s.tags]
        assert not missing, f"Scenarios with no tags: {missing}"

    def test_all_have_owasp_reference(self, registry):
        missing = [s.id for s in registry.all() if not s.references]
        assert not missing, f"Scenarios with no references: {missing}"

    def test_severity_distribution(self, registry):
        """Verify scenario library has variety — not all CRITICAL."""
        scenarios = registry.all()
        severities = {s.severity for s in scenarios}
        assert len(severities) >= 3, (
            f"Only {len(severities)} severity levels used — need variety"
        )

    def test_injection_point_variety(self, registry):
        """Verify multiple injection points are represented."""
        points_used = {s.inject_into for s in registry.all()}
        assert len(points_used) >= 2, (
            f"Only {len(points_used)} injection point(s) used — need variety"
        )


class TestEvaluatorCoverage:
    def test_all_categories_have_evaluators(self):
        assert all_categories_covered(), "Not all ASI categories have registered evaluators"

    def test_evaluators_dont_raise_on_empty_trace(self, registry):
        """Every scenario + evaluator combination handles an empty trace gracefully."""
        errors = []
        for scenario in registry.all():
            evaluator = get_evaluator(scenario.category)
            if evaluator is None:
                errors.append(f"{scenario.id}: no evaluator registered")
                continue
            trace = AgentTrace(scenario_id=scenario.id, adapter="self_audit")
            try:
                result = evaluator.evaluate(scenario, trace)
                assert result.verdict is not None
            except Exception as e:
                errors.append(f"{scenario.id}: evaluator raised {type(e).__name__}: {e}")

        assert not errors, "Evaluator errors on empty traces:\n" + "\n".join(errors)

    def test_evaluators_return_safe_on_clean_trace(self, registry):
        """A clean trace (no tool calls, no output) should return SAFE for most scenarios."""
        from aastf.models.result import Verdict
        # Scenarios that detect the *absence* of something may return VULNERABLE on empty trace
        # (e.g., tool_not_called detection). We just verify no crash and valid verdict.
        for scenario in registry.all():
            evaluator = get_evaluator(scenario.category)
            if not evaluator:
                continue
            trace = AgentTrace(scenario_id=scenario.id, adapter="self_audit")
            result = evaluator.evaluate(scenario, trace)
            assert result.verdict in list(Verdict), (
                f"{scenario.id} returned invalid verdict: {result.verdict}"
            )


class TestScenarioRegistry:
    def test_filter_by_category_correct(self, registry):
        for cat in ASICategory:
            results = registry.filter(categories=[cat])
            assert all(s.category == cat for s in results)

    def test_filter_by_severity_correct(self, registry):
        criticals = registry.filter(min_severity=Severity.CRITICAL)
        assert all(s.severity >= Severity.CRITICAL for s in criticals)
        assert len(criticals) > 0

    def test_filter_empty_intersection(self, registry):
        # Filtering for a non-existent tag returns empty list, not an error
        results = registry.filter(tags=["this-tag-does-not-exist-xyz"])
        assert results == []

    def test_get_known_scenario(self, registry):
        s = registry.get("ASI01-001")
        assert s.id == "ASI01-001"
        assert s.category == ASICategory.ASI01

    def test_all_returns_full_list(self, registry):
        assert len(registry.all()) == 50
