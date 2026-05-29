"""Tests for the cost-aware scheduler module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aastf.cost_scheduler import (
    BudgetExceededError,
    CostAwareScheduler,
    CostConfig,
    CostTracker,
    ResponseCache,
    TestPrioritizer,
    TokenUsage,
)
from aastf.models.result import TestResult, Verdict
from aastf.models.scenario import ASICategory, AttackScenario, DetectionCriteria, Severity
from aastf.models.trace import AgentTrace

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _usage(prompt: int = 100, completion: int = 50, cost: float = 0.0) -> TokenUsage:
    return TokenUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
        estimated_cost_usd=cost,
    )


def _result(
    scenario_id: str = "ASI01-001",
    verdict: Verdict = Verdict.SAFE,
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name="test",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        verdict=verdict,
        trace=AgentTrace(scenario_id=scenario_id, adapter="test"),
    )


def _scenario(
    sid: str = "ASI01-001",
    severity: Severity = Severity.HIGH,
) -> AttackScenario:
    return AttackScenario(
        id=sid,
        name=f"Scenario {sid}",
        category=ASICategory(sid[:5]),
        severity=severity,
        description="test",
        attack_vector="test",
        inject_into="user_message",
        payload="test",
        detection=DetectionCriteria(output_contains=["bad"]),
        expected_behavior="refuse",
        remediation="fix it",
    )


# ---------------------------------------------------------------------------
# TokenUsage model
# ---------------------------------------------------------------------------


class TestTokenUsage:
    def test_defaults(self) -> None:
        u = TokenUsage()
        assert u.prompt_tokens == 0
        assert u.completion_tokens == 0
        assert u.total_tokens == 0
        assert u.estimated_cost_usd == 0.0

    def test_custom_values(self) -> None:
        u = _usage(200, 100, 0.05)
        assert u.prompt_tokens == 200
        assert u.completion_tokens == 100
        assert u.total_tokens == 300
        assert u.estimated_cost_usd == 0.05

    def test_serialisation_roundtrip(self) -> None:
        u = _usage(10, 20, 0.001)
        data = u.model_dump()
        u2 = TokenUsage(**data)
        assert u == u2


# ---------------------------------------------------------------------------
# CostConfig model
# ---------------------------------------------------------------------------


class TestCostConfig:
    def test_defaults(self) -> None:
        c = CostConfig()
        assert c.budget_usd == 50.0
        assert c.warn_at_percent == 80.0
        assert c.enable_caching is True

    def test_custom_config(self) -> None:
        c = CostConfig(budget_usd=10.0, cost_per_1k_prompt=0.05, cost_per_1k_completion=0.10)
        assert c.budget_usd == 10.0
        assert c.cost_per_1k_prompt == 0.05


# ---------------------------------------------------------------------------
# CostTracker
# ---------------------------------------------------------------------------


class TestCostTracker:
    def test_empty_tracker(self) -> None:
        t = CostTracker(CostConfig())
        assert t.total_spent() == 0.0
        assert t.remaining_budget() == 50.0
        assert t.is_over_budget() is False
        assert t.should_warn() is False

    def test_record_and_total(self) -> None:
        t = CostTracker(CostConfig(budget_usd=100.0))
        t.record("ASI01-001", _usage(cost=10.0))
        t.record("ASI01-001", _usage(cost=5.0))
        assert t.total_spent() == 15.0
        assert t.remaining_budget() == 85.0

    def test_over_budget_raises(self) -> None:
        t = CostTracker(CostConfig(budget_usd=1.0))
        with pytest.raises(BudgetExceededError, match="exceeded"):
            t.record("ASI01-001", _usage(cost=2.0))

    def test_should_warn_at_threshold(self) -> None:
        t = CostTracker(CostConfig(budget_usd=100.0, warn_at_percent=80.0))
        t.record("ASI01-001", _usage(cost=79.0))
        assert t.should_warn() is False
        t.record("ASI01-001", _usage(cost=1.0))
        assert t.should_warn() is True

    def test_should_warn_exact_boundary(self) -> None:
        t = CostTracker(CostConfig(budget_usd=10.0, warn_at_percent=50.0))
        t.record("ASI01-001", _usage(cost=5.0))
        assert t.should_warn() is True

    def test_remaining_never_negative(self) -> None:
        cfg = CostConfig(budget_usd=1.0)
        t = CostTracker(cfg)
        # Record under budget first
        t.record("ASI01-001", _usage(cost=0.5))
        # Force over-budget without raising by manipulating internals
        t._records["ASI01-001"].append(_usage(cost=2.0))
        assert t.remaining_budget() == 0.0

    def test_summary_structure(self) -> None:
        t = CostTracker(CostConfig(budget_usd=100.0))
        t.record("ASI01-001", _usage(100, 50, 0.01))
        t.record("ASI02-001", _usage(200, 100, 0.02))
        s = t.summary()
        assert "total_spent_usd" in s
        assert "remaining_usd" in s
        assert "budget_usd" in s
        assert "over_budget" in s
        assert "scenarios" in s
        assert "ASI01-001" in s["scenarios"]
        assert s["scenarios"]["ASI01-001"]["runs"] == 1

    def test_summary_multi_run(self) -> None:
        t = CostTracker(CostConfig(budget_usd=100.0))
        t.record("ASI01-001", _usage(cost=0.01))
        t.record("ASI01-001", _usage(cost=0.02))
        s = t.summary()
        assert s["scenarios"]["ASI01-001"]["runs"] == 2
        assert s["scenarios"]["ASI01-001"]["total_cost_usd"] == 0.03

    def test_should_warn_zero_budget(self) -> None:
        t = CostTracker(CostConfig(budget_usd=0.0))
        assert t.should_warn() is True


# ---------------------------------------------------------------------------
# TestPrioritizer
# ---------------------------------------------------------------------------


class TestTestPrioritizer:
    def test_unseen_scenario_score(self) -> None:
        p = TestPrioritizer()
        assert p.signal_score("ASI01-001") == 0.5

    def test_all_safe_score(self) -> None:
        history = [_result("ASI01-001", Verdict.SAFE) for _ in range(5)]
        p = TestPrioritizer(history)
        assert p.signal_score("ASI01-001") == 0.0

    def test_all_vulnerable_score(self) -> None:
        history = [_result("ASI01-001", Verdict.VULNERABLE) for _ in range(4)]
        p = TestPrioritizer(history)
        assert p.signal_score("ASI01-001") == 1.0

    def test_mixed_score(self) -> None:
        history = [
            _result("ASI01-001", Verdict.VULNERABLE),
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-001", Verdict.VULNERABLE),
            _result("ASI01-001", Verdict.SAFE),
        ]
        p = TestPrioritizer(history)
        assert p.signal_score("ASI01-001") == 0.5

    def test_prioritize_severity_first(self) -> None:
        s_low = _scenario("ASI01-001", Severity.LOW)
        s_crit = _scenario("ASI08-001", Severity.CRITICAL)
        p = TestPrioritizer()
        result = p.prioritize([s_low, s_crit])
        assert result[0].id == "ASI08-001"

    def test_prioritize_signal_within_severity(self) -> None:
        s1 = _scenario("ASI01-001", Severity.HIGH)
        s2 = _scenario("ASI01-002", Severity.HIGH)
        history = [
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-002", Verdict.VULNERABLE),
        ]
        p = TestPrioritizer(history)
        result = p.prioritize([s1, s2])
        assert result[0].id == "ASI01-002"

    def test_is_redundant_true(self) -> None:
        results = [_result("ASI01-001", Verdict.SAFE) for _ in range(3)]
        p = TestPrioritizer()
        assert p.is_redundant("ASI01-001", results) is True

    def test_is_redundant_false_mixed(self) -> None:
        results = [
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-001", Verdict.VULNERABLE),
        ]
        p = TestPrioritizer()
        assert p.is_redundant("ASI01-001", results) is False

    def test_is_redundant_false_too_few(self) -> None:
        results = [_result("ASI01-001", Verdict.SAFE) for _ in range(2)]
        p = TestPrioritizer()
        assert p.is_redundant("ASI01-001", results) is False

    def test_is_redundant_custom_window(self) -> None:
        results = [_result("ASI01-001", Verdict.SAFE) for _ in range(5)]
        p = TestPrioritizer()
        assert p.is_redundant("ASI01-001", results, window=5) is True

    def test_is_redundant_ignores_other_scenarios(self) -> None:
        results = [
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI02-001", Verdict.VULNERABLE),
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-001", Verdict.SAFE),
        ]
        p = TestPrioritizer()
        assert p.is_redundant("ASI01-001", results) is True


# ---------------------------------------------------------------------------
# ResponseCache
# ---------------------------------------------------------------------------


class TestResponseCache:
    def test_cache_key_deterministic(self) -> None:
        k1 = ResponseCache.cache_key("ASI01-001", "hello")
        k2 = ResponseCache.cache_key("ASI01-001", "hello")
        assert k1 == k2

    def test_cache_key_differs_on_scenario(self) -> None:
        k1 = ResponseCache.cache_key("ASI01-001", "hello")
        k2 = ResponseCache.cache_key("ASI01-002", "hello")
        assert k1 != k2

    def test_cache_key_differs_on_prompt(self) -> None:
        k1 = ResponseCache.cache_key("ASI01-001", "hello")
        k2 = ResponseCache.cache_key("ASI01-001", "world")
        assert k1 != k2

    def test_miss_returns_none(self, tmp_path: Path) -> None:
        c = ResponseCache(tmp_path / "cache")
        assert c.get("nonexistent") is None

    def test_put_and_get(self, tmp_path: Path) -> None:
        c = ResponseCache(tmp_path / "cache")
        key = ResponseCache.cache_key("ASI01-001", "prompt")
        c.put(key, "response text")
        assert c.get(key) == "response text"

    def test_hit_rate_empty(self, tmp_path: Path) -> None:
        c = ResponseCache(tmp_path / "cache")
        assert c.hit_rate() == 0.0

    def test_hit_rate_all_misses(self, tmp_path: Path) -> None:
        c = ResponseCache(tmp_path / "cache")
        c.get("a")
        c.get("b")
        assert c.hit_rate() == 0.0

    def test_hit_rate_mixed(self, tmp_path: Path) -> None:
        c = ResponseCache(tmp_path / "cache")
        key = ResponseCache.cache_key("ASI01-001", "p")
        c.put(key, "r")
        c.get(key)  # hit
        c.get("miss")  # miss
        assert c.hit_rate() == 0.5

    def test_put_creates_directory(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c"
        c = ResponseCache(deep)
        c.put("k", "v")
        assert deep.exists()

    def test_cache_file_is_valid_json(self, tmp_path: Path) -> None:
        c = ResponseCache(tmp_path / "cache")
        key = "testkey123"
        c.put(key, "hello")
        path = tmp_path / "cache" / f"{key}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["response"] == "hello"
        assert "cached_at" in data


# ---------------------------------------------------------------------------
# CostAwareScheduler
# ---------------------------------------------------------------------------


class TestCostAwareScheduler:
    def test_estimate_cost_empty(self) -> None:
        s = CostAwareScheduler(CostConfig())
        assert s.estimate_cost([]) == 0.0

    def test_estimate_cost_scales_with_count(self) -> None:
        cfg = CostConfig(cost_per_1k_prompt=0.01, cost_per_1k_completion=0.03)
        s = CostAwareScheduler(cfg)
        one = s.estimate_cost([_scenario()])
        two = s.estimate_cost([_scenario(), _scenario("ASI02-001")])
        assert two == pytest.approx(one * 2)

    def test_schedule_empty(self) -> None:
        s = CostAwareScheduler(CostConfig())
        assert s.schedule([]) == []

    def test_schedule_prioritises(self) -> None:
        cfg = CostConfig(budget_usd=1000.0)
        s = CostAwareScheduler(cfg)
        low = _scenario("ASI01-001", Severity.LOW)
        high = _scenario("ASI01-002", Severity.HIGH)
        result = s.schedule([low, high])
        assert result[0].id == "ASI01-002"

    def test_schedule_removes_redundant(self) -> None:
        cfg = CostConfig(budget_usd=1000.0)
        s = CostAwareScheduler(cfg)
        sc = _scenario("ASI01-001")
        history = [_result("ASI01-001", Verdict.SAFE) for _ in range(3)]
        result = s.schedule([sc], history)
        assert len(result) == 0

    def test_schedule_keeps_non_redundant(self) -> None:
        cfg = CostConfig(budget_usd=1000.0)
        s = CostAwareScheduler(cfg)
        sc = _scenario("ASI01-001")
        history = [
            _result("ASI01-001", Verdict.SAFE),
            _result("ASI01-001", Verdict.VULNERABLE),
            _result("ASI01-001", Verdict.SAFE),
        ]
        result = s.schedule([sc], history)
        assert len(result) == 1

    def test_schedule_caps_to_budget(self) -> None:
        # Tiny budget → can only afford a few scenarios
        cfg = CostConfig(
            budget_usd=0.03,
            cost_per_1k_prompt=0.01,
            cost_per_1k_completion=0.03,
        )
        s = CostAwareScheduler(cfg)
        scenarios = [_scenario(f"ASI01-{i:03d}") for i in range(1, 11)]
        result = s.schedule(scenarios)
        assert len(result) < len(scenarios)

    def test_schedule_returns_empty_when_over_budget(self) -> None:
        cfg = CostConfig(budget_usd=1.0)
        s = CostAwareScheduler(cfg)
        # Blow the budget
        s.tracker._records["x"].append(_usage(cost=2.0))
        result = s.schedule([_scenario()])
        assert result == []

    def test_should_continue_true_initially(self) -> None:
        s = CostAwareScheduler(CostConfig())
        assert s.should_continue() is True

    def test_should_continue_false_after_overspend(self) -> None:
        cfg = CostConfig(budget_usd=1.0)
        s = CostAwareScheduler(cfg)
        s.tracker._records["x"].append(_usage(cost=2.0))
        assert s.should_continue() is False

    def test_cache_disabled(self) -> None:
        cfg = CostConfig(enable_caching=False)
        s = CostAwareScheduler(cfg)
        assert s.cache is None

    def test_cache_enabled(self, tmp_path: Path) -> None:
        cfg = CostConfig(enable_caching=True)
        s = CostAwareScheduler(cfg, cache_dir=tmp_path / "c")
        assert s.cache is not None

    def test_tracker_accessible(self) -> None:
        s = CostAwareScheduler(CostConfig())
        assert isinstance(s.tracker, CostTracker)
