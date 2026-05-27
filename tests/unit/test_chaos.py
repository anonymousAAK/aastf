"""Tests for the chaos testing module (ChaosMonkey for AI agents)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aastf.chaos import (
    ChaosConfig,
    ChaosEffect,
    ChaosEvent,
    ChaosMonkey,
    ChaosReport,
    ChaosType,
    ResilienceScorer,
)

# ---------------------------------------------------------------------------
# ChaosType enum
# ---------------------------------------------------------------------------


class TestChaosType:
    def test_all_members_exist(self) -> None:
        expected = {
            "TOOL_TIMEOUT",
            "TOOL_UNAVAILABLE",
            "CORRUPT_JSON",
            "WRONG_TYPE",
            "INJECT_LATENCY",
            "MODEL_FAILURE",
            "CONTEXT_OVERFLOW",
            "STATE_CORRUPTION",
        }
        assert {m.value for m in ChaosType} == expected

    def test_str_returns_value(self) -> None:
        assert str(ChaosType.TOOL_TIMEOUT) == "TOOL_TIMEOUT"


# ---------------------------------------------------------------------------
# Each ChaosType produces a valid effect
# ---------------------------------------------------------------------------


class TestChaosEffects:
    @pytest.mark.parametrize("ct", list(ChaosType))
    def test_each_chaos_type_has_valid_effect(self, ct: ChaosType) -> None:
        config = ChaosConfig(chaos_type=ct, target="tool:search")
        monkey = ChaosMonkey(configs=[])
        effect = monkey.apply(config)
        assert isinstance(effect, ChaosEffect)
        assert effect.chaos_type == ct
        assert effect.applied is True
        assert effect.effect_description
        assert effect.simulated_response is not None

    def test_context_overflow_custom_payload(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.CONTEXT_OVERFLOW,
            target="model",
            payload="A" * 50_000,
        )
        monkey = ChaosMonkey(configs=[])
        effect = monkey.apply(config)
        assert effect.simulated_response is not None
        assert effect.simulated_response["overflow_payload_length"] == 50_000


# ---------------------------------------------------------------------------
# Probability filtering
# ---------------------------------------------------------------------------


class TestProbability:
    def test_probability_zero_never_triggers(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_TIMEOUT,
            target="all",
            probability=0.0,
        )
        monkey = ChaosMonkey(configs=[config])
        for step in range(100):
            assert monkey.should_trigger(step, "tool:search") is None

    def test_probability_one_always_triggers(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_TIMEOUT,
            target="all",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        for step in range(50):
            assert monkey.should_trigger(step, "tool:search") is not None


# ---------------------------------------------------------------------------
# Step targeting
# ---------------------------------------------------------------------------


class TestStepTargeting:
    def test_trigger_on_specific_step(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.MODEL_FAILURE,
            target="model",
            probability=1.0,
            trigger_on_step=5,
        )
        monkey = ChaosMonkey(configs=[config])
        assert monkey.should_trigger(3, "model") is None
        assert monkey.should_trigger(5, "model") is config
        assert monkey.should_trigger(7, "model") is None

    def test_trigger_on_step_none_matches_any(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.INJECT_LATENCY,
            target="all",
            probability=1.0,
            trigger_on_step=None,
        )
        monkey = ChaosMonkey(configs=[config])
        assert monkey.should_trigger(0, "tool:x") is not None
        assert monkey.should_trigger(99, "tool:y") is not None


# ---------------------------------------------------------------------------
# Target matching
# ---------------------------------------------------------------------------


class TestTargetMatching:
    def test_exact_match(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_TIMEOUT,
            target="tool:search",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        assert monkey.should_trigger(0, "tool:search") is not None
        assert monkey.should_trigger(0, "tool:other") is None

    def test_all_matches_everything(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_TIMEOUT,
            target="all",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        assert monkey.should_trigger(0, "tool:search") is not None
        assert monkey.should_trigger(0, "model") is not None
        assert monkey.should_trigger(0, "state") is not None

    def test_non_matching_target(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_UNAVAILABLE,
            target="tool:search",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        assert monkey.should_trigger(0, "tool:other") is None
        assert monkey.should_trigger(0, "model") is None


# ---------------------------------------------------------------------------
# ChaosMonkey log tracking
# ---------------------------------------------------------------------------


class TestChaosMonkeyLog:
    def test_inject_records_event(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.CORRUPT_JSON,
            target="all",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        effect = monkey.inject(step=3, target="tool:search")
        assert effect is not None
        log = monkey.get_log()
        assert len(log) == 1
        assert log[0].step == 3
        assert log[0].chaos_type == ChaosType.CORRUPT_JSON
        assert log[0].target == "tool:search"
        assert log[0].triggered is True

    def test_no_trigger_no_log(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_TIMEOUT,
            target="tool:search",
            probability=0.0,
        )
        monkey = ChaosMonkey(configs=[config])
        effect = monkey.inject(step=0, target="tool:search")
        assert effect is None
        assert monkey.get_log() == []

    def test_multiple_injections_tracked(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.INJECT_LATENCY,
            target="all",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        for i in range(5):
            monkey.inject(step=i, target="tool:fetch")
        assert len(monkey.get_log()) == 5

    def test_get_log_returns_copy(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_TIMEOUT,
            target="all",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        monkey.inject(step=0, target="tool:x")
        log1 = monkey.get_log()
        log1.clear()
        assert len(monkey.get_log()) == 1  # original unaffected


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_clears_state(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.MODEL_FAILURE,
            target="all",
            probability=1.0,
        )
        monkey = ChaosMonkey(configs=[config])
        monkey.inject(step=0, target="model")
        monkey.inject(step=1, target="model")
        assert len(monkey.get_log()) == 2
        monkey.reset()
        assert monkey.get_log() == []


# ---------------------------------------------------------------------------
# ResilienceScorer
# ---------------------------------------------------------------------------


def _make_event(
    *,
    step: int = 0,
    chaos_type: ChaosType = ChaosType.TOOL_TIMEOUT,
    target: str = "tool:search",
    triggered: bool = True,
    agent_recovered: bool | None = None,
) -> ChaosEvent:
    return ChaosEvent(
        step=step,
        chaos_type=chaos_type,
        target=target,
        triggered=triggered,
        timestamp=datetime.now(tz=timezone.utc),
        agent_recovered=agent_recovered,
    )


class TestResilienceScorer:
    def test_empty_events(self) -> None:
        report = ResilienceScorer.score([])
        assert report.total_injections == 0
        assert report.resilience_score == 100.0
        assert report.verdict == "NO_CHAOS_INJECTED"

    def test_all_graceful(self) -> None:
        events = [
            _make_event(step=i, agent_recovered=True) for i in range(5)
        ]
        report = ResilienceScorer.score(events)
        assert report.graceful_degradations == 5
        assert report.crashes == 0
        assert report.resilience_score == 100.0
        assert report.verdict == "RESILIENT"

    def test_all_crashes(self) -> None:
        events = [
            _make_event(step=i, agent_recovered=False) for i in range(5)
        ]
        report = ResilienceScorer.score(events)
        assert report.crashes == 5
        assert report.graceful_degradations == 0
        assert report.resilience_score <= 50
        assert report.verdict in {"FRAGILE", "PARTIALLY_RESILIENT"}

    def test_all_crashes_with_vuln_types(self) -> None:
        events = [
            _make_event(
                step=i,
                chaos_type=ChaosType.STATE_CORRUPTION,
                agent_recovered=False,
            )
            for i in range(5)
        ]
        report = ResilienceScorer.score(events)
        assert report.vulnerability_exposures == 5
        assert report.resilience_score == 0.0
        assert report.verdict == "FRAGILE"

    def test_mixed_results(self) -> None:
        events = [
            _make_event(step=0, agent_recovered=True),
            _make_event(step=1, agent_recovered=True),
            _make_event(step=2, agent_recovered=False),
        ]
        report = ResilienceScorer.score(events)
        assert report.graceful_degradations == 2
        assert report.crashes == 1
        assert 0 < report.resilience_score < 100
        assert report.total_injections == 3

    def test_partially_resilient_verdict(self) -> None:
        # 3 graceful, 2 crashes (no vuln types) => raw = 3*1 + 2*(-2) = -1
        # max=5, min=5*(-5)=-25, score = (-1 - -25)/(5 - -25)*100 = 24/30*100 = 80
        events = [
            _make_event(step=i, agent_recovered=True) for i in range(3)
        ] + [
            _make_event(step=i + 3, agent_recovered=False) for i in range(2)
        ]
        report = ResilienceScorer.score(events)
        assert report.verdict in {"RESILIENT", "PARTIALLY_RESILIENT"}

    def test_untriggered_events_ignored(self) -> None:
        events = [
            _make_event(step=0, triggered=False, agent_recovered=True),
            _make_event(step=1, triggered=False, agent_recovered=False),
        ]
        report = ResilienceScorer.score(events)
        assert report.total_injections == 0
        assert report.resilience_score == 100.0

    def test_unknown_recovery_state(self) -> None:
        """Events with agent_recovered=None count as injections but not graceful/crash."""
        events = [_make_event(step=0, agent_recovered=None)]
        report = ResilienceScorer.score(events)
        assert report.total_injections == 1
        assert report.graceful_degradations == 0
        assert report.crashes == 0


# ---------------------------------------------------------------------------
# ChaosReport serialization
# ---------------------------------------------------------------------------


class TestChaosReportSerialization:
    def test_round_trip_json(self) -> None:
        event = _make_event(step=1, agent_recovered=True)
        report = ChaosReport(
            total_injections=1,
            graceful_degradations=1,
            crashes=0,
            vulnerability_exposures=0,
            resilience_score=100.0,
            events=[event],
            verdict="RESILIENT",
        )
        data = report.model_dump(mode="json")
        restored = ChaosReport.model_validate(data)
        assert restored.total_injections == 1
        assert restored.verdict == "RESILIENT"
        assert len(restored.events) == 1
        assert restored.events[0].chaos_type == ChaosType.TOOL_TIMEOUT

    def test_json_string_serialization(self) -> None:
        report = ChaosReport(
            total_injections=0,
            graceful_degradations=0,
            crashes=0,
            vulnerability_exposures=0,
            resilience_score=100.0,
            events=[],
            verdict="NO_CHAOS_INJECTED",
        )
        json_str = report.model_dump_json()
        assert '"verdict":"NO_CHAOS_INJECTED"' in json_str.replace(" ", "")


# ---------------------------------------------------------------------------
# ChaosMonkey seed (reproducibility)
# ---------------------------------------------------------------------------


class TestChaosMonkeySeed:
    def test_seeded_reproducibility(self) -> None:
        config = ChaosConfig(
            chaos_type=ChaosType.TOOL_TIMEOUT,
            target="all",
            probability=0.5,
        )
        results_a: list[bool] = []
        results_b: list[bool] = []

        monkey_a = ChaosMonkey(configs=[config])
        monkey_a.seed(42)
        for step in range(20):
            results_a.append(monkey_a.should_trigger(step, "tool:x") is not None)

        monkey_b = ChaosMonkey(configs=[config])
        monkey_b.seed(42)
        for step in range(20):
            results_b.append(monkey_b.should_trigger(step, "tool:x") is not None)

        assert results_a == results_b
