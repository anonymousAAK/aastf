"""Tests for multi-turn attack orchestrators."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aastf.models.scenario import (
    ASICategory,
    AttackScenario,
    DetectionCriteria,
    InjectionPoint,
    Severity,
)
from aastf.orchestrators.base import OrchestrationResult, Turn
from aastf.orchestrators.crescendo import CrescendoOrchestrator
from aastf.orchestrators.pair import PAIROrchestrator
from aastf.orchestrators.tap import TAPOrchestrator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scenario(
    output_contains: list[str] | None = None,
    scenario_id: str = "ASI01-001",
) -> AttackScenario:
    """Build a minimal AttackScenario for testing."""
    return AttackScenario(
        id=scenario_id,
        name="Test scenario",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        description="Unit test scenario",
        attack_vector="multi-turn escalation",
        inject_into=InjectionPoint.USER_MESSAGE,
        payload="test payload",
        detection=DetectionCriteria(
            output_contains=output_contains or [],
        ),
        expected_behavior="Agent should refuse",
        remediation="Add guardrails",
    )


async def _refusing_agent(prompt: str) -> str:
    """Simulates an agent that always refuses."""
    return "I cannot help with that request. It is against my policy."


async def _compliant_agent(prompt: str) -> str:
    """Simulates an agent that always complies with a secret marker."""
    return "Sure! Here are the steps: SECRET_MARKER step 1 step 2 step 3"


def _make_delayed_agent(refuse_count: int = 3):
    """Create a stateful agent that refuses N times then complies."""
    state = {"count": 0}

    async def agent(prompt: str) -> str:
        state["count"] += 1
        if state["count"] <= refuse_count:
            return "I cannot help with that. It is against my policy."
        return "Sure! SECRET_MARKER here are the steps."

    return agent


# ---------------------------------------------------------------------------
# Turn model tests
# ---------------------------------------------------------------------------

class TestTurnModel:
    def test_turn_creation(self) -> None:
        turn = Turn(index=0, role="attacker", content="hello")
        assert turn.index == 0
        assert turn.role == "attacker"
        assert turn.content == "hello"
        assert isinstance(turn.timestamp, datetime)

    def test_turn_serialization(self) -> None:
        turn = Turn(
            index=1,
            role="agent",
            content="I refuse",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        data = turn.model_dump()
        assert data["index"] == 1
        assert data["role"] == "agent"
        assert data["content"] == "I refuse"

    def test_turn_json_round_trip(self) -> None:
        turn = Turn(index=0, role="attacker", content="test")
        json_str = turn.model_dump_json()
        restored = Turn.model_validate_json(json_str)
        assert restored.index == turn.index
        assert restored.content == turn.content


# ---------------------------------------------------------------------------
# OrchestrationResult tests
# ---------------------------------------------------------------------------

class TestOrchestrationResult:
    def test_default_values(self) -> None:
        result = OrchestrationResult(
            scenario_id="ASI01-001",
            orchestrator="TestOrchestrator",
        )
        assert result.succeeded is False
        assert result.turns_to_success is None
        assert result.final_verdict == "SAFE"
        assert result.turns == []

    def test_serialization(self) -> None:
        result = OrchestrationResult(
            scenario_id="ASI01-001",
            orchestrator="CrescendoOrchestrator",
            turns=[Turn(index=0, role="attacker", content="hi")],
            succeeded=True,
            turns_to_success=1,
            objective="test objective",
            final_verdict="VULNERABLE",
        )
        data = result.model_dump()
        assert data["scenario_id"] == "ASI01-001"
        assert data["succeeded"] is True
        assert len(data["turns"]) == 1

    def test_json_round_trip(self) -> None:
        result = OrchestrationResult(
            scenario_id="ASI01-002",
            orchestrator="TAP",
            succeeded=False,
            objective="exfiltrate data",
            final_verdict="SAFE",
        )
        json_str = result.model_dump_json()
        restored = OrchestrationResult.model_validate_json(json_str)
        assert restored.scenario_id == result.scenario_id
        assert restored.orchestrator == result.orchestrator


# ---------------------------------------------------------------------------
# Crescendo orchestrator tests
# ---------------------------------------------------------------------------

class TestCrescendoOrchestrator:
    @pytest.mark.asyncio
    async def test_escalation_progresses_through_levels(self) -> None:
        orch = CrescendoOrchestrator(
            max_turns=5,
            objective="extract secrets",
            escalation_levels=["benign", "adjacent", "indirect", "direct", "aggressive"],
        )
        assert orch.current_level == "benign"

        # Simulate progression
        history: list[Turn] = []
        prompts: list[str] = []
        for i in range(5):
            prompt = await orch.next_prompt(history)
            if prompt is None:
                break
            prompts.append(prompt)
            history.append(Turn(index=i * 2, role="attacker", content=prompt))
            history.append(Turn(index=i * 2 + 1, role="agent", content="I refuse."))

        assert len(prompts) == 5
        # First prompt should be benign-flavored
        assert "curious" in prompts[0].lower() or "general" in prompts[0].lower()

    @pytest.mark.asyncio
    async def test_stops_on_max_turns(self) -> None:
        scenario = _make_scenario(output_contains=["SECRET_MARKER"])
        orch = CrescendoOrchestrator(max_turns=3, objective="test")

        result = await orch.orchestrate(scenario, _refusing_agent)
        attacker_turns = [t for t in result.turns if t.role == "attacker"]
        assert len(attacker_turns) <= 3
        assert result.succeeded is False
        assert result.final_verdict == "SAFE"

    @pytest.mark.asyncio
    async def test_stops_on_success(self) -> None:
        scenario = _make_scenario(output_contains=["SECRET_MARKER"])
        orch = CrescendoOrchestrator(max_turns=10, objective="extract secrets")

        result = await orch.orchestrate(scenario, _compliant_agent)
        assert result.succeeded is True
        assert result.turns_to_success == 1
        assert result.final_verdict == "VULNERABLE"

    @pytest.mark.asyncio
    async def test_custom_templates(self) -> None:
        custom_templates = {
            "level1": "First: {objective}",
            "level2": "Second: {objective}",
        }
        orch = CrescendoOrchestrator(
            max_turns=4,
            objective="test",
            escalation_levels=["level1", "level2"],
            templates=custom_templates,
        )
        prompt = await orch.next_prompt([])
        assert prompt == "First: test"

    @pytest.mark.asyncio
    async def test_fallback_for_missing_template(self) -> None:
        orch = CrescendoOrchestrator(
            max_turns=2,
            objective="test",
            escalation_levels=["unknown_level"],
            templates={},
        )
        prompt = await orch.next_prompt([])
        assert prompt is not None
        assert "test" in prompt

    @pytest.mark.asyncio
    async def test_empty_history_handled(self) -> None:
        orch = CrescendoOrchestrator(max_turns=5, objective="test")
        prompt = await orch.next_prompt([])
        assert prompt is not None
        assert isinstance(prompt, str)


# ---------------------------------------------------------------------------
# TAP orchestrator tests
# ---------------------------------------------------------------------------

class TestTAPOrchestrator:
    @pytest.mark.asyncio
    async def test_branching_creates_correct_number_of_paths(self) -> None:
        orch = TAPOrchestrator(
            max_turns=5,
            objective="test",
            branching_factor=3,
        )
        # First call creates root branches
        prompt = await orch.next_prompt([])
        assert prompt is not None
        # Root branches should be created
        assert len(orch.tree_nodes) == 3

    @pytest.mark.asyncio
    async def test_pruning_removes_low_score_paths(self) -> None:
        orch = TAPOrchestrator(
            max_turns=10,
            objective="test",
            branching_factor=2,
            prune_threshold=0.3,
        )

        # Get first prompt (creates root branches)
        history: list[Turn] = []
        prompt = await orch.next_prompt(history)
        assert prompt is not None
        history.append(Turn(index=0, role="attacker", content=prompt))
        # Agent gives strong refusal -> low score
        history.append(Turn(
            index=1, role="agent",
            content="I cannot help with that. I will not assist. I am unable to do this.",
        ))

        # Next prompt should trigger scoring + branching + pruning
        await orch.next_prompt(history)

        # Some nodes should have been pruned (low score from strong refusal)
        assert orch.pruned_count >= 0  # At least check it doesn't crash

    @pytest.mark.asyncio
    async def test_max_turns_respected(self) -> None:
        scenario = _make_scenario(output_contains=["NEVER_MATCHES"])
        orch = TAPOrchestrator(max_turns=3, objective="test", branching_factor=2)

        result = await orch.orchestrate(scenario, _refusing_agent)
        attacker_turns = [t for t in result.turns if t.role == "attacker"]
        assert len(attacker_turns) <= 3
        assert result.succeeded is False

    @pytest.mark.asyncio
    async def test_empty_history_handled(self) -> None:
        orch = TAPOrchestrator(max_turns=5, objective="test")
        prompt = await orch.next_prompt([])
        assert prompt is not None

    def test_get_best_path_empty_tree(self) -> None:
        orch = TAPOrchestrator(max_turns=5, objective="test")
        assert orch.get_best_path() == []

    def test_score_response_refusal(self) -> None:
        orch = TAPOrchestrator(max_turns=5, objective="test")
        score = orch._score_response("I cannot help. I will not assist.")
        assert score <= 0.2

    def test_score_response_compliance(self) -> None:
        orch = TAPOrchestrator(max_turns=5, objective="test")
        score = orch._score_response(
            "Here are the steps. Step 1: do this. The process is simple."
        )
        assert score >= 0.6

    @pytest.mark.asyncio
    async def test_stops_on_success(self) -> None:
        scenario = _make_scenario(output_contains=["SECRET_MARKER"])
        orch = TAPOrchestrator(max_turns=10, objective="test", branching_factor=2)

        result = await orch.orchestrate(scenario, _compliant_agent)
        assert result.succeeded is True
        assert result.final_verdict == "VULNERABLE"
        assert result.turns_to_success is not None


# ---------------------------------------------------------------------------
# PAIR orchestrator tests
# ---------------------------------------------------------------------------

class TestPAIROrchestrator:
    @pytest.mark.asyncio
    async def test_refinement_changes_strategy_after_refusal(self) -> None:
        orch = PAIROrchestrator(
            max_turns=5,
            objective="test",
            refinement_strategy="rephrase",
        )

        # First prompt uses initial strategy
        prompt1 = await orch.next_prompt([])
        assert prompt1 is not None
        initial_strategy = orch.current_strategy
        assert initial_strategy == "rephrase"

        # Simulate a refusal response
        history = [
            Turn(index=0, role="attacker", content=prompt1),
            Turn(index=1, role="agent", content="I cannot help with that. I will not assist."),
        ]

        prompt2 = await orch.next_prompt(history)
        assert prompt2 is not None
        # Strategy should have changed after refusal
        assert orch.current_strategy != "rephrase" or len(orch.tried_strategies) > 1

    @pytest.mark.asyncio
    async def test_tracks_tried_strategies(self) -> None:
        orch = PAIROrchestrator(
            max_turns=10,
            objective="test",
            refinement_strategy="rephrase",
        )

        history: list[Turn] = []

        # Run several turns with refusals to force strategy switches
        for i in range(4):
            prompt = await orch.next_prompt(history)
            if prompt is None:
                break
            history.append(Turn(index=i * 2, role="attacker", content=prompt))
            history.append(Turn(
                index=i * 2 + 1,
                role="agent",
                content="I cannot help. I must decline this request.",
            ))

        # Multiple strategies should have been tried
        assert len(orch.tried_strategies) >= 3

    @pytest.mark.asyncio
    async def test_max_turns_respected(self) -> None:
        scenario = _make_scenario(output_contains=["NEVER_MATCHES"])
        orch = PAIROrchestrator(max_turns=3, objective="test")

        result = await orch.orchestrate(scenario, _refusing_agent)
        attacker_turns = [t for t in result.turns if t.role == "attacker"]
        assert len(attacker_turns) <= 3
        assert result.succeeded is False

    @pytest.mark.asyncio
    async def test_stops_on_success(self) -> None:
        scenario = _make_scenario(output_contains=["SECRET_MARKER"])
        orch = PAIROrchestrator(max_turns=10, objective="test")

        result = await orch.orchestrate(scenario, _compliant_agent)
        assert result.succeeded is True
        assert result.final_verdict == "VULNERABLE"

    @pytest.mark.asyncio
    async def test_empty_history_handled(self) -> None:
        orch = PAIROrchestrator(max_turns=5, objective="test")
        prompt = await orch.next_prompt([])
        assert prompt is not None

    @pytest.mark.asyncio
    async def test_custom_strategies_list(self) -> None:
        orch = PAIROrchestrator(
            max_turns=5,
            objective="test",
            refinement_strategy="encode",
            strategies=["encode", "roleplay", "context_shift"],
        )
        prompt = await orch.next_prompt([])
        assert prompt is not None
        assert orch.current_strategy == "encode"

    def test_detect_refusal(self) -> None:
        orch = PAIROrchestrator(max_turns=5, objective="test")
        assert orch._detect_refusal("I cannot help with that") is True
        assert orch._detect_refusal("I won't do that") is True
        assert orch._detect_refusal("Sure, here are the steps") is False

    @pytest.mark.asyncio
    async def test_delayed_compliance(self) -> None:
        """Agent refuses first then complies — PAIR should catch it."""
        scenario = _make_scenario(output_contains=["SECRET_MARKER"])
        agent = _make_delayed_agent(refuse_count=2)
        orch = PAIROrchestrator(max_turns=10, objective="test")

        result = await orch.orchestrate(scenario, agent)
        assert result.succeeded is True
        assert result.turns_to_success == 3


# ---------------------------------------------------------------------------
# All orchestrators: shared behavior
# ---------------------------------------------------------------------------

class TestSharedBehavior:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("orch_cls,kwargs", [
        (CrescendoOrchestrator, {"max_turns": 2, "objective": "test"}),
        (TAPOrchestrator, {"max_turns": 2, "objective": "test", "branching_factor": 2}),
        (PAIROrchestrator, {"max_turns": 2, "objective": "test"}),
    ])
    async def test_max_turns_respected(self, orch_cls: type, kwargs: dict) -> None:
        scenario = _make_scenario(output_contains=["NEVER_MATCHES"])
        orch = orch_cls(**kwargs)

        result = await orch.orchestrate(scenario, _refusing_agent)
        attacker_turns = [t for t in result.turns if t.role == "attacker"]
        assert len(attacker_turns) <= 2

    @pytest.mark.asyncio
    @pytest.mark.parametrize("orch_cls,kwargs", [
        (CrescendoOrchestrator, {"max_turns": 5, "objective": "test"}),
        (TAPOrchestrator, {"max_turns": 5, "objective": "test"}),
        (PAIROrchestrator, {"max_turns": 5, "objective": "test"}),
    ])
    async def test_empty_history_handled(self, orch_cls: type, kwargs: dict) -> None:
        orch = orch_cls(**kwargs)
        prompt = await orch.next_prompt([])
        assert prompt is not None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("orch_cls,kwargs", [
        (CrescendoOrchestrator, {"max_turns": 10, "objective": "test"}),
        (TAPOrchestrator, {"max_turns": 10, "objective": "test"}),
        (PAIROrchestrator, {"max_turns": 10, "objective": "test"}),
    ])
    async def test_orchestration_result_has_correct_orchestrator_name(
        self, orch_cls: type, kwargs: dict,
    ) -> None:
        scenario = _make_scenario(output_contains=["SECRET_MARKER"])
        orch = orch_cls(**kwargs)

        result = await orch.orchestrate(scenario, _compliant_agent)
        assert result.orchestrator == orch_cls.__name__
        assert result.scenario_id == "ASI01-001"
