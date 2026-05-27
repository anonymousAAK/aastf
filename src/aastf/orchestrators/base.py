"""Base classes for multi-turn attack orchestrators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from ..models.scenario import AttackScenario


class Turn(BaseModel):
    """A single turn in a multi-turn attack conversation."""

    index: int
    role: str  # "attacker" or "agent"
    content: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class OrchestrationResult(BaseModel):
    """Result of a multi-turn orchestrated attack."""

    scenario_id: str
    orchestrator: str  # name of orchestrator
    turns: list[Turn] = Field(default_factory=list)
    succeeded: bool = False  # did the attack achieve its objective?
    turns_to_success: int | None = None
    objective: str = ""
    final_verdict: str = "SAFE"


class BaseOrchestrator(ABC):
    """Abstract base for multi-turn attack orchestrators.

    Orchestrators generate a sequence of attack prompts, sending each via
    ``send_fn`` and collecting the agent's response. They do NOT call real
    LLMs — prompts are built from templates and heuristics.
    """

    def __init__(self, max_turns: int = 10, objective: str = "") -> None:
        self.max_turns = max_turns
        self.objective = objective

    @abstractmethod
    async def next_prompt(self, history: list[Turn]) -> str | None:
        """Return the next attack prompt, or None to stop."""

    async def orchestrate(
        self,
        scenario: AttackScenario,
        send_fn: Callable,
    ) -> OrchestrationResult:
        """Run the multi-turn attack loop.

        Parameters
        ----------
        scenario:
            The attack scenario providing context (id, payload, detection).
        send_fn:
            Async callable that sends a prompt string to the agent and returns
            the agent's response string.

        Returns
        -------
        OrchestrationResult with the full conversation and outcome.
        """
        history: list[Turn] = []
        succeeded = False
        turns_to_success: int | None = None

        for turn_idx in range(self.max_turns):
            prompt = await self.next_prompt(history)
            if prompt is None:
                break

            attacker_turn = Turn(
                index=turn_idx * 2,
                role="attacker",
                content=prompt,
            )
            history.append(attacker_turn)

            response = await send_fn(prompt)

            agent_turn = Turn(
                index=turn_idx * 2 + 1,
                role="agent",
                content=response,
            )
            history.append(agent_turn)

            if self._check_success(response, scenario):
                succeeded = True
                turns_to_success = turn_idx + 1
                break

        return OrchestrationResult(
            scenario_id=scenario.id,
            orchestrator=self.__class__.__name__,
            turns=history,
            succeeded=succeeded,
            turns_to_success=turns_to_success,
            objective=self.objective,
            final_verdict="VULNERABLE" if succeeded else "SAFE",
        )

    def _check_success(self, response: str, scenario: AttackScenario) -> bool:
        """Check whether the agent's response indicates the attack succeeded."""
        detection = scenario.detection
        response_lower = response.lower()

        # Check output_contains — if any marker appears, the attack succeeded
        return any(marker.lower() in response_lower for marker in detection.output_contains)
