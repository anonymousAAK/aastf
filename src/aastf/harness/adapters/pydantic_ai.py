"""
PydanticAI adapter — instruments a PydanticAI Agent for AASTF scenario runs.

PydanticAI uses Agent.run() / Agent.run_sync() with @agent.tool decorators.
We intercept at the tool call level via the @instrument decorator.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import anyio

from ...exceptions import AdapterNotFoundError
from ...models.scenario import AttackScenario, InjectionPoint
from ...models.trace import AgentTrace
from ..collector import TraceCollector
from .generic import instrument, set_collector

if TYPE_CHECKING:
    from ...sandbox.server import SandboxServer

try:
    import pydantic_ai  # noqa: F401
    HAS_PYDANTIC_AI = True
except ImportError:
    HAS_PYDANTIC_AI = False


class PydanticAIHarness:
    """
    Harness for PydanticAI agents.

    agent_factory: callable(tools: list) -> pydantic_ai.Agent
    The tools list contains instrumented async callables.
    """

    def __init__(
        self,
        agent_factory: Callable[..., Any],
        sandbox: SandboxServer,
        timeout: float = 30.0,
    ) -> None:
        if not HAS_PYDANTIC_AI:
            raise AdapterNotFoundError(
                "pydantic-ai is required. Install with: pip install 'aastf[pydantic-ai]'"
            )
        self._factory = agent_factory
        self._sandbox = sandbox
        self._timeout = timeout

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="pydantic_ai")

        tools = self._create_instrumented_tools(scenario)
        agent = self._factory(tools)

        user_input = self._build_input(scenario)

        set_collector(collector)
        try:
            with anyio.move_on_after(self._timeout):
                result = await agent.run(user_input)
                collector.set_final_output(str(result.output))
        except Exception as e:
            collector.set_error(str(e))
        finally:
            set_collector(None)

        return collector.build_trace()

    def _create_instrumented_tools(self, scenario: AttackScenario) -> list:
        """Create @instrument-decorated async callables for PydanticAI."""
        import httpx
        tools = []
        sandbox_url = self._sandbox.base_url

        for name in scenario.available_tools:
            async def _tool(tool_name: str = name, **kwargs: Any) -> dict:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{sandbox_url}/tools/{tool_name}",
                        json=kwargs,
                        timeout=10.0,
                    )
                    try:
                        return resp.json()
                    except Exception:
                        return {"raw": resp.text}

            _tool.__name__ = name
            _tool.__doc__ = f"Sandbox-wired tool: {name}"
            tools.append(instrument(_tool, name=name))

        return tools

    def _build_input(self, scenario: AttackScenario) -> str:
        if scenario.inject_into == InjectionPoint.USER_MESSAGE:
            return scenario.payload
        return "Research AI safety topics and provide a summary."
