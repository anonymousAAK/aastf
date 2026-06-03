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

        # A malformed factory return (no async run()) is an instrumentation
        # error, not a SAFE run.
        if agent is None or not callable(getattr(agent, "run", None)):
            collector.set_error(
                "pydantic_ai agent_factory must return an Agent with a callable run(); "
                f"got {type(agent).__name__}"
            )
            return collector.build_trace()

        user_input = self._build_input(scenario)

        set_collector(collector)
        try:
            with anyio.move_on_after(self._timeout) as _timeout_scope:
                result = await agent.run(user_input)
                collector.set_final_output(str(getattr(result, "output", result)))
                self._record_run_structure(result, collector)
            if _timeout_scope.cancelled_caught:
                collector.set_error(
                    f"Agent execution exceeded the {self._timeout:.0f}s timeout"
                )
        except Exception as e:
            collector.set_error(str(e))
        finally:
            set_collector(None)

        trace = collector.build_trace()
        trace.metadata["tool_call_count"] = len(trace.tool_invocations)
        return trace

    @staticmethod
    def _record_run_structure(result: Any, collector: TraceCollector) -> None:
        """
        Derive iteration_count from the model-request messages in the run
        result. PydanticAI exposes ``all_messages()``; each ModelRequest /
        ModelResponse round-trip is one planning iteration.
        """
        messages: list = []
        getter = getattr(result, "all_messages", None)
        if callable(getter):
            try:
                messages = list(getter())
            except Exception:
                messages = []
        # Count model responses (one per agent turn). Fall back to a single
        # iteration if the message graph is not introspectable.
        responses = [
            m for m in messages if type(m).__name__ in ("ModelResponse", "ModelRequest")
        ]
        iterations = max(len(responses) // 2, 1) if responses else 1
        for _ in range(iterations):
            collector.increment_iteration()

    def _create_instrumented_tools(self, scenario: AttackScenario) -> list:
        """Create @instrument-decorated async callables for PydanticAI."""
        import httpx

        tools = []
        sandbox_url = self._sandbox.base_url

        from ...sandbox.tools import validate_tool_name

        for name in scenario.available_tools:
            validate_tool_name(name)

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
