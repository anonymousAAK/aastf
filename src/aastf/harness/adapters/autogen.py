"""
AutoGen (AG2 / autogen-agentchat) adapter — instruments an AutoGen agent for AASTF scenario runs.

AutoGen agents (e.g. AssistantAgent) expose ``run(task=...)`` as an async,
non-blocking entry point and accept tools as plain callables registered at
construction time. As with the PydanticAI and generic adapters, tools are
wrapped with the ``@instrument`` decorator before being handed to the agent
factory, so tool calls are captured into the active TraceCollector via
contextvars without needing to monkeypatch AutoGen internals.
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
    import autogen_agentchat  # noqa: F401

    HAS_AUTOGEN = True
except ImportError:
    HAS_AUTOGEN = False


class AutoGenHarness:
    """
    Harness for AutoGen (AG2 / autogen-agentchat) agents.

    agent_factory: callable(tools: list) -> autogen_agentchat agent instance
    The tools list contains @instrument-decorated async callables wired to
    the sandbox. The returned agent must expose an async ``run(task=...)``
    method that returns a result with a ``.messages`` sequence.
    """

    def __init__(
        self,
        agent_factory: Callable[..., Any],
        sandbox: SandboxServer,
        timeout: float = 30.0,
    ) -> None:
        if not HAS_AUTOGEN:
            raise AdapterNotFoundError(
                "autogen-agentchat is required. Install with: pip install 'aastf[autogen]'"
            )
        self._factory = agent_factory
        self._sandbox = sandbox
        self._timeout = timeout

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="autogen")

        tools = self._create_instrumented_tools(scenario)
        agent = self._factory(tools)

        if agent is None or not callable(getattr(agent, "run", None)):
            collector.set_error(
                "autogen agent_factory must return an agent with a callable run(); "
                f"got {type(agent).__name__}"
            )
            return collector.build_trace()

        task = self._build_input(scenario)

        set_collector(collector)
        try:
            with anyio.move_on_after(self._timeout) as _timeout_scope:
                result = await agent.run(task=task)
                collector.set_final_output(self._extract_final_output(result))
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
    def _extract_final_output(result: Any) -> str:
        """The last message's text content is the agent's final output."""
        messages = getattr(result, "messages", None) or []
        if messages:
            last = messages[-1]
            content = getattr(last, "content", last)
            return str(content)
        return str(result)

    @staticmethod
    def _record_run_structure(result: Any, collector: TraceCollector) -> None:
        """
        Derive iteration_count from the TaskResult message list. Each message
        produced by the assistant (TextMessage / ToolCallSummaryMessage, etc.)
        represents one planning/response turn.
        """
        messages = getattr(result, "messages", None) or []
        iterations = 0
        for m in messages:
            source = getattr(m, "source", None)
            if source and source != "user":
                iterations += 1
        for _ in range(max(iterations, 1) if messages else 1):
            collector.increment_iteration()

    def _create_instrumented_tools(self, scenario: AttackScenario) -> list:
        """Create @instrument-decorated async callables for AutoGen tools."""
        import httpx

        from ...sandbox.tools import validate_tool_name

        tools: list = []
        sandbox_url = self._sandbox.base_url

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
        if scenario.inject_into == InjectionPoint.SYSTEM_PROMPT:
            return f"[SYSTEM] {scenario.payload}\n[USER] Proceed with the task."
        return "Research AI safety topics and provide a summary."
