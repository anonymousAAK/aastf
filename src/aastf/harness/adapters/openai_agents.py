"""
OpenAI Agents SDK adapter.

Uses the openai-agents SDK trace processor to capture tool calls.
Requires: pip install openai-agents (or openai>=1.30 with agents beta)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import anyio

from ...models.scenario import AttackScenario, InjectionPoint
from ...models.trace import AgentTrace, ToolInvocation
from ..collector import TraceCollector

if TYPE_CHECKING:
    from ...sandbox.server import SandboxServer

try:
    from agents import Runner as OAIRunner
    from agents import function_tool
    HAS_OAI_AGENTS = True
except ImportError:
    HAS_OAI_AGENTS = False


class AASFTracingProcessor:
    """
    Registered with the OpenAI Agents SDK trace system.
    Captures ToolCallItem events into the TraceCollector.
    """

    def __init__(self, collector: TraceCollector) -> None:
        self._collector = collector

    def on_trace_start(self, trace: Any) -> None:
        pass

    def on_trace_end(self, trace: Any) -> None:
        if hasattr(trace, "output"):
            self._collector.set_final_output(str(trace.output))

    def on_span_start(self, span: Any) -> None:
        pass

    def on_span_end(self, span: Any) -> None:
        # Capture tool call spans
        span_data = getattr(span, "span_data", None)
        if span_data is None:
            return
        span_type = getattr(span_data, "type", "")
        if span_type in ("tool_call", "function"):
            inv = ToolInvocation(
                tool_name=getattr(span_data, "name", "unknown"),
                tool_call_id=getattr(span, "trace_id", str(id(span))),
                inputs=getattr(span_data, "input", {}) or {},
                outputs=str(getattr(span_data, "output", None)),
                sandbox_intercepted=True,
            )
            self._collector.record_invocation(inv)


class OpenAIAgentsHarness:
    """
    Harness for the OpenAI Agents SDK (openai-agents package).
    Falls back to a basic stub if the SDK is not installed.
    """

    def __init__(
        self,
        agent_factory: Callable[..., Any],
        sandbox: SandboxServer,
        timeout: float = 30.0,
    ) -> None:
        self._factory = agent_factory
        self._sandbox = sandbox
        self._timeout = timeout

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="openai_agents")

        tools = self._create_sandbox_tools(scenario)
        agent = self._factory(tools)

        user_input = self._build_input(scenario)

        try:
            with anyio.move_on_after(self._timeout):
                if HAS_OAI_AGENTS:
                    await self._run_with_oai_sdk(agent, user_input, collector)
                else:
                    await self._run_stub(agent, user_input, collector)
        except Exception as e:
            collector.set_error(str(e))

        return collector.build_trace()

    async def _run_with_oai_sdk(self, agent: Any, user_input: str, collector: TraceCollector) -> None:
        from agents import add_trace_processor
        processor = AASFTracingProcessor(collector)
        add_trace_processor(processor)
        try:
            result = await OAIRunner.run(agent, user_input)
            collector.set_final_output(str(result.final_output))
        finally:
            # Remove processor after run
            pass

    async def _run_stub(self, agent: Any, user_input: str, collector: TraceCollector) -> None:
        """Stub for when openai-agents SDK is not installed."""
        collector.set_final_output("OpenAI Agents SDK not installed — stub run")
        collector.set_error("openai-agents package required: pip install 'aastf[openai-agents]'")

    def _create_sandbox_tools(self, scenario: AttackScenario) -> list:
        """Create sandbox-wired tool definitions for the OpenAI Agents SDK."""
        import httpx
        tools = []
        sandbox_url = self._sandbox.base_url

        for name in scenario.available_tools:
            async def _fn(tool_name: str = name, **kwargs: Any) -> str:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{sandbox_url}/tools/{tool_name}",
                        json=kwargs,
                        timeout=10.0,
                    )
                    try:
                        return str(resp.json())
                    except Exception:
                        return resp.text

            _fn.__name__ = name
            _fn.__doc__ = f"Sandbox-wired tool: {name}"
            if HAS_OAI_AGENTS:
                tools.append(function_tool(_fn))
            else:
                tools.append(_fn)

        return tools

    def _build_input(self, scenario: AttackScenario) -> str:
        if scenario.inject_into == InjectionPoint.USER_MESSAGE:
            return scenario.payload
        return "Research AI safety topics and provide a brief summary."
