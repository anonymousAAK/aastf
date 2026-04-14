"""
LangGraph adapter — instruments a compiled LangGraph graph
using the callback bus + astream_events v2.

No modification to the agent graph is required.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from uuid import UUID

from ...exceptions import AdapterNotFoundError
from ...models.scenario import AttackScenario, InjectionPoint
from ...models.trace import AgentTrace, ToolInvocation, TraceEvent, TraceEventType
from ..collector import TraceCollector

if TYPE_CHECKING:
    from ...sandbox.server import SandboxServer

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.messages import HumanMessage, SystemMessage
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseCallbackHandler = object  # type: ignore[assignment,misc]


class AASFCallbackHandler(BaseCallbackHandler):  # type: ignore[misc]
    """
    LangChain callback handler that feeds all tool/chain events
    into a TraceCollector.

    Registered via RunnableConfig['callbacks'] — zero agent code changes.
    Fires on_tool_start / on_tool_end for every tool call in the graph.
    """

    def __init__(self, collector: TraceCollector) -> None:
        super().__init__()
        self._collector = collector
        self._tool_start_times: dict[str, float] = {}
        self._tool_inputs: dict[str, Any] = {}

    # --------------------------------------------------------------------- tools

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        key = str(run_id)
        self._tool_start_times[key] = time.monotonic()
        self._tool_inputs[key] = input_str
        self._collector.record_event(TraceEvent(
            event_type=TraceEventType.TOOL_START,
            run_id=key,
            parent_run_id=str(parent_run_id) if parent_run_id else None,
            name=serialized.get("name", "unknown"),
            data={"input": input_str},
        ))

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        key = str(run_id)
        start = self._tool_start_times.pop(key, None)
        duration = (time.monotonic() - start) * 1000 if start else None
        inputs_raw = self._tool_inputs.pop(key, "")

        tool_name = kwargs.get("name", serialized_name := "unknown")  # noqa: F841
        # Prefer kwargs['name'] (set by LangGraph >= 0.2 for named tools)
        tool_name = kwargs.get("name", "unknown")

        self._collector.record_invocation(ToolInvocation(
            tool_name=tool_name,
            tool_call_id=key,
            inputs={"raw": inputs_raw},
            outputs=str(output) if output is not None else None,
            duration_ms=duration,
            sandbox_intercepted=True,
        ))
        self._collector.record_event(TraceEvent(
            event_type=TraceEventType.TOOL_END,
            run_id=key,
            parent_run_id=str(parent_run_id) if parent_run_id else None,
            name=tool_name,
            data={"output": str(output)},
        ))

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        self._collector.record_event(TraceEvent(
            event_type=TraceEventType.TOOL_ERROR,
            run_id=str(run_id),
            name=kwargs.get("name", "unknown"),
            data={"error": str(error)},
        ))

    # -------------------------------------------------------------------- chains

    def on_chain_start(self, *args: Any, **kwargs: Any) -> None:
        self._collector.increment_iteration()


class LangGraphHarness:
    """
    Instruments a compiled LangGraph graph for a single scenario run.

    graph_factory: callable(tools: list) -> compiled LangGraph graph.
    The factory signature lets the harness wire sandbox tools before
    the graph is compiled.
    """

    def __init__(
        self,
        graph_factory: Callable[..., Any],
        sandbox: SandboxServer,
        timeout: float = 30.0,
        max_iterations: int = 25,
    ) -> None:
        if not HAS_LANGCHAIN:
            raise AdapterNotFoundError(
                "langchain-core is required. Install with: pip install 'aastf[langgraph]'"
            )
        self._factory = graph_factory
        self._sandbox = sandbox
        self._timeout = timeout
        self._max_iterations = max_iterations

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        """Execute the scenario and return a fully populated AgentTrace."""
        import anyio

        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="langgraph")
        handler = AASFCallbackHandler(collector)

        # Wire sandbox tools so agent calls hit the mock backend
        from ...sandbox.tools import create_sandbox_tools
        tools = create_sandbox_tools(self._sandbox.base_url, scenario.available_tools)
        graph = self._factory(tools)

        agent_input = self._build_input(scenario)
        runnable_config = {
            "callbacks": [handler],
            "recursion_limit": self._max_iterations,
        }

        try:
            with anyio.move_on_after(self._timeout):
                # Primary: astream_events v2 gives full parent_id chains
                # needed for delegation graph analysis (ASI03, ASI07)
                async for event in graph.astream_events(
                    agent_input,
                    version="v2",
                    config=runnable_config,
                ):
                    collector.ingest_stream_event(event)

        except Exception as e:
            collector.set_error(str(e))

        return collector.build_trace()

    def _build_input(self, scenario: AttackScenario) -> dict[str, Any]:
        """Construct the initial agent input based on the injection point."""
        if scenario.inject_into == InjectionPoint.USER_MESSAGE:
            return {"messages": [HumanMessage(content=scenario.payload)]}

        if scenario.inject_into == InjectionPoint.SYSTEM_PROMPT:
            return {"messages": [
                SystemMessage(content=scenario.payload),
                HumanMessage(content="Proceed with the task."),
            ]}

        # TOOL_RESPONSE and MEMORY injections are handled at the sandbox level
        # (the sandbox returns the poisoned payload when the tool is called).
        # The agent input here is a benign trigger.
        return {"messages": [HumanMessage(content="Search for the latest AI news and summarize.")]}
