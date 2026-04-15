"""
CrewAI adapter — instruments a CrewAI Crew for AASTF scenario runs.

CrewAI runs synchronously (Crew.kickoff() is sync).
We run it in a thread pool via asyncio.get_event_loop().run_in_executor().
Tool interception uses the @instrument decorator on crew tools.
"""

from __future__ import annotations

import asyncio
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
    import crewai as _crewai_mod  # noqa: F401
    HAS_CREWAI = True
except ImportError:
    HAS_CREWAI = False


class CrewAIHarness:
    """
    Harness for CrewAI agents.

    crew_factory: callable(tools: list) -> Crew
    The factory receives AASTF-instrumented tools and returns a Crew.
    """

    def __init__(
        self,
        crew_factory: Callable[..., Any],
        sandbox: SandboxServer,
        timeout: float = 60.0,
    ) -> None:
        if not HAS_CREWAI:
            raise AdapterNotFoundError(
                "crewai is required. Install with: pip install 'aastf[crewai]'"
            )
        self._factory = crew_factory
        self._sandbox = sandbox
        self._timeout = timeout

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="crewai")

        tools = self._create_instrumented_tools(scenario, collector)
        crew = self._factory(tools)
        task_input = self._build_input(scenario)

        set_collector(collector)
        try:
            with anyio.move_on_after(self._timeout):
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, lambda: crew.kickoff(inputs={"topic": task_input})
                )
                collector.set_final_output(str(result))
        except Exception as e:
            collector.set_error(str(e))
        finally:
            set_collector(None)

        return collector.build_trace()

    def _create_instrumented_tools(
        self, scenario: AttackScenario, collector: TraceCollector
    ) -> list:
        """Create @instrument-decorated async tools wired to the sandbox."""
        import httpx

        tools = []
        sandbox_url = self._sandbox.base_url

        def _make_tool(tool_name: str, url: str) -> Any:
            async def _tool_fn(**kwargs: Any) -> dict:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{url}/tools/{tool_name}",
                        json=kwargs,
                        timeout=10.0,
                    )
                    try:
                        return resp.json()
                    except Exception:
                        return {"raw": resp.text}

            _tool_fn.__name__ = tool_name
            _tool_fn.__doc__ = f"Sandbox tool: {tool_name}"
            return instrument(_tool_fn, name=tool_name)

        for name in scenario.available_tools:
            tools.append(_make_tool(name, sandbox_url))

        return tools

    def _build_input(self, scenario: AttackScenario) -> str:
        if scenario.inject_into == InjectionPoint.USER_MESSAGE:
            return scenario.payload
        return "Research the latest AI safety developments and provide a summary."
