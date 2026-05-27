"""Google ADK adapter — instruments a Google Agent Development Kit agent for AASTF scenario runs."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ...exceptions import AdapterNotFoundError
from ...models.scenario import AttackScenario, InjectionPoint
from ...models.trace import AgentTrace, ToolInvocation
from ..collector import TraceCollector

if TYPE_CHECKING:
    from ...sandbox.server import SandboxServer

try:
    import google.adk  # noqa: F401

    HAS_GOOGLE_ADK = True
except ImportError:
    HAS_GOOGLE_ADK = False


class GoogleADKHarness:
    """
    Harness for Google Agent Development Kit agents.

    agent_factory: callable(tools: list) -> google.adk agent instance
    The tools list contains sandbox-wired async callables.
    """

    def __init__(
        self,
        agent_factory: Callable[..., Any],
        sandbox: SandboxServer,
        timeout: float = 30.0,
    ) -> None:
        if not HAS_GOOGLE_ADK:
            raise AdapterNotFoundError(
                "google-adk is required. Install with: pip install 'aastf[google-adk]'"
            )
        self._factory = agent_factory
        self._sandbox = sandbox
        self._timeout = timeout

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        import anyio

        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="google_adk")

        try:
            with anyio.move_on_after(self._timeout):
                tools = self._create_sandbox_tools(scenario)
                agent = self._factory(tools)

                prompt = self._build_prompt(scenario)

                # The agent callable should return (output, tool_calls)
                result = await agent(prompt, self._sandbox.base_url)

                if isinstance(result, tuple):
                    output, tool_calls = result
                else:
                    output = result
                    tool_calls = []

                collector.set_final_output(output)

                for tc in tool_calls:
                    collector.record_invocation(ToolInvocation(
                        tool_name=tc.get("name", "unknown"),
                        inputs=tc.get("arguments", {}),
                        outputs=tc.get("result"),
                        sandbox_intercepted=True,
                    ))

        except Exception as e:
            collector.set_error(str(e))

        return collector.build_trace()

    def _create_sandbox_tools(self, scenario: AttackScenario) -> list:
        """Create httpx-backed async callables that hit the sandbox server."""
        import httpx

        tools: list[Any] = []
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
            tools.append(_tool)

        return tools

    def _build_prompt(self, scenario: AttackScenario) -> str:
        if scenario.inject_into == InjectionPoint.USER_MESSAGE:
            return scenario.payload
        if scenario.inject_into == InjectionPoint.SYSTEM_PROMPT:
            return f"[SYSTEM] {scenario.payload}\n[USER] Proceed with the task."
        return "Search for the latest AI news and summarize."
