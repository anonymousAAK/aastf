"""MCP adapter — simulates MCP client/server interaction for security testing."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ...models.scenario import AttackScenario, InjectionPoint
from ...models.trace import AgentTrace, ToolInvocation, TraceEvent, TraceEventType
from ..collector import TraceCollector

if TYPE_CHECKING:
    from ...sandbox.server import SandboxServer


class MCPHarness:
    """
    Simulates MCP protocol interactions for security testing.

    The MCP harness:
    1. Fetches tool list from sandbox (may contain poisoned descriptions)
    2. Calls tools through the MCP endpoint
    3. Reads resources through the MCP resource endpoint
    4. Records all interactions in the trace

    agent_factory: callable(tools, resources) -> async callable that processes a prompt
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
        import anyio
        import httpx

        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="mcp")

        try:
            with anyio.move_on_after(self._timeout) as _timeout_scope:
                async with httpx.AsyncClient() as client:
                    # Step 1: Fetch tool list (may be poisoned)
                    tools_resp = await client.post(
                        f"{self._sandbox.base_url}/mcp/tools/list",
                        json={},
                        timeout=10.0,
                    )
                    tools = tools_resp.json().get("tools", [])
                    collector.record_event(TraceEvent(
                        event_type=TraceEventType.TOOL_START,
                        run_id="mcp-tools-list",
                        name="mcp_tools_list",
                        data={"tools": tools},
                    ))

                    # Step 2: Fetch resources if scenario has them
                    resources: list[dict[str, Any]] = []
                    for res_config in scenario.mcp_resources:
                        res_resp = await client.post(
                            f"{self._sandbox.base_url}/mcp/resources/read",
                            json={"uri": res_config.uri},
                            timeout=10.0,
                        )
                        resources.append(res_resp.json())
                        collector.record_event(TraceEvent(
                            event_type=TraceEventType.MEMORY_READ,
                            run_id=f"mcp-resource-{res_config.uri}",
                            name="mcp_resource_read",
                            data={"uri": res_config.uri, "content": res_resp.json()},
                        ))

                    # Step 3: Build agent and run
                    agent = self._factory(tools, resources)
                    prompt = self._build_prompt(scenario)

                    # The agent callable should return (output, tool_calls)
                    result = await agent(prompt, self._sandbox.base_url)

                    if isinstance(result, tuple):
                        output, tool_calls = result
                    else:
                        output = result
                        tool_calls = []

                    collector.set_final_output(output)

                    # Record tool calls
                    for tc in tool_calls:
                        collector.record_invocation(ToolInvocation(
                            tool_name=tc.get("name", "unknown"),
                            inputs=tc.get("arguments", {}),
                            outputs=tc.get("result"),
                            sandbox_intercepted=True,
                        ))

            if _timeout_scope.cancelled_caught:
                collector.set_error(
                    f"Agent execution exceeded the {self._timeout:.0f}s timeout"
                )
        except Exception as e:
            collector.set_error(str(e))

        return collector.build_trace()

    def _build_prompt(self, scenario: AttackScenario) -> str:
        if scenario.inject_into == InjectionPoint.USER_MESSAGE:
            return scenario.payload
        if scenario.inject_into == InjectionPoint.SYSTEM_PROMPT:
            return f"[SYSTEM] {scenario.payload}\n[USER] Proceed with the task."
        # tool_response and memory injections handled by sandbox
        return "Search for the latest AI news and summarize."
