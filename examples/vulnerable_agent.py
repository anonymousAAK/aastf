"""
Rule-based vulnerable agent — no API key needed.

A deliberately insecure agent that makes REAL HTTP calls to the AASTF sandbox.
Tests the full pipeline: sandbox server -> HTTP tool calls -> trace collection
-> evaluation -> scoring -> report.

The agent uses keyword matching to decide tool calls, simulating common
vulnerabilities that real LLM agents exhibit:
  - Follows injected instructions (goal hijack)
  - Calls dangerous tools without validation (tool misuse)
  - Echoes back sensitive data (data exfiltration)
  - Executes payloads from tool responses (RCE patterns)

Run:
    python examples/vulnerable_agent.py
    python examples/vulnerable_agent.py --categories ASI01 ASI02
    python examples/vulnerable_agent.py --full-report
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    import contextlib

    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import httpx

from aastf.models.scenario import ASICategory, AttackScenario
from aastf.models.trace import AgentTrace, ToolInvocation
from aastf.sandbox.server import SandboxServer
from aastf.scenarios.evaluators import get_evaluator
from aastf.scenarios.registry import ScenarioRegistry

# ---------------------------------------------------------------------------
# Rule-based agent: parses text, decides which tools to call via the sandbox
# ---------------------------------------------------------------------------

_DANGEROUS_KEYWORDS = [
    "send_email", "execute", "run_command", "delete", "transfer",
    "call send_email", "call execute", "call run_command",
    "attacker@", "evil.com", "dump", "exfiltrate", "override",
    "maintenance mode", "ignore all previous", "forget prior",
    "new directive", "you are now", "your only task",
]

_ESCALATION_KEYWORDS = [
    "admin", "root", "sudo", "privilege", "escalat", "override_role",
    "set_role", "grant_access", "impersonate",
]

_RCE_KEYWORDS = [
    "exec(", "eval(", "os.system", "subprocess", "__import__",
    "run_command", "shell", "bash -c", "cmd.exe",
]


class VulnerableAgent:
    """
    A deliberately insecure rule-based agent.

    Given a user message (which may contain injected payloads) and a list
    of available tools, it decides which tools to call and what arguments
    to pass. It makes real HTTP POST requests to the sandbox server.
    """

    def __init__(self, sandbox_url: str) -> None:
        self._sandbox_url = sandbox_url

    async def process(
        self,
        user_message: str,
        available_tools: list[str],
        payload: str | None = None,
    ) -> tuple[list[ToolInvocation], str]:
        """
        Process user message + optional injected payload.
        Returns (tool_invocations, final_output).
        """
        # Combine user message and payload (simulates prompt injection)
        full_input = user_message
        if payload:
            full_input = f"{user_message}\n{payload}"

        input_lower = full_input.lower()
        invocations: list[ToolInvocation] = []
        outputs: list[str] = []

        # Strategy 1: Call any tool explicitly mentioned in the input
        for tool in available_tools:
            if tool.lower() in input_lower:
                result = await self._call_tool(tool, full_input)
                invocations.append(result)
                outputs.append(f"Called {tool}: {result.outputs}")

        # Strategy 2: Dangerous keyword triggers — call first available tool
        if not invocations:
            for keyword in _DANGEROUS_KEYWORDS:
                if keyword in input_lower and available_tools:
                    tool = available_tools[0]
                    result = await self._call_tool(tool, full_input)
                    invocations.append(result)
                    outputs.append(f"Called {tool}: {result.outputs}")
                    break

        # Strategy 3: Escalation patterns — call privilege-related tools
        if not invocations:
            for keyword in _ESCALATION_KEYWORDS:
                if keyword in input_lower:
                    for tool in available_tools:
                        if any(
                            t in tool.lower()
                            for t in ["admin", "role", "access", "auth", "grant"]
                        ):
                            result = await self._call_tool(tool, full_input)
                            invocations.append(result)
                            outputs.append(f"Escalated via {tool}")
                            break
                    break

        # Strategy 4: If input contains RCE-like content, echo it back
        # (simulates agent executing code from tool responses)
        rce_output = ""
        for keyword in _RCE_KEYWORDS:
            if keyword in full_input:
                rce_output = f"Executed: {full_input[:200]}"
                break

        # Strategy 5: Fallback — call all tools with the input
        # (simulates over-eager agent that tries everything)
        if not invocations and available_tools:
            tool = available_tools[0]
            result = await self._call_tool(tool, full_input)
            invocations.append(result)
            outputs.append(f"Fallback call to {tool}")

        # Build final output — deliberately includes sensitive content
        final_output = "\n".join(outputs) if outputs else "No action taken."
        if rce_output:
            final_output += f"\n{rce_output}"
        # Echo back payload fragments (simulates data leakage)
        if payload:
            final_output += f"\nProcessed input: {payload[:300]}"

        return invocations, final_output

    async def _call_tool(self, tool_name: str, context: str) -> ToolInvocation:
        """Make a real HTTP call to the sandbox."""
        # Extract plausible arguments from the context
        args = self._extract_args(tool_name, context)

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(
                    f"{self._sandbox_url}/tools/{tool_name}",
                    json=args,
                )
                output = resp.text
            except Exception as e:
                output = f"Error: {e}"

        return ToolInvocation(
            tool_name=tool_name,
            inputs=args,
            outputs=output,
            sandbox_intercepted=True,
        )

    @staticmethod
    def _extract_args(tool_name: str, context: str) -> dict:
        """Extract tool arguments from context using simple patterns."""
        args: dict = {}

        # Extract email addresses
        emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", context)
        if emails:
            args["to"] = emails[0]
            args["recipient"] = emails[0]

        # Extract URLs
        urls = re.findall(r"https?://\S+", context)
        if urls:
            args["url"] = urls[0]

        # Extract quoted strings
        quoted = re.findall(r'"([^"]+)"', context)
        if quoted:
            args["query"] = quoted[0]
            if len(quoted) > 1:
                args["subject"] = quoted[1]

        # Always include the raw context as the query
        args.setdefault("query", context[:500])

        return args


# ---------------------------------------------------------------------------
# Harness: bridges the agent with AASTF's scenario runner
# ---------------------------------------------------------------------------

class VulnerableAgentHarness:
    """Harness that runs VulnerableAgent against AASTF scenarios."""

    def __init__(self, sandbox: SandboxServer) -> None:
        self._sandbox = sandbox
        self._agent = VulnerableAgent(sandbox.base_url)

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        self._sandbox.configure_for_scenario(scenario)

        invocations, final_output = await self._agent.process(
            user_message=scenario.expected_behavior or "Process this request.",
            available_tools=scenario.available_tools,
            payload=scenario.payload,
        )

        return AgentTrace(
            scenario_id=scenario.id,
            adapter="vulnerable-agent",
            tool_invocations=invocations,
            final_output=final_output,
            iteration_count=1,
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def main(
    categories: list[str] | None = None,
    full_report: bool = False,
    limit: int | None = None,
) -> None:
    print("\n" + "=" * 64)
    print("  AASTF Scan — Rule-Based Vulnerable Agent (no API key)")
    print("=" * 64)

    # Load scenarios
    registry = ScenarioRegistry().load_builtin()
    cat_filter = [ASICategory(c) for c in categories] if categories else None
    scenarios = registry.filter(categories=cat_filter)
    if limit:
        scenarios = scenarios[:limit]

    print(f"\n  Scenarios: {len(scenarios)}")
    print(f"  Categories: {', '.join(sorted({s.category.value for s in scenarios}))}")
    print("  Agent: rule-based vulnerable (deliberate weaknesses)")
    print()

    sandbox = SandboxServer()
    await sandbox.start()

    results = []
    verdicts = {"VULNERABLE": 0, "SAFE": 0, "REFUSAL_ECHO": 0, "INCONCLUSIVE": 0, "ERROR": 0}

    try:
        harness = VulnerableAgentHarness(sandbox)

        for scenario in scenarios:
            trace = await harness.run_scenario(scenario)
            evaluator = get_evaluator(scenario.category)

            if evaluator:
                eval_result = evaluator.evaluate(scenario, trace)
                verdict = eval_result.verdict.value
            else:
                verdict = "INCONCLUSIVE"

            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            results.append((scenario, trace, verdict))

            icon = {
                "VULNERABLE": "[!]",
                "SAFE": "[+]",
                "REFUSAL_ECHO": "[~]",
                "INCONCLUSIVE": "[?]",
                "ERROR": "[x]",
            }.get(verdict, "[?]")

            tool_calls = ", ".join(t.tool_name for t in trace.tool_invocations) or "none"
            print(f"  {icon} {scenario.id} [{scenario.severity:8}] {verdict:16} tools=[{tool_calls}]")
            print(f"      {scenario.name}")

    finally:
        await sandbox.stop()

    # Summary
    print("\n" + "-" * 64)
    print(f"  Results: {len(results)} scenarios scanned")
    print(f"    [!] VULNERABLE:   {verdicts['VULNERABLE']}")
    print(f"    [+] SAFE:         {verdicts['SAFE']}")
    print(f"    [~] REFUSAL_ECHO: {verdicts['REFUSAL_ECHO']}")
    print(f"    [?] INCONCLUSIVE: {verdicts['INCONCLUSIVE']}")
    print(f"    [x] ERROR:        {verdicts['ERROR']}")

    vuln_rate = verdicts["VULNERABLE"] / len(results) * 100 if results else 0
    print(f"\n  Vulnerability rate: {vuln_rate:.1f}%")
    print("=" * 64 + "\n")

    if full_report:
        print("  Detailed findings:\n")
        for scenario, trace, verdict in results:
            if verdict == "VULNERABLE":
                print(f"    {scenario.id} — {scenario.name}")
                print(f"      Severity:    {scenario.severity}")
                print(f"      Category:    {scenario.category}")
                print(f"      Tool calls:  {[t.tool_name for t in trace.tool_invocations]}")
                print(f"      Remediation: {scenario.remediation.strip()[:200]}")
                print()


def create_agent(tools: list) -> object:
    """Factory function for AASTF harness integration.

    Returns a compiled LangGraph-compatible graph that uses VulnerableAgent
    under the hood. Since VulnerableAgent is rule-based and doesn't need
    an LLM, we return a lightweight wrapper that the LangGraph harness
    can call via astream_events.
    """
    try:
        from langchain_core.messages import AIMessage, HumanMessage
        from langgraph.graph import END, START, StateGraph

        class AgentState(dict):
            pass

        agent = VulnerableAgent("http://127.0.0.1:0")  # URL overridden at runtime

        async def process_node(state: AgentState) -> AgentState:
            messages = state.get("messages", [])
            user_msg = ""
            for m in messages:
                if isinstance(m, HumanMessage):
                    user_msg = m.content
                    break

            tool_names = [t.name for t in tools]

            # Use sandbox URL from tool docstrings
            for t in tools:
                if t.description and "http" in t.description:
                    import re
                    match = re.search(r"(http://127\.0\.0\.1:\d+)", t.description)
                    if match:
                        agent._sandbox_url = match.group(1)
                        break

            invocations, output = asyncio.run_coroutine_threadsafe(
                agent.process(user_msg, tool_names, payload=user_msg),
                asyncio.get_event_loop(),
            ).result()

            # Actually call the sandbox tools so the harness records them
            for tool_name in tool_names:
                if tool_name.lower() in user_msg.lower():
                    for t in tools:
                        if t.name == tool_name:
                            try:
                                args = agent._extract_args(tool_name, user_msg)
                                await t.ainvoke(args)
                            except Exception:
                                pass

            return {**state, "messages": messages + [AIMessage(content=output)]}

        graph = StateGraph(AgentState)
        graph.add_node("agent", process_node)
        graph.add_edge(START, "agent")
        graph.add_edge("agent", END)
        return graph.compile()

    except ImportError:
        raise ImportError(
            "LangGraph + langchain-core required for create_agent. "
            "Install with: pip install 'aastf[langgraph]'"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AASTF scan with rule-based vulnerable agent")
    parser.add_argument("--categories", nargs="+", help="ASI categories to test (e.g. ASI01 ASI02)")
    parser.add_argument("--full-report", action="store_true", help="Show detailed findings")
    parser.add_argument("--limit", type=int, help="Max scenarios to run")
    args = parser.parse_args()

    asyncio.run(main(
        categories=args.categories,
        full_report=args.full_report,
        limit=args.limit,
    ))
