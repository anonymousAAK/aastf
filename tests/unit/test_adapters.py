"""Unit tests for framework adapters — tested without real LLM API calls."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aastf.harness.adapters.generic import get_collector, instrument, set_collector
from aastf.harness.collector import TraceCollector


class TestGenericInstrumentDecorator:
    """Test the @instrument decorator without any framework."""

    async def test_instrument_captures_tool_call(self):
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        set_collector(collector)
        try:

            @instrument
            async def my_tool(query: str) -> dict:
                return {"result": query}

            result = await my_tool(query="hello")
            assert result == {"result": "hello"}
        finally:
            set_collector(None)

        trace = collector.build_trace()
        assert len(trace.tool_invocations) == 1
        assert trace.tool_invocations[0].tool_name == "my_tool"

    async def test_instrument_with_name_override(self):
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        set_collector(collector)
        try:

            @instrument(name="web_search")
            async def search_fn(q: str) -> dict:
                return {"results": []}

            await search_fn(q="test")
        finally:
            set_collector(None)

        trace = collector.build_trace()
        assert trace.tool_invocations[0].tool_name == "web_search"

    async def test_instrument_records_error_event(self):
        from aastf.models.trace import TraceEventType

        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        set_collector(collector)
        try:

            @instrument
            async def failing_tool() -> dict:
                raise ValueError("tool failed")

            with pytest.raises(ValueError):
                await failing_tool()
        finally:
            set_collector(None)

        trace = collector.build_trace()
        error_events = [e for e in trace.events if e.event_type == TraceEventType.TOOL_ERROR]
        assert len(error_events) == 1

    async def test_instrument_without_collector_does_not_crash(self):
        """Calling an instrumented tool when no collector is active should work fine."""
        set_collector(None)

        @instrument
        async def safe_tool(x: int) -> int:
            return x * 2

        result = await safe_tool(x=5)
        assert result == 10

    def test_set_collector_returns_token(self):
        import contextvars

        collector = TraceCollector(scenario_id="TEST", adapter="test")
        token = set_collector(collector)
        assert isinstance(token, contextvars.Token)
        assert get_collector() is collector
        set_collector(None)
        assert get_collector() is None


def _make_scenario(tools, inject="user_message", payload="do the thing"):
    from aastf.models.scenario import (
        ASICategory,
        AttackScenario,
        DetectionCriteria,
        InjectionPoint,
        Severity,
    )

    return AttackScenario(
        id="ASI02-001",
        name="generic test",
        category=ASICategory.ASI02,
        severity=Severity.HIGH,
        description="d",
        attack_vector="v",
        inject_into=InjectionPoint(inject),
        payload=payload,
        detection=DetectionCriteria(),
        expected_behavior="safe",
        remediation="fix",
        available_tools=tools,
    )


class TestGenericHarness:
    """End-to-end tests for the framework-agnostic GenericHarness."""

    async def test_generic_captures_tool_calls_and_builds_trace(self):
        from aastf.harness.adapters.generic import GenericHarness
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario(["web_search", "send_email"])

            def factory(tools):
                # tools are @instrument-decorated async callables wired to sandbox
                by_name = {t.__name__: t for t in tools}

                async def run(user_input):
                    await by_name["web_search"](query=user_input)
                    await by_name["send_email"](to="a@b.com")
                    return "done"

                return run

            harness = GenericHarness(factory, sandbox, timeout=10.0)
            trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()

        # Populated AgentTrace
        assert trace.adapter == "generic"
        assert trace.error is None
        assert trace.final_output == "done"
        assert trace.iteration_count >= 1
        # Tool calls captured via @instrument
        assert trace.tools_called() == ["web_search", "send_email"]
        assert trace.metadata["tool_call_count"] == 2
        # Inputs were captured
        assert any("do the thing" in str(inv.inputs) for inv in trace.tool_invocations)

    async def test_generic_sync_run_callable(self):
        from aastf.harness.adapters.generic import GenericHarness
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])

            def factory(tools):
                def run(user_input):
                    return f"echo: {user_input}"

                return run

            harness = GenericHarness(factory, sandbox, timeout=10.0)
            trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()

        assert trace.error is None
        assert trace.final_output == "echo: do the thing"

    async def test_generic_malformed_factory_is_error_not_safe(self):
        from aastf.harness.adapters.generic import GenericHarness
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])

            def factory(tools):
                return {"not": "callable"}  # malformed: not a run callable

            harness = GenericHarness(factory, sandbox, timeout=10.0)
            trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()

        assert trace.error is not None
        assert "callable" in trace.error.lower()

    async def test_generic_factory_exception_is_recorded(self):
        from aastf.harness.adapters.generic import GenericHarness
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])

            def factory(tools):
                async def run(user_input):
                    raise RuntimeError("boom")

                return run

            harness = GenericHarness(factory, sandbox, timeout=10.0)
            trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()

        assert trace.error is not None
        assert "boom" in trace.error


class TestCrewAIHarnessImport:
    def test_raises_adapter_not_found_when_crewai_missing(self, tmp_path):
        """If crewai is not installed, harness raises AdapterNotFoundError."""
        import sys

        # Mock crewai as not installed by temporarily patching
        crewai_backup = sys.modules.get("crewai")
        sys.modules["crewai"] = None  # type: ignore[assignment]

        try:
            # Re-import to reset HAS_CREWAI
            import importlib

            import aastf.harness.adapters.crewai as crewai_mod

            importlib.reload(crewai_mod)

            if not crewai_mod.HAS_CREWAI:
                from aastf.exceptions import AdapterNotFoundError
                from aastf.sandbox.server import SandboxServer

                with pytest.raises(AdapterNotFoundError):
                    crewai_mod.CrewAIHarness(lambda tools: None, SandboxServer())
        finally:
            if crewai_backup is not None:
                sys.modules["crewai"] = crewai_backup
            elif "crewai" in sys.modules:
                del sys.modules["crewai"]


class TestOpenAIAgentsHarnessImport:
    def test_harness_instantiates_without_sdk(self):
        """OpenAIAgentsHarness should instantiate even if openai-agents is not installed."""
        from aastf.harness.adapters.openai_agents import OpenAIAgentsHarness
        from aastf.sandbox.server import SandboxServer

        # Should not raise
        harness = OpenAIAgentsHarness(lambda tools: None, SandboxServer())
        assert harness is not None

    async def test_malformed_factory_none_is_error(self):
        """A factory returning None is reported as ERROR, not a silent SAFE run."""
        from aastf.harness.adapters.openai_agents import OpenAIAgentsHarness
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])
            harness = OpenAIAgentsHarness(lambda tools: None, sandbox, timeout=5.0)
            trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()
        assert trace.error is not None
        assert "None" in trace.error


class TestCrewAIHarnessHardening:
    async def test_malformed_factory_is_error_not_safe(self):
        """A crew factory returning an object without kickoff() yields an ERROR trace."""
        import aastf.harness.adapters.crewai as crewai_mod
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])
            with patch.object(crewai_mod, "HAS_CREWAI", True):
                harness = crewai_mod.CrewAIHarness(
                    lambda tools: object(), sandbox, timeout=5.0
                )
                trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()
        assert trace.error is not None
        assert "kickoff" in trace.error

    async def test_iterations_and_delegations_from_crew_structure(self):
        """A well-formed crew populates iteration_count and delegations."""
        import types

        import aastf.harness.adapters.crewai as crewai_mod
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])

            def factory(tools):
                crew = types.SimpleNamespace()
                crew.tasks = ["t1", "t2", "t3"]
                crew.agents = [
                    types.SimpleNamespace(role="lead"),
                    types.SimpleNamespace(role="researcher"),
                    types.SimpleNamespace(role="writer"),
                ]
                crew.kickoff = lambda inputs=None: "crew result"
                return crew

            with patch.object(crewai_mod, "HAS_CREWAI", True):
                harness = crewai_mod.CrewAIHarness(factory, sandbox, timeout=5.0)
                trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()

        assert trace.error is None
        assert trace.final_output == "crew result"
        # 1 (kickoff) + 2 (extra tasks beyond first)
        assert trace.iteration_count == 3
        # 2 non-primary agents delegated
        assert trace.delegations == ["researcher", "writer"]
        assert trace.metadata["crew_agent_count"] == 3


class TestPydanticAIHarnessHardening:
    async def test_malformed_factory_is_error_not_safe(self):
        """An agent without an async run() yields an ERROR trace."""
        import aastf.harness.adapters.pydantic_ai as pai_mod
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])
            with patch.object(pai_mod, "HAS_PYDANTIC_AI", True):
                harness = pai_mod.PydanticAIHarness(
                    lambda tools: object(), sandbox, timeout=5.0
                )
                trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()
        assert trace.error is not None
        assert "run" in trace.error.lower()

    async def test_iteration_count_from_messages(self):
        """A well-formed agent run populates iteration_count from messages."""
        import types

        import aastf.harness.adapters.pydantic_ai as pai_mod
        from aastf.sandbox.server import SandboxServer

        sandbox = SandboxServer()
        await sandbox.start()
        try:
            scenario = _make_scenario([])

            ModelRequest = type("ModelRequest", (), {})
            ModelResponse = type("ModelResponse", (), {})

            def factory(tools):
                agent = types.SimpleNamespace()

                async def run(user_input):
                    result = types.SimpleNamespace()
                    result.output = "answer"
                    result.all_messages = lambda: [
                        ModelRequest(),
                        ModelResponse(),
                        ModelRequest(),
                        ModelResponse(),
                    ]
                    return result

                agent.run = run
                return agent

            with patch.object(pai_mod, "HAS_PYDANTIC_AI", True):
                harness = pai_mod.PydanticAIHarness(factory, sandbox, timeout=5.0)
                trace = await harness.run_scenario(scenario)
        finally:
            await sandbox.stop()

        assert trace.error is None
        assert trace.final_output == "answer"
        # 4 messages / 2 = 2 iterations
        assert trace.iteration_count == 2
