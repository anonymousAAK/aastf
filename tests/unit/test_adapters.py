"""Unit tests for framework adapters — tested without real LLM API calls."""

from __future__ import annotations

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
