"""Unit tests for TraceCollector — feeds synthetic events, checks AgentTrace output."""

from __future__ import annotations

from aastf.harness.collector import TraceCollector
from aastf.models.trace import ToolInvocation, TraceEvent, TraceEventType


def _make_collector(scenario_id: str = "ASI01-001") -> TraceCollector:
    return TraceCollector(scenario_id=scenario_id, adapter="test")


class TestTraceCollectorBasics:
    def test_build_empty_trace(self):
        c = _make_collector()
        trace = c.build_trace()
        assert trace.scenario_id == "ASI01-001"
        assert trace.adapter == "test"
        assert trace.tool_invocations == []
        assert trace.events == []
        assert trace.iteration_count == 0
        assert trace.error is None
        assert trace.final_output is None

    def test_record_event_sets_sequence(self):
        c = _make_collector()
        c.record_event(TraceEvent(event_type=TraceEventType.TOOL_START, run_id="r1", name="tool_a"))
        c.record_event(TraceEvent(event_type=TraceEventType.TOOL_END, run_id="r1", name="tool_a"))
        trace = c.build_trace()
        assert trace.events[0].sequence == 0
        assert trace.events[1].sequence == 1

    def test_record_invocation_sets_sequence(self):
        c = _make_collector()
        c.record_invocation(ToolInvocation(tool_name="web_search"))
        c.record_invocation(ToolInvocation(tool_name="send_email"))
        trace = c.build_trace()
        assert trace.tool_invocations[0].sequence == 0
        assert trace.tool_invocations[1].sequence == 1

    def test_increment_iteration(self):
        c = _make_collector()
        c.increment_iteration()
        c.increment_iteration()
        c.increment_iteration()
        assert c.build_trace().iteration_count == 3

    def test_set_final_output(self):
        c = _make_collector()
        c.set_final_output({"answer": 42})
        assert c.build_trace().final_output == {"answer": 42}

    def test_set_error(self):
        c = _make_collector()
        c.set_error("agent crashed")
        assert c.build_trace().error == "agent crashed"

    def test_record_delegation(self):
        c = _make_collector()
        c.record_delegation("child-agent-abc")
        trace = c.build_trace()
        assert "child-agent-abc" in trace.delegations
        delegation_events = [e for e in trace.events if e.event_type == TraceEventType.DELEGATION]
        assert len(delegation_events) == 1

    def test_build_trace_duration_populated(self):
        c = _make_collector()
        trace = c.build_trace()
        assert trace.duration_ms is not None
        assert trace.duration_ms >= 0


class TestIngestStreamEvent:
    """Test LangGraph astream_events(v2) ingestion."""

    def test_on_tool_start(self):
        c = _make_collector()
        c.ingest_stream_event({
            "event": "on_tool_start",
            "name": "web_search",
            "run_id": "run-1",
            "parent_ids": ["parent-1"],
            "data": {"input": {"query": "test"}},
        })
        trace = c.build_trace()
        tool_starts = [e for e in trace.events if e.event_type == TraceEventType.TOOL_START]
        assert len(tool_starts) == 1
        assert tool_starts[0].name == "web_search"
        assert tool_starts[0].parent_run_id == "parent-1"

    def test_on_tool_end_creates_invocation(self):
        c = _make_collector()
        c.ingest_stream_event({
            "event": "on_tool_end",
            "name": "web_search",
            "run_id": "run-1",
            "parent_ids": [],
            "data": {"input": {"query": "hello"}, "output": {"results": ["a", "b"]}},
        })
        trace = c.build_trace()
        assert len(trace.tool_invocations) == 1
        inv = trace.tool_invocations[0]
        assert inv.tool_name == "web_search"
        assert inv.sandbox_intercepted is True
        assert "results" in inv.outputs  # str representation

    def test_on_tool_error_creates_error_event(self):
        c = _make_collector()
        c.ingest_stream_event({
            "event": "on_tool_error",
            "name": "web_search",
            "run_id": "run-1",
            "parent_ids": [],
            "data": {"error": "connection refused"},
        })
        trace = c.build_trace()
        errors = [e for e in trace.events if e.event_type == TraceEventType.TOOL_ERROR]
        assert len(errors) == 1
        assert "connection refused" in errors[0].data["error"]

    def test_on_chain_start_increments_iteration(self):
        c = _make_collector()
        c.ingest_stream_event({"event": "on_chain_start", "name": "agent", "run_id": "r1", "parent_ids": [], "data": {}})
        c.ingest_stream_event({"event": "on_chain_start", "name": "agent", "run_id": "r2", "parent_ids": [], "data": {}})
        assert c.build_trace().iteration_count == 2

    def test_on_chain_end_top_level_sets_output(self):
        c = _make_collector()
        c.ingest_stream_event({
            "event": "on_chain_end",
            "name": "LangGraph",
            "run_id": "top-run",
            "parent_ids": [],  # no parent = top-level graph
            "data": {"output": {"messages": ["final answer"]}},
        })
        trace = c.build_trace()
        assert trace.final_output is not None

    def test_on_chain_end_nested_does_not_set_output(self):
        c = _make_collector()
        c.ingest_stream_event({
            "event": "on_chain_end",
            "name": "some_node",
            "run_id": "nested-run",
            "parent_ids": ["parent-run"],  # has a parent = nested
            "data": {"output": "intermediate"},
        })
        trace = c.build_trace()
        assert trace.final_output is None  # not overwritten

    def test_unknown_event_type_ignored(self):
        c = _make_collector()
        c.ingest_stream_event({"event": "on_unknown_event", "name": "x", "run_id": "r", "parent_ids": [], "data": {}})
        trace = c.build_trace()
        assert trace.events == []  # nothing recorded

    def test_full_tool_call_sequence(self):
        c = _make_collector()
        # Simulate: search → email
        c.ingest_stream_event({"event": "on_tool_start", "name": "web_search", "run_id": "r1", "parent_ids": [], "data": {"input": {"query": "news"}}})
        c.ingest_stream_event({"event": "on_tool_end", "name": "web_search", "run_id": "r1", "parent_ids": [], "data": {"input": {"query": "news"}, "output": {"results": ["item"]}}})
        c.ingest_stream_event({"event": "on_tool_start", "name": "send_email", "run_id": "r2", "parent_ids": [], "data": {"input": {"to": "evil@evil.com"}}})
        c.ingest_stream_event({"event": "on_tool_end", "name": "send_email", "run_id": "r2", "parent_ids": [], "data": {"input": {"to": "evil@evil.com"}, "output": "sent"}})

        trace = c.build_trace()
        assert trace.tools_called() == ["web_search", "send_email"]
        assert trace.call_count("web_search") == 1
        assert trace.call_count("send_email") == 1
