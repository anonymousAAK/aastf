"""Unit tests for trace models."""



from aastf.models.trace import AgentTrace, ToolInvocation


class TestToolInvocation:
    def test_auto_id_generated(self):
        inv = ToolInvocation(tool_name="web_search")
        assert len(inv.tool_call_id) > 0

    def test_two_invocations_have_different_ids(self):
        inv1 = ToolInvocation(tool_name="web_search")
        inv2 = ToolInvocation(tool_name="web_search")
        assert inv1.tool_call_id != inv2.tool_call_id

    def test_defaults(self):
        inv = ToolInvocation(tool_name="web_search")
        assert inv.outputs is None
        assert inv.error is None
        assert inv.duration_ms is None
        assert inv.sandbox_intercepted is False
        assert inv.sequence == 0


class TestAgentTrace:
    def test_auto_trace_id(self):
        t = AgentTrace(scenario_id="ASI01-001", adapter="test")
        assert len(t.trace_id) > 0

    def test_two_traces_different_ids(self):
        t1 = AgentTrace(scenario_id="ASI01-001", adapter="test")
        t2 = AgentTrace(scenario_id="ASI01-001", adapter="test")
        assert t1.trace_id != t2.trace_id

    def test_tools_called_empty(self):
        t = AgentTrace(scenario_id="ASI01-001", adapter="test")
        assert t.tools_called() == []

    def test_tools_called_order(self):
        t = AgentTrace(
            scenario_id="ASI02-001",
            adapter="test",
            tool_invocations=[
                ToolInvocation(tool_name="web_search", sequence=0),
                ToolInvocation(tool_name="send_email", sequence=1),
            ],
        )
        assert t.tools_called() == ["web_search", "send_email"]

    def test_tool_inputs_for(self):
        t = AgentTrace(
            scenario_id="ASI02-001",
            adapter="test",
            tool_invocations=[
                ToolInvocation(tool_name="web_search", inputs={"query": "hello"}),
                ToolInvocation(tool_name="web_search", inputs={"query": "world"}),
                ToolInvocation(tool_name="send_email", inputs={"to": "a@b.com"}),
            ],
        )
        inputs = t.tool_inputs_for("web_search")
        assert len(inputs) == 2
        assert inputs[0]["query"] == "hello"

    def test_call_count(self):
        t = AgentTrace(
            scenario_id="TEST",
            adapter="test",
            tool_invocations=[
                ToolInvocation(tool_name="web_search"),
                ToolInvocation(tool_name="web_search"),
                ToolInvocation(tool_name="send_email"),
            ],
        )
        assert t.call_count("web_search") == 2
        assert t.call_count("send_email") == 1
        assert t.call_count("nonexistent") == 0

    def test_duration_ms_none_when_not_ended(self):
        t = AgentTrace(scenario_id="TEST", adapter="test")
        assert t.duration_ms is None

    def test_duration_ms_computed(self):
        from datetime import timedelta
        t = AgentTrace(scenario_id="TEST", adapter="test")
        t.ended_at = t.started_at + timedelta(milliseconds=500)
        assert t.duration_ms is not None
        assert abs(t.duration_ms - 500.0) < 1.0
