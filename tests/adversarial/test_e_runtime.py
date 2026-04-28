"""
Category E — Runtime / Harness Robustness.

Hypotheses:
  E1. TraceCollector correctly handles empty/None event data.
  E2. TraceCollector.build_trace() is idempotent (callable multiple times).
  E3. TraceCollector sequence numbering is monotonically increasing.
  E4. AgentTrace.tools_called() returns tools in call order.
  E5. Evaluators do not mutate the trace or scenario passed to them.
  E6. TrendTracker handles concurrent inserts without data loss (basic test).
  E7. TrendTracker.get_run returns None for unknown run_id (not KeyError).
  E8. TrendTracker.compare raises KeyError for missing run_ids.
  E9. Runner._accumulate correctly counts all verdict types.
  E10. ScanReport counters never go negative.
  E11. custom_evaluator field in DetectionCriteria is silently ignored (BUG-03).
"""

from __future__ import annotations

import copy

import pytest

from aastf.models.result import ScanReport, TestResult, Verdict
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace, ToolInvocation, TraceEvent, TraceEventType
from aastf.harness.collector import TraceCollector

from .conftest import make_scenario, make_trace


# --------------------------------------------------------------------------- E1
class TestTraceCollector:
    """E1–E3: TraceCollector robustness."""

    def test_empty_collector_builds_trace(self):
        """Hypothesis: A freshly created collector builds a valid trace."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        trace = collector.build_trace()
        assert trace.scenario_id == "ASI01-001"
        assert trace.adapter == "test"
        assert trace.tool_invocations == []
        assert trace.events == []

    def test_ingest_unknown_event_type_is_ignored(self):
        """Hypothesis: Unknown event type in stream is silently ignored."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        # Event with unknown type should not raise
        collector.ingest_stream_event({"event": "on_unknown_event_xyz", "name": "test", "run_id": "r1"})
        trace = collector.build_trace()
        assert trace is not None

    def test_ingest_tool_start_and_end(self):
        """Hypothesis: on_tool_start + on_tool_end produces one ToolInvocation."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        collector.ingest_stream_event({
            "event": "on_tool_start",
            "name": "web_search",
            "run_id": "run-1",
            "parent_ids": [],
            "data": {"input": {"query": "test"}},
        })
        collector.ingest_stream_event({
            "event": "on_tool_end",
            "name": "web_search",
            "run_id": "run-1",
            "parent_ids": [],
            "data": {"input": {"query": "test"}, "output": {"results": []}},
        })
        trace = collector.build_trace()
        assert len(trace.tool_invocations) == 1
        assert trace.tool_invocations[0].tool_name == "web_search"

    def test_on_chain_start_increments_iteration(self):
        """Hypothesis: Each on_chain_start event increments iteration_count."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        for _ in range(5):
            collector.ingest_stream_event({
                "event": "on_chain_start",
                "name": "agent",
                "run_id": f"run-{_}",
                "parent_ids": [],
                "data": {},
            })
        trace = collector.build_trace()
        assert trace.iteration_count == 5

    def test_sequence_is_monotonically_increasing(self):
        """Hypothesis: Event sequence numbers are monotonically increasing."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        for i in range(3):
            collector.ingest_stream_event({
                "event": "on_llm_start",
                "name": f"llm_{i}",
                "run_id": f"run-{i}",
                "parent_ids": [],
                "data": {},
            })
        trace = collector.build_trace()
        seqs = [e.sequence for e in trace.events]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == len(seqs)  # all unique

    def test_set_final_output_captured(self):
        """Hypothesis: set_final_output is reflected in built trace."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        collector.set_final_output({"messages": [{"content": "done"}]})
        trace = collector.build_trace()
        assert trace.final_output is not None

    def test_set_error_captured(self):
        """Hypothesis: set_error is reflected in built trace."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        collector.set_error("Timeout after 30s")
        trace = collector.build_trace()
        assert trace.error == "Timeout after 30s"

    def test_build_trace_idempotent(self):
        """E2: Calling build_trace() twice returns consistent results."""
        collector = TraceCollector(scenario_id="ASI01-001", adapter="test")
        collector.set_final_output("done")
        t1 = collector.build_trace()
        t2 = collector.build_trace()
        assert t1.final_output == t2.final_output
        assert len(t1.events) == len(t2.events)


# --------------------------------------------------------------------------- E4
class TestAgentTrace:
    """E4: AgentTrace utility methods."""

    def test_tools_called_returns_ordered_list(self):
        """Hypothesis: tools_called() returns tool names in invocation order."""
        trace = make_trace(tools=["web_search", "send_email", "delete_file"])
        assert trace.tools_called() == ["web_search", "send_email", "delete_file"]

    def test_tool_inputs_for_filters_correctly(self):
        """Hypothesis: tool_inputs_for() returns only inputs for the named tool."""
        from aastf.models.trace import ToolInvocation
        trace = AgentTrace(
            scenario_id="test",
            adapter="test",
            tool_invocations=[
                ToolInvocation(tool_name="web_search", inputs={"query": "a"}, sequence=0),
                ToolInvocation(tool_name="send_email", inputs={"to": "b"}, sequence=1),
                ToolInvocation(tool_name="web_search", inputs={"query": "c"}, sequence=2),
            ],
        )
        inputs = trace.tool_inputs_for("web_search")
        assert len(inputs) == 2
        assert all("query" in inp for inp in inputs)

    def test_call_count_is_accurate(self):
        """Hypothesis: call_count() returns the number of times a tool was called."""
        trace = make_trace(tools=["web_search", "web_search", "send_email"])
        assert trace.call_count("web_search") == 2
        assert trace.call_count("send_email") == 1
        assert trace.call_count("delete_file") == 0

    def test_duration_ms_is_none_without_ended_at(self):
        """Hypothesis: duration_ms is None when ended_at is not set."""
        trace = AgentTrace(scenario_id="test", adapter="test")
        assert trace.duration_ms is None


# --------------------------------------------------------------------------- E5
class TestEvaluatorImmutability:
    """E5: Evaluators do not mutate the trace or scenario."""

    @pytest.mark.parametrize("cat", list(ASICategory))
    def test_evaluator_does_not_mutate_trace(self, cat):
        """Hypothesis: Evaluator.evaluate() does not modify the trace object."""
        scenario = make_scenario(cat)
        trace = make_trace(tools=["web_search"], output="test output")
        # Deep copy for comparison
        trace_before = copy.deepcopy(trace)
        ev = get_evaluator(cat)
        assert ev is not None
        ev.evaluate(scenario, trace)
        # Check key fields unchanged
        assert trace.tool_invocations == trace_before.tool_invocations
        assert trace.final_output == trace_before.final_output
        assert trace.iteration_count == trace_before.iteration_count


from aastf.scenarios.evaluators import get_evaluator


# --------------------------------------------------------------------------- E6–E8
class TestTrendTracker:
    """E6–E8: TrendTracker robustness."""

    def test_record_and_retrieve(self, tmp_path):
        """E6: Basic record/retrieve cycle works."""
        from aastf.reporting.trend_tracker import TrendTracker
        tracker = TrendTracker(db_path=tmp_path / "trend.db")
        report = ScanReport(aastf_version="0.3.0", adapter="test", total_scenarios=5)
        tracker.record(report)
        runs = tracker.last_n_runs(10)
        assert len(runs) == 1
        assert runs[0]["run_id"] == report.run_id

    def test_get_run_returns_none_for_unknown(self, tmp_path):
        """E7: get_run returns None for unknown run_id, not KeyError."""
        from aastf.reporting.trend_tracker import TrendTracker
        tracker = TrendTracker(db_path=tmp_path / "trend.db")
        result = tracker.get_run("nonexistent-id-xyz")
        assert result is None

    def test_compare_raises_for_missing_run(self, tmp_path):
        """E8: compare raises KeyError for missing run_ids."""
        from aastf.reporting.trend_tracker import TrendTracker
        tracker = TrendTracker(db_path=tmp_path / "trend.db")
        with pytest.raises(KeyError):
            tracker.compare("missing-a", "missing-b")

    def test_trend_summary_empty_db(self, tmp_path):
        """Hypothesis: trend_summary on empty DB returns no_data, not an error."""
        from aastf.reporting.trend_tracker import TrendTracker
        tracker = TrendTracker(db_path=tmp_path / "trend.db")
        summary = tracker.trend_summary()
        assert summary["trend"] == "no_data"

    def test_db_path_is_relative_to_cwd(self):
        """
        E6 INFO: TrendTracker.DEFAULT_PATH is CWD-relative (.aastf/trend.db).
        This means running from different directories creates different databases.
        Documenting this as an INFO finding.
        """
        from aastf.reporting.trend_tracker import TrendTracker
        from pathlib import Path
        assert TrendTracker.DEFAULT_PATH == Path(".aastf") / "trend.db"
        # This is not absolute — confirms CWD-relative storage


# --------------------------------------------------------------------------- E9–E10
class TestRunnerAccumulate:
    """E9–E10: Runner._accumulate correctly counts all verdict types."""

    def _make_test_result(self, verdict: Verdict) -> TestResult:
        return TestResult(
            scenario_id="ASI01-001",
            scenario_name="Test",
            category=ASICategory.ASI01,
            severity=Severity.HIGH,
            verdict=verdict,
            trace=AgentTrace(scenario_id="ASI01-001", adapter="test"),
        )

    def test_accumulate_vulnerable(self):
        from aastf.runner import Runner
        from aastf.models.config import FrameworkConfig
        config = FrameworkConfig(adapter="langgraph", agent_factory="os:getcwd")
        runner = Runner(config)
        report = ScanReport(aastf_version="0.3.0", adapter="test")
        runner._accumulate(report, self._make_test_result(Verdict.VULNERABLE))
        assert report.vulnerable == 1

    def test_accumulate_safe(self):
        from aastf.runner import Runner
        from aastf.models.config import FrameworkConfig
        config = FrameworkConfig(adapter="langgraph", agent_factory="os:getcwd")
        runner = Runner(config)
        report = ScanReport(aastf_version="0.3.0", adapter="test")
        runner._accumulate(report, self._make_test_result(Verdict.SAFE))
        assert report.safe == 1

    def test_accumulate_refusal_echo(self):
        from aastf.runner import Runner
        from aastf.models.config import FrameworkConfig
        config = FrameworkConfig(adapter="langgraph", agent_factory="os:getcwd")
        runner = Runner(config)
        report = ScanReport(aastf_version="0.3.0", adapter="test")
        runner._accumulate(report, self._make_test_result(Verdict.REFUSAL_ECHO))
        assert report.refusal_echo_count == 1

    def test_accumulate_error(self):
        from aastf.runner import Runner
        from aastf.models.config import FrameworkConfig
        config = FrameworkConfig(adapter="langgraph", agent_factory="os:getcwd")
        runner = Runner(config)
        report = ScanReport(aastf_version="0.3.0", adapter="test")
        runner._accumulate(report, self._make_test_result(Verdict.ERROR))
        assert report.errors == 1

    def test_counters_never_negative(self):
        """E10: Counters in ScanReport are non-negative after any accumulation."""
        from aastf.runner import Runner
        from aastf.models.config import FrameworkConfig
        config = FrameworkConfig(adapter="langgraph", agent_factory="os:getcwd")
        runner = Runner(config)
        report = ScanReport(aastf_version="0.3.0", adapter="test")
        for v in Verdict:
            runner._accumulate(report, self._make_test_result(v))
        assert report.vulnerable >= 0
        assert report.safe >= 0
        assert report.refusal_echo_count >= 0
        assert report.errors >= 0
        assert report.inconclusive >= 0


# --------------------------------------------------------------------------- E11
class TestCustomEvaluatorIgnored:
    """E11: custom_evaluator field is silently ignored (BUG-03)."""

    def test_custom_evaluator_field_in_scenario_is_ignored(self):
        """
        Hypothesis (BUG-03): Setting custom_evaluator='os:getcwd' in DetectionCriteria
        has no effect — it is never called by any evaluator.
        The evaluator still returns SAFE on clean trace.
        """
        from aastf.models.scenario import DetectionCriteria, AttackScenario, InjectionPoint
        scenario = AttackScenario(
            id="ASI01-001",
            name="Custom evaluator test",
            category=ASICategory.ASI01,
            severity=Severity.HIGH,
            description="test",
            attack_vector="test",
            inject_into=InjectionPoint.USER_MESSAGE,
            payload="test",
            detection=DetectionCriteria(
                custom_evaluator="os:getcwd",  # Should be called but isn't
            ),
            expected_behavior="safe",
            remediation="fix",
        )
        trace = make_trace()
        ev = get_evaluator(ASICategory.ASI01)
        result = ev.evaluate(scenario, trace)
        # custom_evaluator is ignored → SAFE (no detection criteria fire)
        assert result.verdict == Verdict.SAFE, (
            "BUG-03: custom_evaluator field is ignored; scenario returns SAFE regardless"
        )
