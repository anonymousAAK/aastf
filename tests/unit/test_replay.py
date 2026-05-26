"""Tests for aastf.replay — deterministic trace record / replay."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aastf.replay import (
    DivergenceInfo,
    RecordedCall,
    ReplayTrace,
    TraceRecorder,
    TraceReplayer,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_request(model: str = "gpt-4", prompt: str = "hello") -> dict:
    return {"model": model, "messages": [{"role": "user", "content": prompt}]}


def _sample_response(text: str = "world") -> dict:
    return {"choices": [{"message": {"content": text}}]}


# ---------------------------------------------------------------------------
# TraceRecorder
# ---------------------------------------------------------------------------


class TestTraceRecorder:
    def test_record_increments_index(self, tmp_path: Path) -> None:
        rec = TraceRecorder(tmp_path / "trace.json", adapter="langgraph")
        c0 = rec.record_call("ASI01-001", "llm_inference", _sample_request(), _sample_response())
        c1 = rec.record_call("ASI01-001", "tool_call", {"tool": "x"}, {"result": "y"})
        assert c0.index == 0
        assert c1.index == 1

    def test_get_stats(self, tmp_path: Path) -> None:
        rec = TraceRecorder(tmp_path / "trace.json", adapter="crewai")
        rec.record_call("ASI01-001", "llm_inference", _sample_request(), _sample_response())
        rec.record_call("ASI02-001", "tool_call", {"tool": "a"}, {"out": "b"})
        stats = rec.get_stats()
        assert stats["total_calls"] == 2
        assert stats["scenarios_covered"] == 2
        assert stats["calls_by_type"]["llm_inference"] == 1
        assert stats["calls_by_type"]["tool_call"] == 1
        assert stats["adapter"] == "crewai"

    def test_otel_attributes_populated(self, tmp_path: Path) -> None:
        rec = TraceRecorder(tmp_path / "t.json", adapter="openai_agents")
        call = rec.record_call("ASI01-001", "llm_inference", _sample_request("gpt-4o"), _sample_response())
        assert call.otel_attributes["gen_ai.system"] == "openai_agents"
        assert call.otel_attributes["gen_ai.request.model"] == "gpt-4o"
        assert call.otel_attributes["gen_ai.operation.name"] == "llm_inference"


# ---------------------------------------------------------------------------
# Save / Load round-trip
# ---------------------------------------------------------------------------


class TestSaveLoadRoundTrip:
    def test_round_trip(self, tmp_path: Path) -> None:
        out = tmp_path / "trace.json"
        rec = TraceRecorder(out, adapter="langgraph")
        rec.record_call("ASI01-001", "llm_inference", _sample_request(), _sample_response())
        rec.record_call("ASI01-001", "tool_call", {"tool": "calc"}, {"result": 42})
        rec.save()

        assert out.exists()

        replayer = TraceReplayer(out)
        trace = replayer.load()

        assert trace.aastf_version is not None
        assert trace.adapter == "langgraph"
        assert trace.scenario_count == 1
        assert len(trace.calls) == 2
        assert trace.calls[0].call_type == "llm_inference"
        assert trace.calls[1].call_type == "tool_call"

    def test_round_trip_preserves_content(self, tmp_path: Path) -> None:
        out = tmp_path / "trace.json"
        req = _sample_request("claude-3", "summarise this")
        resp = _sample_response("done")
        rec = TraceRecorder(out, adapter="pydantic_ai")
        rec.record_call("ASI03-001", "llm_inference", req, resp)
        rec.save()

        replayer = TraceReplayer(out)
        replayer.load()
        got = replayer.get_response("ASI03-001", "llm_inference", req)
        assert got == resp

    def test_otel_resource_attributes_round_trip(self, tmp_path: Path) -> None:
        out = tmp_path / "trace.json"
        rec = TraceRecorder(out, adapter="mcp")
        rec.record_call("MCP01-001", "tool_call", {"tool": "x"}, {"ok": True})
        rec.save()

        replayer = TraceReplayer(out)
        trace = replayer.load()
        assert trace.otel_resource_attributes["service.name"] == "aastf"
        assert trace.otel_resource_attributes["telemetry.sdk.language"] == "python"


# ---------------------------------------------------------------------------
# TraceReplayer — matching
# ---------------------------------------------------------------------------


class TestTraceReplayer:
    def _build_replayer(self, tmp_path: Path, calls: list[tuple]) -> TraceReplayer:
        """Helper: write a trace with the given (scenario, type, req, resp) tuples."""
        out = tmp_path / "trace.json"
        rec = TraceRecorder(out, adapter="test")
        for scenario_id, call_type, req, resp in calls:
            rec.record_call(scenario_id, call_type, req, resp)
        rec.save()
        replayer = TraceReplayer(out)
        replayer.load()
        return replayer

    def test_get_response_matches(self, tmp_path: Path) -> None:
        req = _sample_request()
        resp = _sample_response("matched")
        replayer = self._build_replayer(tmp_path, [("ASI01-001", "llm_inference", req, resp)])
        assert replayer.get_response("ASI01-001", "llm_inference", req) == resp

    def test_get_response_returns_none_on_mismatch(self, tmp_path: Path) -> None:
        req = _sample_request("gpt-4", "hello")
        resp = _sample_response("matched")
        replayer = self._build_replayer(tmp_path, [("ASI01-001", "llm_inference", req, resp)])
        different = _sample_request("gpt-4", "different prompt")
        assert replayer.get_response("ASI01-001", "llm_inference", different) is None

    def test_get_response_returns_none_on_wrong_scenario(self, tmp_path: Path) -> None:
        req = _sample_request()
        resp = _sample_response()
        replayer = self._build_replayer(tmp_path, [("ASI01-001", "llm_inference", req, resp)])
        assert replayer.get_response("ASI99-999", "llm_inference", req) is None

    def test_sequential_replay(self, tmp_path: Path) -> None:
        """Two calls for the same scenario are replayed in order."""
        req1 = _sample_request("gpt-4", "first")
        resp1 = _sample_response("r1")
        req2 = _sample_request("gpt-4", "second")
        resp2 = _sample_response("r2")
        replayer = self._build_replayer(
            tmp_path,
            [
                ("ASI01-001", "llm_inference", req1, resp1),
                ("ASI01-001", "llm_inference", req2, resp2),
            ],
        )
        assert replayer.get_response("ASI01-001", "llm_inference", req1) == resp1
        assert replayer.get_response("ASI01-001", "llm_inference", req2) == resp2


# ---------------------------------------------------------------------------
# Divergence detection
# ---------------------------------------------------------------------------


class TestDivergenceDetection:
    def _build_replayer(self, tmp_path: Path, calls: list[tuple]) -> TraceReplayer:
        out = tmp_path / "trace.json"
        rec = TraceRecorder(out, adapter="test")
        for scenario_id, call_type, req, resp in calls:
            rec.record_call(scenario_id, call_type, req, resp)
        rec.save()
        replayer = TraceReplayer(out)
        replayer.load()
        return replayer

    def test_no_divergence_on_match(self, tmp_path: Path) -> None:
        req = _sample_request()
        resp = _sample_response()
        replayer = self._build_replayer(tmp_path, [("ASI01-001", "llm_inference", req, resp)])
        assert replayer.check_divergence("ASI01-001", "llm_inference", req) is None

    def test_request_mismatch(self, tmp_path: Path) -> None:
        req = _sample_request("gpt-4", "original")
        resp = _sample_response()
        replayer = self._build_replayer(tmp_path, [("ASI01-001", "llm_inference", req, resp)])

        different = _sample_request("gpt-4", "changed")
        div = replayer.check_divergence("ASI01-001", "llm_inference", different)
        assert div is not None
        assert div.divergence_type == "request_mismatch"
        assert div.call_index == 0
        assert div.expected_request == req
        assert div.actual_request == different

    def test_extra_call(self, tmp_path: Path) -> None:
        req = _sample_request()
        resp = _sample_response()
        replayer = self._build_replayer(tmp_path, [("ASI01-001", "llm_inference", req, resp)])
        # Consume the one recorded call
        replayer.get_response("ASI01-001", "llm_inference", req)
        # Now an extra call comes in
        extra_req = _sample_request("gpt-4", "surprise")
        div = replayer.check_divergence("ASI01-001", "llm_inference", extra_req)
        assert div is not None
        assert div.divergence_type == "extra_call"
        assert div.actual_request == extra_req
        assert div.expected_request == {}

    def test_missing_call(self, tmp_path: Path) -> None:
        req1 = _sample_request("gpt-4", "first")
        req2 = _sample_request("gpt-4", "second")
        resp = _sample_response()
        replayer = self._build_replayer(
            tmp_path,
            [
                ("ASI01-001", "llm_inference", req1, resp),
                ("ASI01-001", "llm_inference", req2, resp),
            ],
        )
        # Consume only the first call
        replayer.get_response("ASI01-001", "llm_inference", req1)
        # Scenario ends — check for missing calls
        div = replayer.check_missing_calls("ASI01-001")
        assert div is not None
        assert div.divergence_type == "missing_call"
        assert div.expected_request == req2
        assert div.actual_request == {}
        assert div.call_index == 1

    def test_no_missing_when_fully_consumed(self, tmp_path: Path) -> None:
        req = _sample_request()
        resp = _sample_response()
        replayer = self._build_replayer(tmp_path, [("ASI01-001", "llm_inference", req, resp)])
        replayer.get_response("ASI01-001", "llm_inference", req)
        assert replayer.check_missing_calls("ASI01-001") is None

    def test_no_missing_for_unknown_scenario(self, tmp_path: Path) -> None:
        replayer = self._build_replayer(tmp_path, [])
        assert replayer.check_missing_calls("ASI99-999") is None


# ---------------------------------------------------------------------------
# Empty trace
# ---------------------------------------------------------------------------


class TestEmptyTrace:
    def test_empty_save_load(self, tmp_path: Path) -> None:
        out = tmp_path / "empty.json"
        rec = TraceRecorder(out, adapter="langgraph")
        rec.save()

        replayer = TraceReplayer(out)
        trace = replayer.load()
        assert trace.scenario_count == 0
        assert trace.calls == []

    def test_empty_stats(self, tmp_path: Path) -> None:
        rec = TraceRecorder(tmp_path / "e.json")
        stats = rec.get_stats()
        assert stats["total_calls"] == 0
        assert stats["scenarios_covered"] == 0
        assert stats["calls_by_type"] == {}

    def test_get_response_on_empty(self, tmp_path: Path) -> None:
        out = tmp_path / "empty.json"
        rec = TraceRecorder(out, adapter="test")
        rec.save()
        replayer = TraceReplayer(out)
        replayer.load()
        assert replayer.get_response("ASI01-001", "llm_inference", _sample_request()) is None

    def test_check_divergence_extra_on_empty(self, tmp_path: Path) -> None:
        out = tmp_path / "empty.json"
        rec = TraceRecorder(out, adapter="test")
        rec.save()
        replayer = TraceReplayer(out)
        replayer.load()
        div = replayer.check_divergence("ASI01-001", "llm_inference", _sample_request())
        assert div is not None
        assert div.divergence_type == "extra_call"


# ---------------------------------------------------------------------------
# Pydantic model validation
# ---------------------------------------------------------------------------


class TestModels:
    def test_divergence_info_fields(self) -> None:
        d = DivergenceInfo(
            scenario_id="ASI01-001",
            call_index=3,
            expected_request={"a": 1},
            actual_request={"b": 2},
            divergence_type="request_mismatch",
        )
        assert d.scenario_id == "ASI01-001"
        assert d.call_index == 3
        assert d.divergence_type == "request_mismatch"

    def test_recorded_call_defaults(self) -> None:
        c = RecordedCall(
            index=0,
            scenario_id="ASI01-001",
            call_type="llm_inference",
            request={},
            response={},
        )
        assert c.trace_id  # auto-generated
        assert c.span_id  # auto-generated
        assert c.parent_span_id is None
        assert isinstance(c.timestamp, datetime)

    def test_replay_trace_model(self) -> None:
        t = ReplayTrace(
            aastf_version="0.7.0",
            recorded_at=datetime.now(timezone.utc),
            adapter="langgraph",
            scenario_count=5,
        )
        assert t.calls == []
        assert t.otel_resource_attributes == {}
