"""
Deterministic replay system for AASTF scans.

Supports two modes:
  - **Recording**: capture all LLM calls and tool responses during a scan.
  - **Replay**: substitute recorded responses for exact reproduction.

The trace format aligns with OpenTelemetry GenAI semantic conventions by
including span-like attributes (trace_id, span_id, timestamps) on each
recorded call.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from . import __version__

# ---------------------------------------------------------------------------
# Pydantic models — file format
# ---------------------------------------------------------------------------


class RecordedCall(BaseModel):
    """A single captured call (LLM inference, tool call, or tool response)."""

    index: int
    scenario_id: str
    call_type: str  # "llm_inference", "tool_call", "tool_response"
    request: dict[str, Any]
    response: dict[str, Any]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # OpenTelemetry GenAI semconv span-like attributes
    trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_span_id: str | None = None
    otel_attributes: dict[str, Any] = Field(default_factory=dict)


class DivergenceInfo(BaseModel):
    """Describes how an actual request diverged from the recorded trace."""

    scenario_id: str
    call_index: int
    expected_request: dict[str, Any]
    actual_request: dict[str, Any]
    divergence_type: str  # "missing_call", "request_mismatch", "extra_call"


class ReplayTrace(BaseModel):
    """Top-level model for a serialised replay trace file."""

    aastf_version: str
    recorded_at: datetime
    adapter: str
    scenario_count: int
    calls: list[RecordedCall] = Field(default_factory=list)

    # OpenTelemetry GenAI semconv top-level attributes
    otel_resource_attributes: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _request_fingerprint(request: dict[str, Any]) -> str:
    """Stable hash of a request dict for fast lookup."""
    raw = json.dumps(request, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# TraceRecorder
# ---------------------------------------------------------------------------


class TraceRecorder:
    """Records LLM / tool interactions during a live scan."""

    def __init__(self, output_path: Path, adapter: str = "unknown") -> None:
        self._output_path = output_path
        self._adapter = adapter
        self._calls: list[RecordedCall] = []
        self._scenario_ids: set[str] = set()
        self._counter: int = 0
        self._trace_id: str = uuid.uuid4().hex
        self._recorded_at: datetime = datetime.now(timezone.utc)

    # ---------------------------------------------------------------- public

    def record_call(
        self,
        scenario_id: str,
        call_type: str,
        request: dict[str, Any],
        response: dict[str, Any],
        *,
        parent_span_id: str | None = None,
    ) -> RecordedCall:
        """Append a call to the in-memory trace and return it."""
        call = RecordedCall(
            index=self._counter,
            scenario_id=scenario_id,
            call_type=call_type,
            request=request,
            response=response,
            trace_id=self._trace_id,
            parent_span_id=parent_span_id,
            otel_attributes={
                "gen_ai.system": self._adapter,
                "gen_ai.request.model": request.get("model", ""),
                "gen_ai.operation.name": call_type,
            },
        )
        self._calls.append(call)
        self._scenario_ids.add(scenario_id)
        self._counter += 1
        return call

    def save(self) -> Path:
        """Serialise the trace to disk as JSON and return the output path."""
        trace = ReplayTrace(
            aastf_version=__version__,
            recorded_at=self._recorded_at,
            adapter=self._adapter,
            scenario_count=len(self._scenario_ids),
            calls=self._calls,
            otel_resource_attributes={
                "service.name": "aastf",
                "service.version": __version__,
                "telemetry.sdk.language": "python",
            },
        )
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._output_path.write_text(
            trace.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return self._output_path

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics about the recorded trace."""
        by_type: dict[str, int] = {}
        for c in self._calls:
            by_type[c.call_type] = by_type.get(c.call_type, 0) + 1
        return {
            "total_calls": len(self._calls),
            "scenarios_covered": len(self._scenario_ids),
            "calls_by_type": by_type,
            "adapter": self._adapter,
            "output_path": str(self._output_path),
        }


# ---------------------------------------------------------------------------
# TraceReplayer
# ---------------------------------------------------------------------------


class TraceReplayer:
    """Replays a previously recorded trace for deterministic reproduction."""

    def __init__(self, trace_path: Path) -> None:
        self._trace_path = trace_path
        self._trace: ReplayTrace | None = None
        # Lookup structures built on load()
        self._calls_by_scenario: dict[str, list[RecordedCall]] = {}
        self._cursor: dict[str, int] = {}  # per-scenario next-call index

    # ---------------------------------------------------------------- public

    def load(self) -> ReplayTrace:
        """Read the trace file from disk and build lookup indices."""
        raw = self._trace_path.read_text(encoding="utf-8")
        self._trace = ReplayTrace.model_validate_json(raw)

        self._calls_by_scenario.clear()
        self._cursor.clear()
        for call in self._trace.calls:
            self._calls_by_scenario.setdefault(call.scenario_id, []).append(call)
        return self._trace

    def get_response(
        self,
        scenario_id: str,
        call_type: str,
        request: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Return the next recorded response if it matches, else ``None``.

        Advances the per-scenario cursor on a successful match.
        """
        calls = self._calls_by_scenario.get(scenario_id, [])
        idx = self._cursor.get(scenario_id, 0)
        if idx >= len(calls):
            return None

        expected = calls[idx]
        if expected.call_type != call_type:
            return None
        if _request_fingerprint(expected.request) != _request_fingerprint(request):
            return None

        # Match — advance cursor and return recorded response
        self._cursor[scenario_id] = idx + 1
        return expected.response

    def check_divergence(
        self,
        scenario_id: str,
        call_type: str,
        request: dict[str, Any],
    ) -> DivergenceInfo | None:
        """Check whether the current call diverges from the recording.

        Returns ``None`` when the call matches the expected recording.
        """
        calls = self._calls_by_scenario.get(scenario_id, [])
        idx = self._cursor.get(scenario_id, 0)

        # Extra call — no more recorded calls for this scenario
        if idx >= len(calls):
            return DivergenceInfo(
                scenario_id=scenario_id,
                call_index=idx,
                expected_request={},
                actual_request=request,
                divergence_type="extra_call",
            )

        expected = calls[idx]

        # Call-type or request content mismatch
        if (
            expected.call_type != call_type
            or _request_fingerprint(expected.request) != _request_fingerprint(request)
        ):
            return DivergenceInfo(
                scenario_id=scenario_id,
                call_index=idx,
                expected_request=expected.request,
                actual_request=request,
                divergence_type="request_mismatch",
            )

        return None

    def check_missing_calls(self, scenario_id: str) -> DivergenceInfo | None:
        """Check if there are unplayed calls remaining for a scenario.

        Call this after a scenario finishes to detect missing calls.
        """
        calls = self._calls_by_scenario.get(scenario_id, [])
        idx = self._cursor.get(scenario_id, 0)
        if idx < len(calls):
            expected = calls[idx]
            return DivergenceInfo(
                scenario_id=scenario_id,
                call_index=idx,
                expected_request=expected.request,
                actual_request={},
                divergence_type="missing_call",
            )
        return None

    @property
    def trace(self) -> ReplayTrace | None:
        return self._trace
