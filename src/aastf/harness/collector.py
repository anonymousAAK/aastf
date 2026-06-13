"""TraceCollector — in-memory aggregator for a single scenario run."""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from ..models.trace import AgentTrace, ToolInvocation, TraceEvent, TraceEventType


class TraceCollector:
    """
    Single-scenario, single-run event collector.
    Thread-safe — uses a lock to protect shared state.

    Usage:
        collector = TraceCollector(scenario_id="ASI02-001", adapter="langgraph")
        # ... feed events via record_event / record_invocation / ingest_stream_event ...
        trace = collector.build_trace()
    """

    def __init__(self, scenario_id: str, adapter: str) -> None:
        self._scenario_id = scenario_id
        self._adapter = adapter
        self._events: list[TraceEvent] = []
        self._invocations: list[ToolInvocation] = []
        self._delegations: list[str] = []
        self._iteration_count: int = 0
        self._final_output: Any = None
        self._error: str | None = None
        self._started_at: datetime = datetime.now(timezone.utc)
        self._seq: int = 0
        self._metadata: dict[str, Any] = {}
        # Every run_id we have seen, used to reconstruct delegation chains
        # (a child run whose parent is a known run is a delegated sub-agent).
        self._seen_runs: set[str] = set()
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------ recording

    def record_event(self, event: TraceEvent) -> None:
        with self._lock:
            event.sequence = self._seq
            self._seq += 1
            self._events.append(event)

    def record_invocation(self, inv: ToolInvocation) -> None:
        with self._lock:
            inv.sequence = len(self._invocations)
            self._invocations.append(inv)

    def record_delegation(self, child_agent_id: str) -> None:
        with self._lock:
            self._delegations.append(child_agent_id)
        self.record_event(
            TraceEvent(
                event_type=TraceEventType.DELEGATION,
                run_id="delegation",
                name=child_agent_id,
            )
        )

    def increment_iteration(self) -> None:
        with self._lock:
            self._iteration_count += 1

    def set_final_output(self, output: Any) -> None:
        with self._lock:
            self._final_output = output

    def set_error(self, error: str) -> None:
        with self._lock:
            self._error = error

    def set_metadata(self, key: str, value: Any) -> None:
        """Attach an arbitrary key/value to the trace metadata."""
        with self._lock:
            self._metadata[key] = value

    def note_parentage(self, run_id: str, parent_run_id: str | None) -> None:
        """
        Record a run and (optionally) its parent. When a run's parent is itself
        a previously-seen run (i.e. a nested chain/agent), we treat the child as
        a delegation so ``delegations`` is populated for frameworks that expose
        parent_run_id chains (LangGraph, OpenAI Agents handoffs, etc.).
        """
        if not run_id:
            return
        with self._lock:
            parent_known = bool(parent_run_id) and parent_run_id in self._seen_runs
            already = run_id in self._delegations
            self._seen_runs.add(run_id)
        if parent_known and not already:
            self.record_delegation(run_id)

    # ------------------------------------------------------------------ LangGraph

    def ingest_stream_event(self, event: dict[str, Any]) -> None:
        """
        Process a raw LangGraph astream_events(version='v2') event dict.

        LangGraph v2 stream event structure:
          {
            "event": "on_tool_start" | "on_tool_end" | "on_chain_start" | ...,
            "name": "<tool or chain name>",
            "run_id": "<uuid>",
            "parent_ids": ["<parent-uuid>", ...],
            "data": { "input": ..., "output": ... },
            "tags": [...],
          }
        """
        kind: str = event.get("event", "")
        name: str = event.get("name", "")
        run_id: str = event.get("run_id", "")
        parent_ids: list[str] = event.get("parent_ids", [])
        parent_id: str | None = parent_ids[0] if parent_ids else None
        data: dict[str, Any] = event.get("data", {})

        if kind == "on_tool_start":
            self.record_event(
                TraceEvent(
                    event_type=TraceEventType.TOOL_START,
                    run_id=run_id,
                    parent_run_id=parent_id,
                    name=name,
                    data={"input": data.get("input", {})},
                )
            )

        elif kind == "on_tool_end":
            output = data.get("output")
            tool_input = data.get("input", {})
            inv = ToolInvocation(
                tool_name=name,
                tool_call_id=run_id,
                inputs=tool_input if isinstance(tool_input, dict) else {"raw": str(tool_input)},
                outputs=str(output) if output is not None else None,
                sandbox_intercepted=True,
            )
            self.record_invocation(inv)
            self.record_event(
                TraceEvent(
                    event_type=TraceEventType.TOOL_END,
                    run_id=run_id,
                    parent_run_id=parent_id,
                    name=name,
                    data={"output": str(output) if output is not None else None},
                )
            )

        elif kind == "on_tool_error":
            self.record_event(
                TraceEvent(
                    event_type=TraceEventType.TOOL_ERROR,
                    run_id=run_id,
                    parent_run_id=parent_id,
                    name=name,
                    data={"error": str(data.get("error", ""))},
                )
            )

        elif kind == "on_chain_start":
            # Each chain_start = one planning iteration
            self.increment_iteration()
            # A chain whose parent is itself a known chain is a sub-agent /
            # delegation in the run graph (ASI03 / ASI07 analysis).
            self.note_parentage(run_id, parent_id)
            self.record_event(
                TraceEvent(
                    event_type=TraceEventType.CHAIN_START,
                    run_id=run_id,
                    parent_run_id=parent_id,
                    name=name,
                )
            )

        elif kind == "on_chain_end":
            # Detect final graph output
            if name in ("LangGraph", "agent") and not parent_id:
                output = data.get("output")
                if output is not None:
                    self.set_final_output(output)
            self.record_event(
                TraceEvent(
                    event_type=TraceEventType.CHAIN_END,
                    run_id=run_id,
                    parent_run_id=parent_id,
                    name=name,
                )
            )

        elif kind == "on_llm_start":
            self.record_event(
                TraceEvent(
                    event_type=TraceEventType.LLM_START,
                    run_id=run_id,
                    parent_run_id=parent_id,
                    name=name,
                )
            )

        elif kind == "on_llm_end":
            self.record_event(
                TraceEvent(
                    event_type=TraceEventType.LLM_END,
                    run_id=run_id,
                    parent_run_id=parent_id,
                    name=name,
                )
            )

    # ------------------------------------------------------------------- build

    def build_trace(self) -> AgentTrace:
        with self._lock:
            return AgentTrace(
                scenario_id=self._scenario_id,
                adapter=self._adapter,
                started_at=self._started_at,
                ended_at=datetime.now(timezone.utc),
                events=list(self._events),
                tool_invocations=list(self._invocations),
                final_output=self._final_output,
                error=self._error,
                iteration_count=self._iteration_count,
                delegations=list(self._delegations),
                metadata=dict(self._metadata),
            )
