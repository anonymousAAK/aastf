"""Agent execution trace models — captures everything the agent did."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TraceEventType(StrEnum):
    TOOL_START = "tool_start"
    TOOL_END = "tool_end"
    TOOL_ERROR = "tool_error"
    LLM_START = "llm_start"
    LLM_END = "llm_end"
    AGENT_ACTION = "agent_action"
    AGENT_FINISH = "agent_finish"
    CHAIN_START = "chain_start"
    CHAIN_END = "chain_end"
    DELEGATION = "delegation"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"


class ToolInvocation(BaseModel):
    """A single tool call made by the agent, as captured by the harness."""

    tool_name: str
    tool_call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    inputs: dict[str, Any] = Field(default_factory=dict)
    outputs: Any | None = None
    error: str | None = None
    duration_ms: float | None = None
    sandbox_intercepted: bool = False
    sequence: int = 0  # call order within this trace


class TraceEvent(BaseModel):
    """A single event in the agent's execution timeline."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: TraceEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    run_id: str
    parent_run_id: str | None = None  # enables delegation graph reconstruction
    name: str
    data: dict[str, Any] = Field(default_factory=dict)
    sequence: int = 0


class AgentTrace(BaseModel):
    """Complete execution trace of a single scenario run."""

    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    adapter: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ended_at: datetime | None = None
    events: list[TraceEvent] = Field(default_factory=list)
    tool_invocations: list[ToolInvocation] = Field(default_factory=list)
    final_output: Any = None
    error: str | None = None
    iteration_count: int = 0
    delegations: list[str] = Field(default_factory=list)  # child agent run IDs

    @property
    def duration_ms(self) -> float | None:
        if self.ended_at:
            return (self.ended_at - self.started_at).total_seconds() * 1000
        return None

    def tools_called(self) -> list[str]:
        """Ordered list of tool names called during this trace."""
        return [inv.tool_name for inv in self.tool_invocations]

    def tool_inputs_for(self, tool_name: str) -> list[dict[str, Any]]:
        """All input dicts for a specific tool name."""
        return [inv.inputs for inv in self.tool_invocations if inv.tool_name == tool_name]

    def call_count(self, tool_name: str) -> int:
        return sum(1 for inv in self.tool_invocations if inv.tool_name == tool_name)
