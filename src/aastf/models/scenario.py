"""Core scenario data models — the schema everything else references."""

from __future__ import annotations

import re
import sys
from enum import Enum

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    class StrEnum(str, Enum):  # noqa: N801
        """Backport for Python 3.10."""

        def __str__(self) -> str:
            return self.value
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ASICategory(StrEnum):
    ASI01 = "ASI01"  # Agent Goal Hijack
    ASI02 = "ASI02"  # Tool Misuse & Exploitation
    ASI03 = "ASI03"  # Identity & Privilege Abuse
    ASI04 = "ASI04"  # Agentic Supply Chain Vulnerabilities
    ASI05 = "ASI05"  # Unexpected Code Execution (RCE)
    ASI06 = "ASI06"  # Memory & Context Poisoning
    ASI07 = "ASI07"  # Insecure Inter-Agent Communication
    ASI08 = "ASI08"  # Cascading Failures
    ASI09 = "ASI09"  # Human-Agent Trust Exploitation
    ASI10 = "ASI10"  # Rogue Agents

    @property
    def display_name(self) -> str:
        names = {
            "ASI01": "Agent Goal Hijack",
            "ASI02": "Tool Misuse & Exploitation",
            "ASI03": "Identity & Privilege Abuse",
            "ASI04": "Agentic Supply Chain Vulnerabilities",
            "ASI05": "Unexpected Code Execution (RCE)",
            "ASI06": "Memory & Context Poisoning",
            "ASI07": "Insecure Inter-Agent Communication",
            "ASI08": "Cascading Failures",
            "ASI09": "Human-Agent Trust Exploitation",
            "ASI10": "Rogue Agents",
        }
        return names[self.value]


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def numeric(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    def __gt__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.numeric() > other.numeric()

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return self.numeric() >= other.numeric()


class InjectionPoint(StrEnum):
    USER_MESSAGE = "user_message"
    TOOL_RESPONSE = "tool_response"
    MEMORY = "memory"
    SYSTEM_PROMPT = "system_prompt"


class MCPResourceConfig(BaseModel):
    """Defines an MCP resource served by the sandbox for resource-based attacks."""

    uri: str
    content: str
    mime_type: str = "text/plain"


class ToolResponseConfig(BaseModel):
    """Defines what the sandbox returns when a specific tool is called."""

    tool_name: str
    trigger_contains: str | None = None  # only apply if request body contains this
    response_payload: Any = None
    response_mode: Literal["success", "error", "malformed", "delayed"] = "success"
    delay_seconds: float = 0.0
    call_count_limit: int | None = None  # only respond this way on first N calls
    tool_description: str | None = None  # used for schema poisoning scenarios
    tool_input_schema: dict[str, Any] | None = None  # used for schema extension attacks

    @field_validator("delay_seconds")
    @classmethod
    def _validate_delay(cls, v: float) -> float:
        if not (0 <= v <= 300):
            raise ValueError(f"delay_seconds must be between 0 and 300, got {v}")
        return v

    @field_validator("call_count_limit")
    @classmethod
    def _validate_call_count_limit(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError(f"call_count_limit must be >= 0, got {v}")
        return v

    @field_validator("trigger_contains")
    @classmethod
    def _validate_trigger_contains(cls, v: str | None) -> str | None:
        if v is not None and len(v) == 0:
            raise ValueError("trigger_contains must be a non-empty string when provided")
        return v


class DetectionCriteria(BaseModel):
    """
    Defines what constitutes a successful attack (VULNERABLE verdict).
    At least one criterion must fire for the scenario to FAIL.
    """

    # FAIL if agent called any of these tools
    tool_called: list[str] = Field(default_factory=list)
    # FAIL if agent did NOT call these tools (used for logging gap detection - ASI09)
    tool_not_called: list[str] = Field(default_factory=list)
    # FAIL if a tool was called with input containing ANY of these substrings.
    # Accepts either a single string or a list per tool; a single string is
    # normalised to a one-element list. (A previous dict[str, str] schema let
    # YAML silently collapse multiple substrings written under the same tool key
    # down to the last one, dropping most detection patterns.)
    tool_input_contains: dict[str, list[str]] = Field(default_factory=dict)
    # FAIL if total tool calls in the trace exceed this count (ASI08)
    tool_call_count_exceeds: int | None = None
    # FAIL if any of these strings appear in the agent's final output
    output_contains: list[str] = Field(default_factory=list)
    # FAIL if none of these strings appear in the agent's final output (expected safety signal absent)
    output_not_contains: list[str] = Field(default_factory=list)
    # FAIL if planning loop iterations exceed this count (ASI08)
    loop_iterations_exceed: int | None = None
    # Custom evaluator: dotted path to a Python callable(scenario, trace) -> bool
    custom_evaluator: str | None = None

    @field_validator("tool_call_count_exceeds", "loop_iterations_exceed", mode="before")
    @classmethod
    def _non_negative_threshold(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError(f"Threshold values must be non-negative integers, got: {v!r}")
        return v

    @field_validator("tool_input_contains", mode="before")
    @classmethod
    def _normalise_tool_input_contains(cls, v: object) -> object:
        """Accept either a string or a list of strings per tool; normalise to lists."""
        if isinstance(v, dict):
            return {
                key: ([val] if isinstance(val, str) else val)
                for key, val in v.items()
            }
        return v


class AttackScenario(BaseModel):
    """A single OWASP ASI attack scenario loaded from a YAML file."""

    id: str
    name: str
    category: ASICategory
    severity: Severity
    description: str
    attack_vector: str
    preconditions: list[str] = Field(default_factory=list)

    # Where the adversarial payload is injected
    inject_into: InjectionPoint
    # The injection content (may contain Jinja2 templates)
    payload: str
    # Additional payload variants for fuzzing (--run-variants flag)
    payload_variants: list[str] = Field(default_factory=list)

    # How the sandbox should respond to tool calls
    tool_responses: list[ToolResponseConfig] = Field(default_factory=list)
    # Tools available to the agent during this test
    available_tools: list[str] = Field(default_factory=list)
    # MCP resource definitions served by the sandbox
    mcp_resources: list[MCPResourceConfig] = Field(default_factory=list)

    # How to determine pass/fail
    detection: DetectionCriteria

    # Documentation
    expected_behavior: str
    remediation: str
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    author: str = "aastf-core"
    version: str = "1.0"

    # Compliance mapping metadata
    cwe_ids: list[str] = Field(default_factory=list)
    nist_ai_rmf: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def id_format(cls, v: str) -> str:
        if not re.match(r"^(ASI|MCP|CVE|MAS|A2A)\d{2}-\d{3}$", v):
            raise ValueError(
                f"Scenario ID must match ASI##-###, MCP##-###, CVE##-###, MAS##-###, "
                f"or A2A##-### format (e.g. ASI02-001), got: {v!r}"
            )
        return v
