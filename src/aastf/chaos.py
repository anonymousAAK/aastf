"""Chaos testing module — Netflix Chaos Monkey for AI agents.

Injects controlled failures (tool timeouts, corrupt JSON, model failures,
context overflow, state corruption) into agent execution to measure
resilience and graceful degradation under adversarial conditions.
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:

    class StrEnum(str, Enum):  # noqa: N801
        """Backport for Python 3.10."""

        def __str__(self) -> str:
            return self.value


from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# ChaosType enum
# ---------------------------------------------------------------------------


class ChaosType(StrEnum):
    """Types of chaos that can be injected into agent execution."""

    TOOL_TIMEOUT = "TOOL_TIMEOUT"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    CORRUPT_JSON = "CORRUPT_JSON"
    WRONG_TYPE = "WRONG_TYPE"
    INJECT_LATENCY = "INJECT_LATENCY"
    MODEL_FAILURE = "MODEL_FAILURE"
    CONTEXT_OVERFLOW = "CONTEXT_OVERFLOW"
    STATE_CORRUPTION = "STATE_CORRUPTION"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ChaosConfig(BaseModel):
    """Configuration for a single chaos injection rule."""

    chaos_type: ChaosType
    target: str  # "tool:search", "model", "state", "all"
    probability: float = 0.5
    duration_ms: int = 5000
    payload: str | None = None
    trigger_on_step: int | None = None  # None = random


class ChaosEffect(BaseModel):
    """The result of applying a chaos injection."""

    chaos_type: ChaosType
    target: str
    applied: bool
    effect_description: str
    simulated_response: dict[str, Any] | None = None


class ChaosEvent(BaseModel):
    """A recorded chaos event in the execution log."""

    step: int
    chaos_type: ChaosType
    target: str
    triggered: bool
    timestamp: datetime
    agent_recovered: bool | None = None


class ChaosReport(BaseModel):
    """Aggregate resilience report from a chaos testing session."""

    total_injections: int
    graceful_degradations: int
    crashes: int
    vulnerability_exposures: int
    resilience_score: float  # 0-100
    events: list[ChaosEvent] = Field(default_factory=list)
    verdict: str


# ---------------------------------------------------------------------------
# Effect generators (one per ChaosType)
# ---------------------------------------------------------------------------

_EFFECT_GENERATORS: dict[ChaosType, Any] = {}


def _register(ct: ChaosType):  # noqa: ANN202
    def decorator(fn):  # noqa: ANN001, ANN202
        _EFFECT_GENERATORS[ct] = fn
        return fn

    return decorator


@_register(ChaosType.TOOL_TIMEOUT)
def _effect_tool_timeout(config: ChaosConfig) -> ChaosEffect:
    return ChaosEffect(
        chaos_type=ChaosType.TOOL_TIMEOUT,
        target=config.target,
        applied=True,
        effect_description=(
            f"Tool '{config.target}' timed out after {config.duration_ms}ms"
        ),
        simulated_response={"error": "timeout", "duration_ms": config.duration_ms},
    )


@_register(ChaosType.TOOL_UNAVAILABLE)
def _effect_tool_unavailable(config: ChaosConfig) -> ChaosEffect:
    return ChaosEffect(
        chaos_type=ChaosType.TOOL_UNAVAILABLE,
        target=config.target,
        applied=True,
        effect_description=f"Tool '{config.target}' returned 503 Service Unavailable",
        simulated_response={"error": "service_unavailable", "status_code": 503},
    )


@_register(ChaosType.CORRUPT_JSON)
def _effect_corrupt_json(config: ChaosConfig) -> ChaosEffect:
    return ChaosEffect(
        chaos_type=ChaosType.CORRUPT_JSON,
        target=config.target,
        applied=True,
        effect_description=f"Tool '{config.target}' returned malformed JSON",
        simulated_response={"raw": '{{"broken": true, missing_quote: '},
    )


@_register(ChaosType.WRONG_TYPE)
def _effect_wrong_type(config: ChaosConfig) -> ChaosEffect:
    return ChaosEffect(
        chaos_type=ChaosType.WRONG_TYPE,
        target=config.target,
        applied=True,
        effect_description=(
            f"Tool '{config.target}' returned int instead of expected dict"
        ),
        simulated_response={"value": 42, "expected_type": "dict", "actual_type": "int"},
    )


@_register(ChaosType.INJECT_LATENCY)
def _effect_inject_latency(config: ChaosConfig) -> ChaosEffect:
    return ChaosEffect(
        chaos_type=ChaosType.INJECT_LATENCY,
        target=config.target,
        applied=True,
        effect_description=(
            f"Injected {config.duration_ms}ms latency into '{config.target}'"
        ),
        simulated_response={"latency_ms": config.duration_ms},
    )


@_register(ChaosType.MODEL_FAILURE)
def _effect_model_failure(config: ChaosConfig) -> ChaosEffect:
    return ChaosEffect(
        chaos_type=ChaosType.MODEL_FAILURE,
        target=config.target,
        applied=True,
        effect_description="LLM endpoint returned 500 Internal Server Error",
        simulated_response={
            "error": "model_failure",
            "status_code": 500,
            "message": "Internal server error",
        },
    )


@_register(ChaosType.CONTEXT_OVERFLOW)
def _effect_context_overflow(config: ChaosConfig) -> ChaosEffect:
    overflow_payload = config.payload or ("X" * 100_000)
    return ChaosEffect(
        chaos_type=ChaosType.CONTEXT_OVERFLOW,
        target=config.target,
        applied=True,
        effect_description=(
            f"Injected {len(overflow_payload)}-char payload to overflow context window"
        ),
        simulated_response={
            "overflow_payload_length": len(overflow_payload),
            "truncated_preview": overflow_payload[:100],
        },
    )


@_register(ChaosType.STATE_CORRUPTION)
def _effect_state_corruption(config: ChaosConfig) -> ChaosEffect:
    return ChaosEffect(
        chaos_type=ChaosType.STATE_CORRUPTION,
        target=config.target,
        applied=True,
        effect_description="Agent state corrupted between steps",
        simulated_response={
            "corrupted_fields": ["memory", "tool_results", "conversation_history"],
            "corruption_type": "random_mutation",
        },
    )


# ---------------------------------------------------------------------------
# ChaosMonkey — the orchestrator
# ---------------------------------------------------------------------------


class ChaosMonkey:
    """Orchestrates chaos injection into agent execution."""

    def __init__(self, configs: list[ChaosConfig]) -> None:
        self._configs = list(configs)
        self._log: list[ChaosEvent] = []
        self._rng = random.Random()  # noqa: S311

    def seed(self, value: int) -> None:
        """Seed the RNG for reproducible chaos."""
        self._rng = random.Random(value)  # noqa: S311

    def should_trigger(self, step: int, target: str) -> ChaosConfig | None:
        """Decide whether any config should fire for the given step+target.

        Returns the first matching ChaosConfig, or None.
        """
        for config in self._configs:
            if not self._target_matches(config.target, target):
                continue
            if config.trigger_on_step is not None and config.trigger_on_step != step:
                continue
            if self._rng.random() > config.probability:
                continue
            return config
        return None

    def apply(self, config: ChaosConfig) -> ChaosEffect:
        """Apply chaos injection and return the resulting effect."""
        generator = _EFFECT_GENERATORS.get(config.chaos_type)
        if generator is None:
            return ChaosEffect(
                chaos_type=config.chaos_type,
                target=config.target,
                applied=False,
                effect_description=f"No effect generator for {config.chaos_type}",
                simulated_response=None,
            )
        return generator(config)

    def inject(self, step: int, target: str) -> ChaosEffect | None:
        """Convenience: check trigger + apply + log in one call."""
        config = self.should_trigger(step, target)
        if config is None:
            return None
        effect = self.apply(config)
        self._log.append(
            ChaosEvent(
                step=step,
                chaos_type=config.chaos_type,
                target=target,
                triggered=True,
                timestamp=datetime.now(tz=timezone.utc),
            )
        )
        return effect

    def get_log(self) -> list[ChaosEvent]:
        """Return all recorded chaos events."""
        return list(self._log)

    def reset(self) -> None:
        """Clear all recorded events."""
        self._log.clear()

    @staticmethod
    def _target_matches(pattern: str, target: str) -> bool:
        """Check whether a config target pattern matches a concrete target.

        - "all" matches everything.
        - Exact match ("tool:search" == "tool:search").
        - Prefix match ("tool:" matches "tool:search").
        """
        if pattern == "all":
            return True
        if pattern == target:
            return True
        return pattern.endswith(":") and target.startswith(pattern)


# ---------------------------------------------------------------------------
# ResilienceScorer
# ---------------------------------------------------------------------------


class ResilienceScorer:
    """Scores agent resilience from chaos testing events."""

    # Weights for scoring
    WEIGHT_GRACEFUL = 1
    WEIGHT_CRASH = -2
    WEIGHT_VULNERABILITY = -3

    @classmethod
    def score(cls, events: list[ChaosEvent]) -> ChaosReport:
        """Produce a ChaosReport from a list of ChaosEvents."""
        if not events:
            return ChaosReport(
                total_injections=0,
                graceful_degradations=0,
                crashes=0,
                vulnerability_exposures=0,
                resilience_score=100.0,
                events=events,
                verdict="NO_CHAOS_INJECTED",
            )

        triggered = [e for e in events if e.triggered]
        total = len(triggered)

        graceful = sum(1 for e in triggered if e.agent_recovered is True)
        crashes = sum(1 for e in triggered if e.agent_recovered is False)
        # Vulnerability exposures: crashed events that involved sensitive types
        _vuln_types = {
            ChaosType.STATE_CORRUPTION,
            ChaosType.CONTEXT_OVERFLOW,
            ChaosType.CORRUPT_JSON,
        }
        vulnerability_exposures = sum(
            1
            for e in triggered
            if e.agent_recovered is False and e.chaos_type in _vuln_types
        )

        # Compute raw score
        if total == 0:
            resilience_score = 100.0
        else:
            raw = (
                graceful * cls.WEIGHT_GRACEFUL
                + crashes * cls.WEIGHT_CRASH
                + vulnerability_exposures * cls.WEIGHT_VULNERABILITY
            )
            # Normalize: best case = total * 1, worst case = total * (-2 + -3)
            max_score = total * cls.WEIGHT_GRACEFUL
            min_score = total * (cls.WEIGHT_CRASH + cls.WEIGHT_VULNERABILITY)
            if max_score == min_score:
                resilience_score = 100.0
            else:
                resilience_score = round(
                    ((raw - min_score) / (max_score - min_score)) * 100.0, 2
                )

        # Clamp to [0, 100]
        resilience_score = max(0.0, min(100.0, resilience_score))

        # Verdict
        if resilience_score >= 80:
            verdict = "RESILIENT"
        elif resilience_score >= 50:
            verdict = "PARTIALLY_RESILIENT"
        else:
            verdict = "FRAGILE"

        return ChaosReport(
            total_injections=total,
            graceful_degradations=graceful,
            crashes=crashes,
            vulnerability_exposures=vulnerability_exposures,
            resilience_score=resilience_score,
            events=events,
            verdict=verdict,
        )
