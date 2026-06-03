"""Pluggable provider/agent abstraction for the benchmark runner.

This module defines the contract every benchmark provider must satisfy and
ships one concrete, key-free implementation: :class:`DeterministicProvider`.

IMPORTANT — HONESTY NOTE
========================
The built-in :class:`DeterministicProvider` (a.k.a. the ``local`` / reference
provider) does NOT call any model API. It produces **synthetic, reference-only**
verdicts derived deterministically from a seed and the
``(model_id, framework, scenario_id)`` triple. These results are reproducible
fixtures used to exercise the benchmark pipeline end-to-end without network
access or API keys. They are **not** measurements of any real model or vendor
and must never be presented as such. Every artifact generated from this provider
is labelled ``synthetic``/``reference``.

Real providers (those that call an actual model API) implement the
:class:`AgentProvider` protocol and are selected by the runner via the
agent-factory contract documented in :func:`build_provider` and in
``benchmarks/README.md``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..models.scenario import AttackScenario
    from .runner import ModelConfig


# ---------------------------------------------------------------------------
# Provider outcome
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderOutcome:
    """The result of evaluating a single scenario against a provider.

    Attributes:
        verdict: A verdict string (e.g. ``"VULNERABLE"``, ``"SAFE"``). Must be a
            valid :class:`aastf.models.result.Verdict` value, never ``"ERROR"``
            for the deterministic provider (it never errors).
        latency_ms: Synthetic or measured latency in milliseconds.
        synthetic: ``True`` when the verdict is a reference fixture rather than a
            measurement of a real model. The runner propagates this flag so all
            downstream artifacts can be honestly labelled.
    """

    verdict: str
    latency_ms: float
    synthetic: bool = False


# ---------------------------------------------------------------------------
# Provider contract
# ---------------------------------------------------------------------------


@runtime_checkable
class AgentProvider(Protocol):
    """Contract for a benchmark provider.

    A provider maps a ``(model, framework, scenario)`` triple to a
    :class:`ProviderOutcome`. Implementations may call a real model API (and so
    require keys / network) or be fully synthetic like
    :class:`DeterministicProvider`.

    Agent-factory contract for REAL providers
    -----------------------------------------
    A real provider is expected to:

    1. Read its credentials from the env var named by ``model.api_key_env`` and
       fail fast (raising) if the key is missing — the runner converts raised
       exceptions into an ``ERROR`` verdict for that cell, so a missing key
       degrades a single cell rather than the whole run.
    2. Construct a framework agent for ``framework`` (the adapter name) wired to
       ``model.model_id``, drive it through the scenario payload, and return the
       evaluator verdict.
    3. Set ``synthetic=False`` on the returned :class:`ProviderOutcome`.

    Real providers are intentionally NOT shipped here (they need API keys and
    network). Register one by passing an instance to
    :class:`aastf.benchmark.runner.BenchmarkRunner`.
    """

    #: Stable identifier, also used as the ``provider`` value in configs.
    name: str

    async def evaluate(
        self,
        model: ModelConfig,
        framework: str,
        scenario: AttackScenario,
        run_index: int,
    ) -> ProviderOutcome:
        """Return the outcome for one (model, framework, scenario, run)."""
        ...


# ---------------------------------------------------------------------------
# Deterministic / reference provider (key-free, synthetic)
# ---------------------------------------------------------------------------


# Verdict pool the synthetic provider draws from. Weighted toward realistic
# distributions (more SAFE than VULNERABLE) but the exact mapping is a fixed
# function of the seeded hash, NOT a model measurement.
_VERDICT_POOL: tuple[str, ...] = (
    "SAFE",
    "SAFE",
    "SAFE",
    "VULNERABLE",
    "VULNERABLE",
    "REFUSAL_ECHO",
    "INCONCLUSIVE",
    "TOOL_POISONING",
)


class DeterministicProvider:
    """Key-free, fully reproducible synthetic provider (the ``local`` provider).

    The verdict and latency for each ``(model, framework, scenario, run)`` are a
    pure, deterministic function of a configurable ``seed`` and the triple's
    identifiers. Running the same config twice yields byte-identical results.

    These verdicts are SYNTHETIC reference fixtures — not measurements of any
    real model. ``ProviderOutcome.synthetic`` is always ``True``.
    """

    name = "local"

    def __init__(self, seed: int = 1729) -> None:
        self._seed = seed

    def _digest(self, *parts: str) -> int:
        """Stable, cross-process integer digest of the given parts.

        Uses SHA-256 (not the salted built-in ``hash``) so results are identical
        across processes and Python runs.
        """
        joined = "\x1f".join((str(self._seed), *parts))
        h = hashlib.sha256(joined.encode("utf-8")).digest()
        return int.from_bytes(h[:8], "big")

    async def evaluate(
        self,
        model: ModelConfig,
        framework: str,
        scenario: AttackScenario,
        run_index: int,
    ) -> ProviderOutcome:
        # Verdict is independent of run_index so repeats agree (stable verdict);
        # latency varies slightly per run to mimic measurement jitter while
        # staying fully deterministic.
        verdict_digest = self._digest(model.model_id, framework, scenario.id)
        verdict = _VERDICT_POOL[verdict_digest % len(_VERDICT_POOL)]

        latency_digest = self._digest(
            model.model_id, framework, scenario.id, f"run{run_index}",
        )
        # Map into a plausible 50–550 ms band.
        latency_ms = round(50.0 + (latency_digest % 50000) / 100.0, 1)

        return ProviderOutcome(verdict=verdict, latency_ms=latency_ms, synthetic=True)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_provider(provider_name: str, *, seed: int = 1729) -> AgentProvider:
    """Return a provider instance for ``provider_name``.

    Only the key-free deterministic ``local`` provider is built in. Real
    providers (``openai``, ``anthropic``, ...) require API keys and network and
    are supplied by the caller via ``BenchmarkRunner(config, provider=...)``;
    see the :class:`AgentProvider` agent-factory contract.
    """
    if provider_name == "local":
        return DeterministicProvider(seed=seed)
    raise ValueError(
        f"No built-in provider named {provider_name!r}. Only the key-free "
        "'local' (synthetic/reference) provider is built in; pass a real "
        "AgentProvider instance to BenchmarkRunner for live model APIs."
    )
