"""Benchmark runner — orchestrates cross-model, cross-framework security benchmarks."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from ..scenarios.registry import ScenarioRegistry
from .providers import AgentProvider, build_provider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class ModelConfig(BaseModel):
    """Configuration for a single model to benchmark."""

    name: str
    provider: str  # openai, anthropic, google, etc.
    model_id: str  # actual model identifier (e.g. gpt-4o, claude-sonnet-4-20250514)
    api_key_env: str  # env var name for API key

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, v: str) -> str:
        allowed = {"openai", "anthropic", "google", "azure", "bedrock", "local"}
        if v not in allowed:
            raise ValueError(f"provider must be one of {sorted(allowed)}, got {v!r}")
        return v


class BenchmarkConfig(BaseModel):
    """Top-level configuration for a benchmark run."""

    models: list[ModelConfig]
    frameworks: list[str]  # adapter names (langgraph, crewai, etc.)
    scenario_packs: list[str]  # scenario ID prefixes to include (e.g. ["ASI", "MCP"])
    runs_per_scenario: int = 3
    output_dir: Path = Path("benchmark-results")
    timeout_per_scenario: int = 60

    @field_validator("models")
    @classmethod
    def _at_least_one_model(cls, v: list[ModelConfig]) -> list[ModelConfig]:
        if len(v) == 0:
            raise ValueError("At least one model is required")
        return v

    @field_validator("frameworks")
    @classmethod
    def _at_least_one_framework(cls, v: list[str]) -> list[str]:
        if len(v) == 0:
            raise ValueError("At least one framework is required")
        return v

    @field_validator("scenario_packs")
    @classmethod
    def _at_least_one_pack(cls, v: list[str]) -> list[str]:
        if len(v) == 0:
            raise ValueError("At least one scenario pack is required")
        return v

    @field_validator("runs_per_scenario")
    @classmethod
    def _positive_runs(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"runs_per_scenario must be >= 1, got {v}")
        return v


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


class BenchmarkEntry(BaseModel):
    """Single data point: one model + framework + scenario + run."""

    model: str
    framework: str
    scenario_id: str
    category: str
    verdict: str
    severity: str
    latency_ms: float
    run_index: int
    # True when the verdict is a synthetic/reference fixture (deterministic
    # provider), not a measurement of a real model. Defaulted for backward
    # compatibility with previously saved results.
    synthetic: bool = False


class BenchmarkSummary(BaseModel):
    """Aggregate statistics from a benchmark run."""

    total_runs: int
    models_tested: int
    frameworks_tested: int
    scenarios_tested: int
    vulnerability_rate_by_model: dict[str, float] = Field(default_factory=dict)
    vulnerability_rate_by_category: dict[str, float] = Field(default_factory=dict)
    mean_latency_by_model: dict[str, float] = Field(default_factory=dict)


class BenchmarkResult(BaseModel):
    """Complete output of a benchmark run."""

    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # True when every entry came from the synthetic/reference (deterministic)
    # provider. Such results are reproducible fixtures, NOT real-model measurements.
    synthetic: bool = False
    config: BenchmarkConfig
    results: list[BenchmarkEntry] = Field(default_factory=list)
    summary: BenchmarkSummary = Field(
        default_factory=lambda: BenchmarkSummary(
            total_runs=0, models_tested=0, frameworks_tested=0, scenarios_tested=0,
        )
    )

    def save(self, path: Path) -> Path:
        """Persist result as JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> BenchmarkResult:
        """Load a previously saved result."""
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

# Vulnerable verdict values (strings, since BenchmarkEntry stores verdict as str)
_VULNERABLE_VERDICTS = {
    "VULNERABLE",
    "TOOL_POISONING",
    "SCHEMA_POISONING",
    "PREFERENCE_MANIPULATION",
}


class BenchmarkRunner:
    """Orchestrates cross-model, cross-framework benchmark runs.

    The runner does NOT call LLM APIs directly. It delegates to a pluggable
    :class:`aastf.benchmark.providers.AgentProvider`:

    * If a ``provider`` is supplied explicitly, it is always used.
    * Otherwise, if every configured model uses the key-free ``local`` provider,
      the built-in synthetic/reference :class:`DeterministicProvider` is wired
      automatically — so ``benchmark run`` works end-to-end with no API keys and
      produces fully reproducible (but clearly synthetic) results.
    * Otherwise (real providers requested but none injected) the runner falls
      back to the legacy adapter path, which records ERROR per cell unless a real
      agent factory is wired. Real providers should be passed via ``provider=``;
      see the :class:`AgentProvider` agent-factory contract.

    Tests can mock ``_run_single_scenario`` without touching network code.
    """

    def __init__(
        self,
        config: BenchmarkConfig,
        provider: AgentProvider | None = None,
        *,
        seed: int = 1729,
    ) -> None:
        self._config = config
        if provider is None and all(m.provider == "local" for m in config.models):
            provider = build_provider("local", seed=seed)
        self._provider = provider
        self._registry: ScenarioRegistry | None = None

    def _get_registry(self) -> ScenarioRegistry:
        """Load (and cache) the built-in scenario registry once per runner."""
        if self._registry is None:
            self._registry = ScenarioRegistry().load_builtin()
        return self._registry

    # ------------------------------------------------------------------ public

    def generate_matrix(self) -> list[tuple[ModelConfig, str, str]]:
        """Build the full (model, framework, scenario_id) cross-product."""
        scenario_ids = self._resolve_scenarios()
        matrix: list[tuple[ModelConfig, str, str]] = []
        for model in self._config.models:
            for framework in self._config.frameworks:
                for sid in scenario_ids:
                    matrix.append((model, framework, sid))
        return matrix

    async def run(self, *, run_id: str | None = None) -> BenchmarkResult:
        """Execute the full benchmark and return results.

        Args:
            run_id: When provided, pins both the run id and the started/completed
                timestamps to fixed deterministic values. Combined with the
                key-free ``local`` provider this yields a byte-identical result
                JSON across runs — used to commit a reproducible fixture.
        """
        deterministic = run_id is not None
        # Fixed epoch timestamp keeps committed fixtures byte-stable.
        fixed_ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        started_at = fixed_ts if deterministic else datetime.now(timezone.utc)
        matrix = self.generate_matrix()
        entries: list[BenchmarkEntry] = []

        total = len(matrix) * self._config.runs_per_scenario
        logger.info(
            "Benchmark: %d combos x %d runs = %d total executions",
            len(matrix), self._config.runs_per_scenario, total,
        )

        for model, framework, scenario_id in matrix:
            for run_idx in range(self._config.runs_per_scenario):
                entry = await self._run_single_scenario(
                    model, framework, scenario_id, run_idx,
                )
                entries.append(entry)

        completed_at = fixed_ts if deterministic else datetime.now(timezone.utc)
        summary = self._compute_summary(entries)

        synthetic = bool(entries) and all(e.synthetic for e in entries)

        result_kwargs: dict[str, Any] = dict(
            started_at=started_at,
            completed_at=completed_at,
            synthetic=synthetic,
            config=self._config,
            results=entries,
            summary=summary,
        )
        if run_id is not None:
            result_kwargs["run_id"] = run_id
        result = BenchmarkResult(**result_kwargs)

        # Auto-save
        self._config.output_dir.mkdir(parents=True, exist_ok=True)
        out_path = self._config.output_dir / f"benchmark-{result.run_id}.json"
        result.save(out_path)
        logger.info("Benchmark saved to %s", out_path)

        return result

    # ----------------------------------------------------------------- private

    def _resolve_scenarios(self) -> list[str]:
        """Load scenarios matching the configured packs (prefix filter)."""
        registry = self._get_registry()
        all_scenarios = registry.all()
        matched: list[str] = []
        for s in all_scenarios:
            for prefix in self._config.scenario_packs:
                if s.id.startswith(prefix):
                    matched.append(s.id)
                    break
        return sorted(matched)

    async def _run_single_scenario(
        self,
        model: ModelConfig,
        framework: str,
        scenario_id: str,
        run_index: int,
    ) -> BenchmarkEntry:
        """Run one (model, framework, scenario) combination.

        This method is the primary mock point for tests. When a provider is
        configured (the default for the key-free ``local`` provider) it is used
        directly — no NotImplementedError path. Otherwise the runner falls back
        to the legacy adapter delegation, which records ERROR unless a real agent
        factory is wired.
        """
        # Load the specific scenario (registry is cached per runner).
        registry = self._get_registry()
        scenario = registry.get(scenario_id)

        synthetic = False
        t0 = datetime.now(timezone.utc)

        if self._provider is not None:
            try:
                outcome = await self._provider.evaluate(
                    model, framework, scenario, run_index,
                )
                verdict = outcome.verdict
                latency = outcome.latency_ms
                synthetic = outcome.synthetic
            except Exception as exc:
                logger.warning(
                    "Benchmark provider error: %s / %s / %s — %s",
                    model.name, framework, scenario_id, exc,
                )
                verdict = "ERROR"
                latency = (datetime.now(timezone.utc) - t0).total_seconds() * 1000
        else:
            from ..models.config import FrameworkConfig
            from ..runner import Runner

            # Build a minimal FrameworkConfig for this combo.
            fc = FrameworkConfig(
                adapter=framework,  # type: ignore[arg-type]  # validated framework name
                agent_factory="__benchmark__:placeholder",
                timeout_seconds=self._config.timeout_per_scenario,
            )
            runner = Runner(fc)
            try:
                result = await runner._run_one(
                    backend=await self._build_harness(runner, model, framework),
                    scenario=scenario,
                )
                verdict = result.verdict.value
                latency = result.execution_time_ms
            except Exception as exc:
                logger.warning(
                    "Benchmark error: %s / %s / %s — %s",
                    model.name, framework, scenario_id, exc,
                )
                verdict = "ERROR"
                latency = (datetime.now(timezone.utc) - t0).total_seconds() * 1000

        return BenchmarkEntry(
            model=model.name,
            framework=framework,
            scenario_id=scenario_id,
            category=scenario.category.value,
            verdict=verdict,
            severity=scenario.severity.value,
            latency_ms=latency,
            run_index=run_index,
            synthetic=synthetic,
        )

    async def _build_harness(
        self, runner: Any, model: ModelConfig, framework: str,
    ) -> Any:
        """Build a framework harness configured for the given model.

        This is the legacy adapter path, used only when no
        :class:`aastf.benchmark.providers.AgentProvider` is configured. The
        preferred way to run real models is to pass a provider implementing the
        agent-factory contract to ``BenchmarkRunner(config, provider=...)``; the
        key-free ``local`` provider needs no harness at all.
        """
        raise NotImplementedError(
            "Direct benchmark execution requires either a configured AgentProvider "
            "(pass provider= to BenchmarkRunner) or a wired agent factory. The "
            "built-in 'local' provider runs key-free; see benchmarks/README.md."
        )

    def _compute_summary(self, entries: list[BenchmarkEntry]) -> BenchmarkSummary:
        """Aggregate entries into a summary."""
        if not entries:
            return BenchmarkSummary(
                total_runs=0, models_tested=0,
                frameworks_tested=0, scenarios_tested=0,
            )

        models = set()
        frameworks = set()
        scenarios = set()
        vuln_by_model: dict[str, list[bool]] = {}
        vuln_by_category: dict[str, list[bool]] = {}
        latency_by_model: dict[str, list[float]] = {}

        for e in entries:
            models.add(e.model)
            frameworks.add(e.framework)
            scenarios.add(e.scenario_id)

            is_vuln = e.verdict in _VULNERABLE_VERDICTS
            vuln_by_model.setdefault(e.model, []).append(is_vuln)
            vuln_by_category.setdefault(e.category, []).append(is_vuln)
            latency_by_model.setdefault(e.model, []).append(e.latency_ms)

        def _rate(bools: list[bool]) -> float:
            if not bools:
                return 0.0
            return round(sum(bools) / len(bools) * 100, 1)

        def _mean(nums: list[float]) -> float:
            if not nums:
                return 0.0
            return round(sum(nums) / len(nums), 1)

        return BenchmarkSummary(
            total_runs=len(entries),
            models_tested=len(models),
            frameworks_tested=len(frameworks),
            scenarios_tested=len(scenarios),
            vulnerability_rate_by_model={m: _rate(v) for m, v in vuln_by_model.items()},
            vulnerability_rate_by_category={c: _rate(v) for c, v in vuln_by_category.items()},
            mean_latency_by_model={m: _mean(v) for m, v in latency_by_model.items()},
        )


# ---------------------------------------------------------------------------
# Compare utility
# ---------------------------------------------------------------------------


class BenchmarkComparison(BaseModel):
    """Diff between two benchmark runs."""

    run_a_id: str
    run_b_id: str
    improvements: list[dict[str, Any]] = Field(default_factory=list)
    regressions: list[dict[str, Any]] = Field(default_factory=list)
    unchanged: int = 0


def compare_runs(a: BenchmarkResult, b: BenchmarkResult) -> BenchmarkComparison:
    """Compare two benchmark results, detecting improvements and regressions.

    An *improvement* is a (model, framework, scenario) triple that was vulnerable
    in run A but safe in run B. A *regression* is the reverse.

    Uses majority-vote across runs_per_scenario repeats to determine the
    dominant verdict for each triple.
    """
    def _dominant_verdicts(result: BenchmarkResult) -> dict[tuple[str, str, str], str]:
        """For each (model, framework, scenario), pick majority verdict."""
        from collections import Counter

        groups: dict[tuple[str, str, str], list[str]] = {}
        for e in result.results:
            key = (e.model, e.framework, e.scenario_id)
            groups.setdefault(key, []).append(e.verdict)
        out: dict[tuple[str, str, str], str] = {}
        for key, verdicts in groups.items():
            counter = Counter(verdicts)
            out[key] = counter.most_common(1)[0][0]
        return out

    dom_a = _dominant_verdicts(a)
    dom_b = _dominant_verdicts(b)

    all_keys = set(dom_a.keys()) | set(dom_b.keys())
    improvements: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    unchanged = 0

    for key in sorted(all_keys):
        va = dom_a.get(key, "MISSING")
        vb = dom_b.get(key, "MISSING")
        if va == vb:
            unchanged += 1
            continue

        a_vuln = va in _VULNERABLE_VERDICTS
        b_vuln = vb in _VULNERABLE_VERDICTS

        entry = {
            "model": key[0],
            "framework": key[1],
            "scenario_id": key[2],
            "verdict_before": va,
            "verdict_after": vb,
        }
        if a_vuln and not b_vuln:
            improvements.append(entry)
        elif not a_vuln and b_vuln:
            regressions.append(entry)
        # Other transitions (e.g. ERROR -> SAFE) count as unchanged for now
        else:
            unchanged += 1

    return BenchmarkComparison(
        run_a_id=a.run_id,
        run_b_id=b.run_id,
        improvements=improvements,
        regressions=regressions,
        unchanged=unchanged,
    )
