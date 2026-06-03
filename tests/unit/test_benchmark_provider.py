"""Tests for the pluggable benchmark provider abstraction and the key-free,
deterministic (synthetic/reference) ``local`` provider.

These cover task requirements:
- the deterministic provider is stable across runs,
- ``benchmark run`` with the deterministic config exits 0 with non-ERROR entries,
- export (markdown/csv) works on the resulting real data,
- synthetic results are clearly labelled.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aastf.benchmark.providers import (
    AgentProvider,
    DeterministicProvider,
    ProviderOutcome,
    build_provider,
)
from aastf.benchmark.reporters import CSVReporter, MarkdownReporter
from aastf.benchmark.runner import (
    BenchmarkConfig,
    BenchmarkResult,
    BenchmarkRunner,
    ModelConfig,
)
from aastf.cli.app import app

runner = CliRunner()

_REF_CONFIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "benchmarks"
    / "benchmark-local-reference.yaml"
)
_REF_RESULT_PATH = (
    Path(__file__).resolve().parents[2]
    / "benchmarks"
    / "results"
    / "local-reference.json"
)


def _local_model(model_id: str = "reference-a") -> ModelConfig:
    return ModelConfig(
        name=f"ref-{model_id}",
        provider="local",
        model_id=model_id,
        api_key_env="UNUSED_LOCAL_PROVIDER",
    )


def _local_config() -> BenchmarkConfig:
    return BenchmarkConfig(
        models=[_local_model("reference-a"), _local_model("reference-b")],
        frameworks=["langgraph", "crewai"],
        scenario_packs=["ASI01"],
        runs_per_scenario=3,
        timeout_per_scenario=30,
    )


# ---------------------------------------------------------------------------
# Provider contract
# ---------------------------------------------------------------------------


class TestProviderContract:
    def test_deterministic_provider_satisfies_protocol(self) -> None:
        assert isinstance(DeterministicProvider(), AgentProvider)

    def test_build_provider_local(self) -> None:
        p = build_provider("local")
        assert isinstance(p, DeterministicProvider)
        assert p.name == "local"

    def test_build_provider_rejects_unknown(self) -> None:
        with pytest.raises(ValueError, match="No built-in provider"):
            build_provider("openai")

    def test_outcome_is_synthetic(self) -> None:
        p = DeterministicProvider()
        from aastf.scenarios.registry import ScenarioRegistry

        scenario = ScenarioRegistry().load_builtin().get("ASI01-001")
        outcome = asyncio.run(
            p.evaluate(_local_model(), "langgraph", scenario, 0)
        )
        assert isinstance(outcome, ProviderOutcome)
        assert outcome.synthetic is True
        assert outcome.verdict != "ERROR"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_verdict_stable_across_provider_instances(self) -> None:
        from aastf.scenarios.registry import ScenarioRegistry

        scenario = ScenarioRegistry().load_builtin().get("ASI01-001")
        a = asyncio.run(DeterministicProvider().evaluate(_local_model(), "crewai", scenario, 0))
        b = asyncio.run(DeterministicProvider().evaluate(_local_model(), "crewai", scenario, 0))
        assert a.verdict == b.verdict
        assert a.latency_ms == b.latency_ms

    def test_verdict_independent_of_run_index(self) -> None:
        """Repeats of the same cell must agree on the verdict (stable verdict)."""
        from aastf.scenarios.registry import ScenarioRegistry

        scenario = ScenarioRegistry().load_builtin().get("ASI01-002")
        verdicts = {
            asyncio.run(
                DeterministicProvider().evaluate(_local_model(), "langgraph", scenario, i)
            ).verdict
            for i in range(5)
        }
        assert len(verdicts) == 1

    def test_seed_changes_results(self) -> None:
        from aastf.scenarios.registry import ScenarioRegistry

        scenarios = ScenarioRegistry().load_builtin().all()
        scenarios = [s for s in scenarios if s.id.startswith("ASI01")]

        def verdicts(seed: int) -> list[str]:
            p = DeterministicProvider(seed=seed)
            return [
                asyncio.run(p.evaluate(_local_model(), "langgraph", s, 0)).verdict
                for s in scenarios
            ]

        assert verdicts(1) != verdicts(2)

    def test_full_run_byte_identical(self) -> None:
        cfg = _local_config()
        r1 = asyncio.run(BenchmarkRunner(cfg).run(run_id="x"))
        r2 = asyncio.run(BenchmarkRunner(cfg).run(run_id="x"))
        assert r1.model_dump_json() == r2.model_dump_json()

    def test_run_marks_result_synthetic(self) -> None:
        result = asyncio.run(BenchmarkRunner(_local_config()).run(run_id="x"))
        assert result.synthetic is True
        assert all(e.synthetic for e in result.results)


# ---------------------------------------------------------------------------
# End-to-end run via the runner (no NotImplementedError path, no keys)
# ---------------------------------------------------------------------------


class TestDeterministicRun:
    def test_no_error_entries(self) -> None:
        result = asyncio.run(BenchmarkRunner(_local_config()).run(run_id="x"))
        assert len(result.results) == 2 * 2 * 13 * 3
        assert all(e.verdict != "ERROR" for e in result.results)

    def test_local_provider_auto_selected(self) -> None:
        """All-local models -> deterministic provider wired with no injection."""
        runner_obj = BenchmarkRunner(_local_config())
        assert isinstance(runner_obj._provider, DeterministicProvider)

    def test_summary_has_real_numbers(self) -> None:
        result = asyncio.run(BenchmarkRunner(_local_config()).run(run_id="x"))
        rates = result.summary.vulnerability_rate_by_model
        assert set(rates) == {"ref-reference-a", "ref-reference-b"}
        assert all(0.0 <= v <= 100.0 for v in rates.values())


# ---------------------------------------------------------------------------
# CLI: `benchmark run` exits 0 on the deterministic config
# ---------------------------------------------------------------------------


class TestCliDeterministicRun:
    def test_run_exits_zero(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(_REF_CONFIG_PATH.read_text(encoding="utf-8"))
        raw["output_dir"] = str(tmp_path / "out")
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(yaml.safe_dump(raw), encoding="utf-8")

        result = runner.invoke(app, ["benchmark", "run", "--config", str(cfg)])
        assert result.exit_code == 0, result.stdout
        assert "no successful runs" not in result.stdout
        assert "Benchmark complete" in result.stdout

    def test_shipped_reference_config_validates(self) -> None:
        cfg = BenchmarkConfig.model_validate(
            yaml.safe_load(_REF_CONFIG_PATH.read_text(encoding="utf-8"))
        )
        assert all(m.provider == "local" for m in cfg.models)


# ---------------------------------------------------------------------------
# Committed fixture + export on real data
# ---------------------------------------------------------------------------


class TestCommittedFixture:
    def test_fixture_exists_and_is_synthetic(self) -> None:
        result = BenchmarkResult.load(_REF_RESULT_PATH)
        assert result.synthetic is True
        assert result.results
        assert all(e.verdict != "ERROR" for e in result.results)
        assert all(e.synthetic for e in result.results)

    def test_fixture_matches_regeneration(self) -> None:
        """The committed JSON must equal a fresh deterministic regeneration."""
        raw = yaml.safe_load(_REF_CONFIG_PATH.read_text(encoding="utf-8"))
        cfg = BenchmarkConfig.model_validate(raw)
        fresh = asyncio.run(BenchmarkRunner(cfg).run(run_id="local-reference"))
        committed = BenchmarkResult.load(_REF_RESULT_PATH)
        # Compare the data that matters (ignore output_dir/timestamps which the
        # repro script normalizes identically).
        fresh_entries = [e.model_dump() for e in fresh.results]
        committed_entries = [e.model_dump() for e in committed.results]
        assert fresh_entries == committed_entries

    def test_markdown_export_on_real_data(self) -> None:
        result = BenchmarkResult.load(_REF_RESULT_PATH)
        md = MarkdownReporter.generate(result)
        assert "# AASTF Benchmark Report" in md
        assert "ASI01-001" in md

    def test_csv_export_on_real_data(self) -> None:
        result = BenchmarkResult.load(_REF_RESULT_PATH)
        csv_str = CSVReporter.generate(result)
        lines = csv_str.strip().split("\n")
        assert len(lines) == len(result.results) + 1  # header + rows

    def test_summary_md_numbers_match_result(self) -> None:
        """The committed summary table must reflect the committed result data."""
        result = BenchmarkResult.load(_REF_RESULT_PATH)
        summary_md = (
            _REF_RESULT_PATH.parent / "local-reference-summary.md"
        ).read_text(encoding="utf-8")
        assert "SYNTHETIC / REFERENCE" in summary_md
        assert f"Total runs: {result.summary.total_runs}" in summary_md
        for model, rate in result.summary.vulnerability_rate_by_model.items():
            assert f"| {model} | {rate}%" in summary_md


# ---------------------------------------------------------------------------
# Custom provider injection (real-provider agent-factory contract surface)
# ---------------------------------------------------------------------------


class TestCustomProviderInjection:
    def test_injected_provider_is_used(self) -> None:
        class FixedProvider:
            name = "fixed"

            async def evaluate(self, model, framework, scenario, run_index):  # noqa: ANN001
                return ProviderOutcome(verdict="SAFE", latency_ms=1.0, synthetic=False)

        cfg = _local_config()
        result = asyncio.run(BenchmarkRunner(cfg, provider=FixedProvider()).run(run_id="x"))
        assert all(e.verdict == "SAFE" for e in result.results)
        assert result.synthetic is False

    def test_provider_exception_becomes_error_entry(self) -> None:
        class BoomProvider:
            name = "boom"

            async def evaluate(self, model, framework, scenario, run_index):  # noqa: ANN001
                raise RuntimeError("no key")

        cfg = _local_config()
        result = asyncio.run(BenchmarkRunner(cfg, provider=BoomProvider()).run(run_id="x"))
        assert all(e.verdict == "ERROR" for e in result.results)
        # JSON should still be loadable
        assert json.loads(result.model_dump_json())["synthetic"] is False
