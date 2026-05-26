"""Tests for the benchmark runner, reporters, and comparison logic."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aastf.benchmark.reporters import CSVReporter, HuggingFaceExporter, MarkdownReporter
from aastf.benchmark.runner import (
    BenchmarkConfig,
    BenchmarkEntry,
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkSummary,
    ModelConfig,
    compare_runs,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def model_gpt() -> ModelConfig:
    return ModelConfig(
        name="GPT-4o",
        provider="openai",
        model_id="gpt-4o",
        api_key_env="OPENAI_API_KEY",
    )


@pytest.fixture()
def model_claude() -> ModelConfig:
    return ModelConfig(
        name="Claude-Sonnet",
        provider="anthropic",
        model_id="claude-sonnet-4-20250514",
        api_key_env="ANTHROPIC_API_KEY",
    )


@pytest.fixture()
def basic_config(model_gpt: ModelConfig, model_claude: ModelConfig) -> BenchmarkConfig:
    return BenchmarkConfig(
        models=[model_gpt, model_claude],
        frameworks=["langgraph", "crewai"],
        scenario_packs=["ASI"],
        runs_per_scenario=2,
        output_dir=Path("/tmp/bench-test"),
        timeout_per_scenario=30,
    )


def _make_entries(
    models: list[str],
    frameworks: list[str],
    scenario_ids: list[str],
    verdict: str = "VULNERABLE",
    runs: int = 1,
) -> list[BenchmarkEntry]:
    """Helper to create BenchmarkEntry lists."""
    entries = []
    for m in models:
        for fw in frameworks:
            for sid in scenario_ids:
                for r in range(runs):
                    entries.append(BenchmarkEntry(
                        model=m,
                        framework=fw,
                        scenario_id=sid,
                        category="ASI01",
                        verdict=verdict,
                        severity="HIGH",
                        latency_ms=100.0 + r * 10,
                        run_index=r,
                    ))
    return entries


def _make_result(
    entries: list[BenchmarkEntry],
    config: BenchmarkConfig | None = None,
) -> BenchmarkResult:
    """Helper to build a BenchmarkResult with pre-set entries."""
    if config is None:
        config = BenchmarkConfig(
            models=[ModelConfig(name="test", provider="openai", model_id="test", api_key_env="X")],
            frameworks=["langgraph"],
            scenario_packs=["ASI"],
            runs_per_scenario=1,
        )
    models = {e.model for e in entries}
    frameworks = {e.framework for e in entries}
    scenarios = {e.scenario_id for e in entries}
    return BenchmarkResult(
        run_id="test-run-001",
        started_at=datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 5, 27, 12, 30, 0, tzinfo=timezone.utc),
        config=config,
        results=entries,
        summary=BenchmarkSummary(
            total_runs=len(entries),
            models_tested=len(models),
            frameworks_tested=len(frameworks),
            scenarios_tested=len(scenarios),
            vulnerability_rate_by_model={m: 50.0 for m in models},
            vulnerability_rate_by_category={"ASI01": 50.0},
            mean_latency_by_model={m: 105.0 for m in models},
        ),
    )


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestConfigValidation:
    def test_valid_config(self, basic_config: BenchmarkConfig) -> None:
        assert len(basic_config.models) == 2
        assert basic_config.runs_per_scenario == 2

    def test_invalid_provider_rejected(self) -> None:
        with pytest.raises(Exception, match="provider"):
            ModelConfig(
                name="Bad", provider="nonexistent", model_id="x", api_key_env="X",
            )

    def test_empty_models_rejected(self) -> None:
        with pytest.raises(Exception, match="At least one model"):
            BenchmarkConfig(
                models=[], frameworks=["langgraph"],
                scenario_packs=["ASI"], runs_per_scenario=1,
            )

    def test_empty_frameworks_rejected(self) -> None:
        with pytest.raises(Exception, match="At least one framework"):
            BenchmarkConfig(
                models=[ModelConfig(name="x", provider="openai", model_id="x", api_key_env="X")],
                frameworks=[], scenario_packs=["ASI"], runs_per_scenario=1,
            )

    def test_empty_packs_rejected(self) -> None:
        with pytest.raises(Exception, match="At least one scenario pack"):
            BenchmarkConfig(
                models=[ModelConfig(name="x", provider="openai", model_id="x", api_key_env="X")],
                frameworks=["langgraph"], scenario_packs=[], runs_per_scenario=1,
            )

    def test_zero_runs_rejected(self) -> None:
        with pytest.raises(Exception, match="runs_per_scenario"):
            BenchmarkConfig(
                models=[ModelConfig(name="x", provider="openai", model_id="x", api_key_env="X")],
                frameworks=["langgraph"], scenario_packs=["ASI"], runs_per_scenario=0,
            )


# ---------------------------------------------------------------------------
# Matrix generation
# ---------------------------------------------------------------------------


class TestMatrixGeneration:
    def test_matrix_dimensions(self, basic_config: BenchmarkConfig) -> None:
        """Matrix should be models x frameworks x scenarios (not x runs)."""
        runner = BenchmarkRunner(basic_config)
        matrix = runner.generate_matrix()
        # We can't predict exact scenario count, but shape is deterministic:
        # 2 models x 2 frameworks x N scenarios
        assert len(matrix) > 0
        # Every element is a (ModelConfig, str, str) tuple
        for item in matrix:
            assert len(item) == 3
            assert isinstance(item[0], ModelConfig)
            assert isinstance(item[1], str)
            assert isinstance(item[2], str)

    def test_matrix_includes_all_models(self, basic_config: BenchmarkConfig) -> None:
        runner = BenchmarkRunner(basic_config)
        matrix = runner.generate_matrix()
        model_names = {m.name for m, _, _ in matrix}
        assert "GPT-4o" in model_names
        assert "Claude-Sonnet" in model_names

    def test_matrix_includes_all_frameworks(self, basic_config: BenchmarkConfig) -> None:
        runner = BenchmarkRunner(basic_config)
        matrix = runner.generate_matrix()
        fws = {fw for _, fw, _ in matrix}
        assert "langgraph" in fws
        assert "crewai" in fws

    def test_matrix_filters_by_pack(self) -> None:
        """Only scenarios matching scenario_packs prefixes should be included."""
        cfg = BenchmarkConfig(
            models=[ModelConfig(name="x", provider="openai", model_id="x", api_key_env="X")],
            frameworks=["langgraph"],
            scenario_packs=["MCP"],
            runs_per_scenario=1,
        )
        runner = BenchmarkRunner(cfg)
        matrix = runner.generate_matrix()
        for _, _, sid in matrix:
            assert sid.startswith("MCP"), f"Unexpected scenario {sid} for pack MCP"


# ---------------------------------------------------------------------------
# BenchmarkResult serialization
# ---------------------------------------------------------------------------


class TestResultSerialization:
    def test_round_trip_json(self, tmp_path: Path) -> None:
        entries = _make_entries(["ModelA"], ["fw1"], ["ASI01-001"])
        result = _make_result(entries)

        path = tmp_path / "result.json"
        result.save(path)
        assert path.exists()

        loaded = BenchmarkResult.load(path)
        assert loaded.run_id == result.run_id
        assert len(loaded.results) == len(result.results)
        assert loaded.summary.total_runs == result.summary.total_runs

    def test_json_contains_entries(self, tmp_path: Path) -> None:
        entries = _make_entries(["A", "B"], ["fw"], ["ASI01-001"], runs=2)
        result = _make_result(entries)
        path = tmp_path / "r.json"
        result.save(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert len(raw["results"]) == 4  # 2 models x 1 fw x 1 scenario x 2 runs


# ---------------------------------------------------------------------------
# Markdown reporter
# ---------------------------------------------------------------------------


class TestMarkdownReporter:
    def test_contains_header(self) -> None:
        entries = _make_entries(["GPT-4o"], ["langgraph"], ["ASI01-001"])
        result = _make_result(entries)
        md = MarkdownReporter.generate(result)
        assert "# AASTF Benchmark Report" in md

    def test_contains_model_table(self) -> None:
        entries = _make_entries(["GPT-4o"], ["langgraph"], ["ASI01-001"])
        result = _make_result(entries)
        md = MarkdownReporter.generate(result)
        assert "| GPT-4o |" in md
        assert "Vulnerability Rate by Model" in md

    def test_contains_category_table(self) -> None:
        entries = _make_entries(["GPT-4o"], ["langgraph"], ["ASI01-001"])
        result = _make_result(entries)
        md = MarkdownReporter.generate(result)
        assert "Vulnerability Rate by Category" in md
        assert "| ASI01 |" in md

    def test_contains_detail_rows(self) -> None:
        entries = _make_entries(["M"], ["fw"], ["ASI01-001"], runs=3)
        result = _make_result(entries)
        md = MarkdownReporter.generate(result)
        assert "Detailed Results" in md
        assert "ASI01-001" in md

    def test_truncates_large_results(self) -> None:
        """More than 50 entries should show truncation notice."""
        entries = _make_entries(["M"], ["fw"], [f"ASI01-{i:03d}" for i in range(1, 61)])
        result = _make_result(entries)
        md = MarkdownReporter.generate(result)
        assert "Showing 50 of 60 results" in md


# ---------------------------------------------------------------------------
# CSV reporter
# ---------------------------------------------------------------------------


class TestCSVReporter:
    def test_csv_header(self) -> None:
        entries = _make_entries(["M"], ["fw"], ["ASI01-001"])
        result = _make_result(entries)
        csv_str = CSVReporter.generate(result)
        reader = csv.reader(io.StringIO(csv_str))
        header = next(reader)
        assert header == [
            "model", "framework", "scenario_id", "category",
            "verdict", "severity", "latency_ms", "run_index",
        ]

    def test_csv_row_count(self) -> None:
        entries = _make_entries(["A", "B"], ["fw"], ["ASI01-001"], runs=3)
        result = _make_result(entries)
        csv_str = CSVReporter.generate(result)
        lines = csv_str.strip().split("\n")
        assert len(lines) == 7  # 1 header + 6 data (2 models x 1 fw x 1 scenario x 3 runs)

    def test_csv_values(self) -> None:
        entries = _make_entries(["ModelX"], ["crewai"], ["ASI01-001"], verdict="SAFE")
        result = _make_result(entries)
        csv_str = CSVReporter.generate(result)
        reader = csv.reader(io.StringIO(csv_str))
        next(reader)  # skip header
        row = next(reader)
        assert row[0] == "ModelX"
        assert row[1] == "crewai"
        assert row[4] == "SAFE"


# ---------------------------------------------------------------------------
# HuggingFace export
# ---------------------------------------------------------------------------


class TestHuggingFaceExporter:
    def test_creates_expected_files(self, tmp_path: Path) -> None:
        entries = _make_entries(["M"], ["fw"], ["ASI01-001"])
        result = _make_result(entries)
        out_dir = tmp_path / "hf"
        HuggingFaceExporter.export(result, out_dir)

        assert (out_dir / "data.json").exists()
        assert (out_dir / "dataset_infos.json").exists()
        assert (out_dir / "README.md").exists()

    def test_data_json_is_jsonlines(self, tmp_path: Path) -> None:
        entries = _make_entries(["A", "B"], ["fw"], ["ASI01-001"])
        result = _make_result(entries)
        out_dir = tmp_path / "hf"
        HuggingFaceExporter.export(result, out_dir)

        lines = (out_dir / "data.json").read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        row = json.loads(lines[0])
        assert "model" in row
        assert "verdict" in row

    def test_dataset_infos_structure(self, tmp_path: Path) -> None:
        entries = _make_entries(["M"], ["fw"], ["ASI01-001"], runs=5)
        result = _make_result(entries)
        out_dir = tmp_path / "hf"
        HuggingFaceExporter.export(result, out_dir)

        infos = json.loads((out_dir / "dataset_infos.json").read_text(encoding="utf-8"))
        assert "default" in infos
        assert infos["default"]["num_rows"] == 5
        assert "features" in infos["default"]
        assert "model" in infos["default"]["features"]

    def test_readme_has_dataset_card(self, tmp_path: Path) -> None:
        entries = _make_entries(["M"], ["fw"], ["ASI01-001"])
        result = _make_result(entries)
        out_dir = tmp_path / "hf"
        HuggingFaceExporter.export(result, out_dir)

        readme = (out_dir / "README.md").read_text(encoding="utf-8")
        assert "AASTF Security Benchmark Dataset" in readme
        assert "license: mit" in readme
        assert "agentic-ai" in readme


# ---------------------------------------------------------------------------
# Compare runs
# ---------------------------------------------------------------------------


class TestCompareRuns:
    def test_identical_runs_no_changes(self) -> None:
        entries = _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="VULNERABLE")
        a = _make_result(entries)
        b = _make_result(entries)
        b.run_id = "run-b"
        diff = compare_runs(a, b)
        assert len(diff.improvements) == 0
        assert len(diff.regressions) == 0
        assert diff.unchanged == 1

    def test_detects_improvement(self) -> None:
        entries_a = _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="VULNERABLE")
        entries_b = _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="SAFE")
        a = _make_result(entries_a)
        b = _make_result(entries_b)
        b.run_id = "run-b"
        diff = compare_runs(a, b)
        assert len(diff.improvements) == 1
        assert diff.improvements[0]["verdict_before"] == "VULNERABLE"
        assert diff.improvements[0]["verdict_after"] == "SAFE"

    def test_detects_regression(self) -> None:
        entries_a = _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="SAFE")
        entries_b = _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="VULNERABLE")
        a = _make_result(entries_a)
        b = _make_result(entries_b)
        b.run_id = "run-b"
        diff = compare_runs(a, b)
        assert len(diff.regressions) == 1
        assert diff.regressions[0]["verdict_before"] == "SAFE"
        assert diff.regressions[0]["verdict_after"] == "VULNERABLE"

    def test_majority_vote(self) -> None:
        """With 3 runs, majority verdict should win."""
        # Run A: 2 VULNERABLE, 1 SAFE -> majority = VULNERABLE
        entries_a = [
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="VULNERABLE", severity="HIGH",
                           latency_ms=100, run_index=0),
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="VULNERABLE", severity="HIGH",
                           latency_ms=110, run_index=1),
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="SAFE", severity="HIGH",
                           latency_ms=120, run_index=2),
        ]
        # Run B: 2 SAFE, 1 VULNERABLE -> majority = SAFE
        entries_b = [
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="SAFE", severity="HIGH",
                           latency_ms=100, run_index=0),
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="SAFE", severity="HIGH",
                           latency_ms=110, run_index=1),
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="VULNERABLE", severity="HIGH",
                           latency_ms=120, run_index=2),
        ]
        a = _make_result(entries_a)
        b = _make_result(entries_b)
        b.run_id = "run-b"
        diff = compare_runs(a, b)
        assert len(diff.improvements) == 1
        assert len(diff.regressions) == 0

    def test_mixed_changes(self) -> None:
        """Multiple scenarios: some improve, some regress, some unchanged."""
        entries_a = (
            _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="VULNERABLE")
            + _make_entries(["M"], ["fw"], ["ASI01-002"], verdict="SAFE")
            + _make_entries(["M"], ["fw"], ["ASI01-003"], verdict="SAFE")
        )
        entries_b = (
            _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="SAFE")  # improvement
            + _make_entries(["M"], ["fw"], ["ASI01-002"], verdict="VULNERABLE")  # regression
            + _make_entries(["M"], ["fw"], ["ASI01-003"], verdict="SAFE")  # unchanged
        )
        a = _make_result(entries_a)
        b = _make_result(entries_b)
        b.run_id = "run-b"
        diff = compare_runs(a, b)
        assert len(diff.improvements) == 1
        assert len(diff.regressions) == 1
        assert diff.unchanged == 1


# ---------------------------------------------------------------------------
# Summary computation
# ---------------------------------------------------------------------------


class TestSummaryComputation:
    def test_vulnerability_rate(self) -> None:
        runner = BenchmarkRunner(BenchmarkConfig(
            models=[ModelConfig(name="M", provider="openai", model_id="x", api_key_env="X")],
            frameworks=["langgraph"],
            scenario_packs=["ASI"],
            runs_per_scenario=1,
        ))
        entries = (
            _make_entries(["M"], ["fw"], ["ASI01-001"], verdict="VULNERABLE")
            + _make_entries(["M"], ["fw"], ["ASI01-002"], verdict="SAFE")
        )
        summary = runner._compute_summary(entries)
        assert summary.vulnerability_rate_by_model["M"] == 50.0

    def test_mean_latency(self) -> None:
        runner = BenchmarkRunner(BenchmarkConfig(
            models=[ModelConfig(name="M", provider="openai", model_id="x", api_key_env="X")],
            frameworks=["langgraph"],
            scenario_packs=["ASI"],
            runs_per_scenario=1,
        ))
        entries = [
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="SAFE", severity="HIGH",
                           latency_ms=200.0, run_index=0),
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-002",
                           category="ASI01", verdict="SAFE", severity="HIGH",
                           latency_ms=400.0, run_index=0),
        ]
        summary = runner._compute_summary(entries)
        assert summary.mean_latency_by_model["M"] == 300.0

    def test_empty_entries(self) -> None:
        runner = BenchmarkRunner(BenchmarkConfig(
            models=[ModelConfig(name="M", provider="openai", model_id="x", api_key_env="X")],
            frameworks=["langgraph"],
            scenario_packs=["ASI"],
            runs_per_scenario=1,
        ))
        summary = runner._compute_summary([])
        assert summary.total_runs == 0
        assert summary.models_tested == 0

    def test_mcp_verdicts_count_as_vulnerable(self) -> None:
        """TOOL_POISONING etc should count in vulnerability rate."""
        runner = BenchmarkRunner(BenchmarkConfig(
            models=[ModelConfig(name="M", provider="openai", model_id="x", api_key_env="X")],
            frameworks=["langgraph"],
            scenario_packs=["ASI"],
            runs_per_scenario=1,
        ))
        entries = [
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-001",
                           category="ASI01", verdict="TOOL_POISONING", severity="HIGH",
                           latency_ms=100, run_index=0),
            BenchmarkEntry(model="M", framework="fw", scenario_id="ASI01-002",
                           category="ASI01", verdict="SAFE", severity="HIGH",
                           latency_ms=100, run_index=0),
        ]
        summary = runner._compute_summary(entries)
        assert summary.vulnerability_rate_by_model["M"] == 50.0
