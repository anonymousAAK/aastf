"""CLI-level tests for `aastf benchmark`."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from aastf.cli.app import app

runner = CliRunner()

_MIN_CONFIG = """\
models:
  - {{name: gpt-4o, provider: openai, model_id: gpt-4o, api_key_env: OPENAI_API_KEY}}
frameworks: [langgraph]
scenario_packs: [ASI01]
runs_per_scenario: 1
output_dir: {out}
"""


def test_benchmark_run_fails_honestly_when_all_runs_error(tmp_path: Path):
    """Without a configured agent factory every run errors; the command must
    exit non-zero and NOT report success (regression for the stub that printed
    'Benchmark complete!' and exited 0)."""
    cfg = tmp_path / "bench.yaml"
    cfg.write_text(_MIN_CONFIG.format(out=tmp_path / "out"))

    result = runner.invoke(app, ["benchmark", "run", "--config", str(cfg)])

    assert result.exit_code == 1
    assert "no successful runs" in result.stdout
    assert "Benchmark complete" not in result.stdout


def test_benchmark_run_rejects_invalid_config(tmp_path: Path):
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("frameworks: [langgraph]\n")  # missing models / scenario_packs
    result = runner.invoke(app, ["benchmark", "run", "--config", str(cfg)])
    assert result.exit_code == 1
    assert "Invalid config" in result.stdout


def test_shipped_8x4_config_validates():
    """The committed benchmark-8x4.yaml must validate against BenchmarkConfig."""
    import yaml

    from aastf.benchmark.runner import BenchmarkConfig

    path = Path(__file__).resolve().parents[2] / "benchmarks" / "benchmark-8x4.yaml"
    cfg = BenchmarkConfig.model_validate(yaml.safe_load(path.read_text()))
    assert len(cfg.models) == 8
    assert len(cfg.frameworks) == 4
