"""aastf benchmark — cross-model benchmark runner and comparison."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("run")
def benchmark_run(
    config: Path = typer.Option(
        ..., "--config", "-c", help="Path to benchmark config YAML file",
    ),
) -> None:
    """Execute a cross-model security benchmark."""
    if not config.exists():
        console.print(f"[red]Config not found:[/red] {config}")
        raise typer.Exit(1)

    import yaml

    from ...benchmark.runner import BenchmarkConfig, BenchmarkRunner

    raw = yaml.safe_load(config.read_text(encoding="utf-8"))
    try:
        cfg = BenchmarkConfig.model_validate(raw)
    except Exception as e:
        console.print(f"[red]Invalid config:[/red] {e}")
        raise typer.Exit(1) from None

    console.print(f"[bold]Starting benchmark[/bold] — {len(cfg.models)} models, "
                   f"{len(cfg.frameworks)} frameworks, packs={cfg.scenario_packs}")

    result = asyncio.run(BenchmarkRunner(cfg).run())

    total = result.summary.total_runs
    errored = sum(1 for e in result.results if e.verdict == "ERROR")
    out_path = cfg.output_dir / f"benchmark-{result.run_id}.json"

    # Fail honestly: if every run errored, no benchmarking actually happened
    # (direct execution from a config requires a configured agent factory per
    # model/framework — see benchmarks/README.md). Do not report success.
    if total > 0 and errored == total:
        console.print(
            f"\n[red]Benchmark produced no successful runs[/red] "
            f"({errored}/{total} errored).\n"
            "Direct execution from a benchmark config requires a configured agent "
            "factory for each (model, framework) pair; none was available, so every "
            "run was recorded as ERROR. See benchmarks/README.md."
        )
        console.print(f"[dim]All-ERROR result saved to {out_path}[/dim]")
        raise typer.Exit(1)

    console.print(f"\n[green]Benchmark complete![/green]  Run ID: {result.run_id}")
    console.print(f"Total runs: {total}" + (f"  ([yellow]{errored} errored[/yellow])" if errored else ""))

    # Print summary table
    table = Table(title="Vulnerability Rate by Model")
    table.add_column("Model", style="cyan")
    table.add_column("Vuln Rate", style="red")
    table.add_column("Mean Latency (ms)", style="yellow")
    for model, rate in sorted(result.summary.vulnerability_rate_by_model.items()):
        lat = result.summary.mean_latency_by_model.get(model, 0.0)
        table.add_row(model, f"{rate}%", f"{lat}")
    console.print(table)

    console.print(f"\n[dim]Results saved to {out_path}[/dim]")


@app.command("compare")
def benchmark_compare(
    run_a: Path = typer.Argument(..., help="Path to first benchmark result JSON"),
    run_b: Path = typer.Argument(..., help="Path to second benchmark result JSON"),
) -> None:
    """Compare two benchmark runs — detect improvements and regressions."""
    for p in (run_a, run_b):
        if not p.exists():
            console.print(f"[red]File not found:[/red] {p}")
            raise typer.Exit(1)

    from ...benchmark.runner import BenchmarkResult, compare_runs

    a = BenchmarkResult.load(run_a)
    b = BenchmarkResult.load(run_b)
    diff = compare_runs(a, b)

    console.print("\n[bold]Benchmark Comparison[/bold]")
    console.print(f"Run A: {diff.run_a_id}")
    console.print(f"Run B: {diff.run_b_id}")
    console.print(f"Unchanged: {diff.unchanged}")

    if diff.improvements:
        console.print(f"\n[green]Improvements ({len(diff.improvements)}):[/green]")
        table = Table()
        table.add_column("Model")
        table.add_column("Framework")
        table.add_column("Scenario")
        table.add_column("Before")
        table.add_column("After")
        for imp in diff.improvements:
            table.add_row(
                imp["model"], imp["framework"], imp["scenario_id"],
                imp["verdict_before"], imp["verdict_after"],
            )
        console.print(table)

    if diff.regressions:
        console.print(f"\n[red]Regressions ({len(diff.regressions)}):[/red]")
        table = Table()
        table.add_column("Model")
        table.add_column("Framework")
        table.add_column("Scenario")
        table.add_column("Before")
        table.add_column("After")
        for reg in diff.regressions:
            table.add_row(
                reg["model"], reg["framework"], reg["scenario_id"],
                reg["verdict_before"], reg["verdict_after"],
            )
        console.print(table)

    if not diff.improvements and not diff.regressions:
        console.print("\n[green]No changes detected between runs.[/green]")


@app.command("export")
def benchmark_export(
    input_file: Path = typer.Option(
        ..., "--input", "-i", help="Path to benchmark result JSON",
    ),
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Export format: markdown|csv|huggingface",
    ),
    output: Path = typer.Option(
        None, "--output", "-o",
        help="Output path (file for markdown/csv, directory for huggingface)",
    ),
) -> None:
    """Export benchmark results to various formats."""
    if not input_file.exists():
        console.print(f"[red]File not found:[/red] {input_file}")
        raise typer.Exit(1)

    from ...benchmark.reporters import CSVReporter, HuggingFaceExporter, MarkdownReporter
    from ...benchmark.runner import BenchmarkResult

    result = BenchmarkResult.load(input_file)

    if format == "markdown":
        md = MarkdownReporter.generate(result)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(md, encoding="utf-8")
            console.print(f"[green]Markdown report written:[/green] {output}")
        else:
            console.print(md)

    elif format == "csv":
        csv_str = CSVReporter.generate(result)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(csv_str, encoding="utf-8")
            console.print(f"[green]CSV report written:[/green] {output}")
        else:
            console.print(csv_str)

    elif format == "huggingface":
        out_dir = output or Path("hf-dataset")
        HuggingFaceExporter.export(result, out_dir)
        console.print(f"[green]HuggingFace dataset exported to:[/green] {out_dir}")

    else:
        console.print(f"[red]Unknown format:[/red] {format}. Supported: markdown, csv, huggingface")
        raise typer.Exit(1)
