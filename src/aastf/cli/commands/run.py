"""aastf run — execute a security scan against an agent."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console

from ...models.config import FrameworkConfig
from ...models.scenario import Severity

app = typer.Typer()
console = Console()


@app.command()
def run(
    agent_module: str = typer.Argument(
        ...,
        help="Dotted path to agent factory: 'myapp.agent:create_agent'",
    ),
    adapter: str = typer.Option("langgraph", "--adapter", "-a", help="Framework adapter"),
    category: list[str] = typer.Option(
        [], "--category", "-c",
        help="ASI categories to test, e.g. --category ASI01 --category ASI02 (default: all)",
    ),
    fail_on: str = typer.Option(
        "HIGH", "--fail-on",
        help="Exit code 1 if any finding at this severity or above",
    ),
    format: list[str] = typer.Option(
        ["console", "json"], "--format", "-f",
        help="Output formats: console, json, sarif (repeatable)",
    ),
    output_dir: str = typer.Option("aastf-results", "--output-dir", "-o"),
    timeout: float = typer.Option(30.0, "--timeout", "-t", help="Per-scenario timeout (seconds)"),
    scenario_dir: list[str] = typer.Option(
        [], "--scenario-dir",
        help="Additional scenario directory (repeatable)",
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude",
        help="Scenario IDs to exclude (repeatable)",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show scenarios without executing"),
) -> None:
    """Execute a security scan against an agent system."""
    from ...models.config import FrameworkConfig

    config = FrameworkConfig(
        adapter=adapter,
        agent_factory=agent_module,
        categories=list(category),
        exclude_scenarios=list(exclude),
        scenario_dirs=list(scenario_dir),
        report_formats=list(format),
        output_dir=output_dir,
        fail_on_severity=fail_on,
        timeout_seconds=timeout,
    )

    if dry_run:
        _dry_run(config)
        return

    report = asyncio.run(_execute(config))

    # Write reports
    run_dir = Path(output_dir) / f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)

    if "json" in format or "json" in [f.lower() for f in format]:
        from ...reporting.json_reporter import JSONReporter
        out = JSONReporter().write(report, run_dir / "report.json")
        console.print(f"[dim]JSON report:[/dim] {out}")

    if "sarif" in format or "sarif" in [f.lower() for f in format]:
        from ...reporting.sarif_reporter import SARIFReporter
        out = SARIFReporter().write(report, run_dir / "results.sarif")
        console.print(f"[dim]SARIF report:[/dim] {out}")

    # Exit code logic
    fail_severity = Severity(fail_on) if fail_on else None
    if fail_severity:
        blocking = [
            f for f in report.findings
            if f.severity >= fail_severity
        ]
        if blocking:
            console.print(
                f"\n[bold red]FAILED:[/bold red] {len(blocking)} finding(s) at or above "
                f"[red]{fail_on}[/red] severity. Exit code 1."
            )
            raise typer.Exit(1)

    raise typer.Exit(0)


def _dry_run(config: FrameworkConfig) -> None:
    """Show which scenarios would run, without executing."""
    from rich.table import Table

    from ...models.scenario import ASICategory
    from ...scenarios.registry import ScenarioRegistry

    registry = ScenarioRegistry().load_builtin()
    for d in config.scenario_dirs:
        registry.load_directory(Path(d))

    categories = [ASICategory(c) for c in config.categories] if config.categories else None
    scenarios = registry.filter(categories=categories, exclude_ids=config.exclude_scenarios)

    table = Table(title=f"Dry run — {len(scenarios)} scenarios would execute")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Severity")
    for s in scenarios:
        table.add_row(s.id, s.name[:50], s.category.value, s.severity.value)
    console.print(table)


async def _execute(config: FrameworkConfig):
    from ...reporting.console_reporter import ConsoleReporter
    from ...runner import Runner

    reporter = ConsoleReporter(console)

    # Load scenarios to get count for header
    from pathlib import Path

    from ...models.scenario import ASICategory
    from ...scenarios.registry import ScenarioRegistry
    registry = ScenarioRegistry().load_builtin()
    for d in config.scenario_dirs:
        registry.load_directory(Path(d))
    categories = [ASICategory(c) for c in config.categories] if config.categories else None
    scenarios = registry.filter(categories=categories, exclude_ids=config.exclude_scenarios)

    reporter.print_header(config.adapter, len(scenarios))

    runner = Runner(config)
    report = await runner.run()

    if "console" in config.report_formats:
        reporter.print_report(report)

    return report
