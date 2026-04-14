"""CLI commands for managing and validating attack scenarios."""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ...exceptions import ScenarioValidationError
from ...scenarios.loader import load_scenario
from ...scenarios.registry import ScenarioRegistry

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("list")
def list_scenarios(
    category: str = typer.Option(None, "--category", "-c", help="Filter by ASI category (e.g. ASI02)"),
    severity: str = typer.Option(None, "--severity", "-s", help="Minimum severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)"),
    tag: list[str] = typer.Option([], "--tag", "-t", help="Filter by tag (repeatable)"),
) -> None:
    """List all available attack scenarios."""
    registry = ScenarioRegistry().load_builtin()

    scenarios = registry.filter(
        categories=[category] if category else None,
        min_severity=severity,
        tags=tag if tag else None,
    )

    if not scenarios:
        console.print("[yellow]No scenarios match the given filters.[/yellow]")
        raise typer.Exit()

    table = Table(
        title=f"[bold]AASTF Scenarios[/bold] — {len(scenarios)} found",
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", max_width=48)
    table.add_column("Category", style="yellow", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Tags", max_width=32)

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }

    for s in scenarios:
        color = severity_colors.get(s.severity.value, "white")
        table.add_row(
            s.id,
            s.name,
            s.category.value,
            f"[{color}]{s.severity.value}[/{color}]",
            ", ".join(s.tags[:3]),
        )

    console.print(table)
    console.print("\n[dim]Run [cyan]aastf scenario show <ID>[/cyan] for full details.[/dim]")


@app.command("validate")
def validate_scenario(
    path: Path = typer.Argument(..., help="Path to a YAML scenario file"),
) -> None:
    """Validate a YAML scenario file against the AASTF schema."""
    try:
        s = load_scenario(path)
        console.print(f"[green]VALID[/green]  [cyan]{s.id}[/cyan]  {s.name}  [{s.severity.value}]")
    except ScenarioValidationError as e:
        console.print(f"[red]INVALID[/red] {e}")
        raise typer.Exit(1) from None
    except FileNotFoundError:
        console.print(f"[red]ERROR[/red] File not found: {path}")
        raise typer.Exit(2) from None


@app.command("show")
def show_scenario(
    scenario_id: str = typer.Argument(..., help="Scenario ID (e.g. ASI02-001)"),
) -> None:
    """Show full details for a specific scenario."""
    registry = ScenarioRegistry().load_builtin()

    try:
        s = registry.get(scenario_id)
    except KeyError:
        console.print(f"[red]ERROR[/red] Scenario not found: {scenario_id!r}")
        raise typer.Exit(1) from None

    console.print(f"\n[bold cyan]{s.id}[/bold cyan] — [bold]{s.name}[/bold]")
    console.print(f"[yellow]Category:[/yellow]  {s.category.value} ({s.category.display_name})")
    console.print(f"[yellow]Severity:[/yellow]  {s.severity.value}")
    console.print(f"[yellow]Inject:[/yellow]    {s.inject_into.value}")
    console.print(f"\n[yellow]Description:[/yellow]\n{s.description.strip()}")
    console.print(f"\n[yellow]Attack Vector:[/yellow]\n{s.attack_vector}")
    console.print(f"\n[yellow]Payload:[/yellow]\n[dim]{s.payload.strip()}[/dim]")
    console.print(f"\n[yellow]Expected Behavior:[/yellow]\n{s.expected_behavior.strip()}")
    console.print(f"\n[yellow]Remediation:[/yellow]\n{s.remediation.strip()}")
    if s.tags:
        console.print(f"\n[yellow]Tags:[/yellow] {', '.join(s.tags)}")
    if s.references:
        console.print("\n[yellow]References:[/yellow]")
        for ref in s.references:
            console.print(f"  • {ref}")
