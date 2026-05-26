"""aastf drift — detect regressions between two scan reports."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("compare")
def drift_compare(
    baseline: Path = typer.Argument(..., help="Baseline (older) report JSON file"),
    current: Path = typer.Argument(..., help="Current (newer) report JSON file"),
    output: Path = typer.Option(None, "--output", "-o", help="Write drift report JSON to file"),
    fail_on_regression: bool = typer.Option(
        False, "--fail-on-regression", help="Exit with code 1 if regressions found"
    ),
) -> None:
    """Compare two scan reports and detect drift (new vulns, severity changes, score regressions)."""
    from pydantic import ValidationError

    from ...drift import DriftDetector
    from ...models.result import ScanReport

    for p in [baseline, current]:
        if not p.exists():
            console.print(f"[red]Not found:[/red] {p}")
            raise typer.Exit(1)

    try:
        base_report = ScanReport.model_validate_json(
            baseline.read_text(encoding="utf-8")
        )
        curr_report = ScanReport.model_validate_json(
            current.read_text(encoding="utf-8")
        )
    except (ValidationError, ValueError) as e:
        console.print(f"[red]Invalid report file:[/red] {e}")
        raise typer.Exit(1) from None

    detector = DriftDetector(base_report, curr_report)
    drift_report = detector.detect()

    # Console output
    drift_label = drift_report.overall_drift.upper()
    if drift_report.overall_drift == "regressed":
        color = "red"
    elif drift_report.overall_drift == "improved":
        color = "green"
    else:
        color = "yellow"

    console.print("\n[bold]Drift Analysis[/bold]")
    console.print(f"  Baseline: {baseline.name}")
    console.print(f"  Current:  {current.name}")
    console.print(f"  Overall:  [{color}]{drift_label}[/{color}]")

    if drift_report.new_vulnerabilities:
        console.print(f"\n  [red]New vulnerabilities ({len(drift_report.new_vulnerabilities)}):[/red]")
        for item in drift_report.new_vulnerabilities:
            console.print(f"    - {item.scenario_id}: {item.description}")

    if drift_report.severity_upgrades:
        console.print(f"\n  [red]Severity upgrades ({len(drift_report.severity_upgrades)}):[/red]")
        for item in drift_report.severity_upgrades:
            console.print(f"    - {item.scenario_id}: {item.description}")

    if drift_report.score_regressions:
        console.print(f"\n  [red]Score regressions ({len(drift_report.score_regressions)}):[/red]")
        for item in drift_report.score_regressions:
            console.print(f"    - {item.scenario_id}: {item.description}")

    if drift_report.resolved:
        console.print(f"\n  [green]Resolved ({len(drift_report.resolved)}):[/green]")
        for item in drift_report.resolved:
            console.print(f"    - {item.scenario_id}: {item.description}")

    if not any([drift_report.new_vulnerabilities, drift_report.severity_upgrades,
                drift_report.score_regressions, drift_report.resolved]):
        console.print("\n  [dim]No drift detected.[/dim]")

    console.print()

    # JSON output
    if output:
        output.write_text(
            drift_report.model_dump_json(indent=2),
            encoding="utf-8",
        )
        console.print(f"[green]Drift report written:[/green] {output}")

    if fail_on_regression and detector.has_regressions():
        raise typer.Exit(1)
