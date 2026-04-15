"""aastf report — render and compare scan reports."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("show")
def show_report(
    report_path: Path = typer.Argument(..., help="Path to a report.json file"),
    format: str = typer.Option("console", "--format", "-f", help="Output format: console|html|sarif"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Re-render a scan report in a different format."""
    if not report_path.exists():
        console.print(f"[red]Report not found:[/red] {report_path}")
        raise typer.Exit(1)

    from ...models.result import ScanReport
    report = ScanReport.model_validate_json(report_path.read_text(encoding="utf-8"))

    if format == "console":
        from ...reporting.console_reporter import ConsoleReporter
        ConsoleReporter(console).print_report(report)
    elif format == "html":
        from ...reporting.html_reporter import HTMLReporter
        out = output or report_path.with_suffix(".html")
        HTMLReporter().write(report, out)
        console.print(f"[green]HTML report written:[/green] {out}")
    elif format == "sarif":
        from ...reporting.sarif_reporter import SARIFReporter
        out = output or report_path.with_suffix(".sarif")
        SARIFReporter().write(report, out)
        console.print(f"[green]SARIF report written:[/green] {out}")
    else:
        console.print(f"[red]Unknown format:[/red] {format}")
        raise typer.Exit(1)


@app.command("compare")
def compare_reports(
    report_a: Path = typer.Argument(..., help="First (newer) report.json"),
    report_b: Path = typer.Argument(..., help="Second (older) report.json"),
) -> None:
    """Compare two scan reports and show the vulnerability delta."""
    from ...models.result import ScanReport, Verdict

    for p in [report_a, report_b]:
        if not p.exists():
            console.print(f"[red]Not found:[/red] {p}")
            raise typer.Exit(1)

    a = ScanReport.model_validate_json(report_a.read_text(encoding="utf-8"))
    b = ScanReport.model_validate_json(report_b.read_text(encoding="utf-8"))

    delta_risk = a.overall_risk_score - b.overall_risk_score
    delta_vuln = a.vulnerable - b.vulnerable

    risk_arrow = "[red]↑[/red]" if delta_risk > 0 else "[green]↓[/green]" if delta_risk < 0 else "→"
    vuln_arrow = "[red]↑[/red]" if delta_vuln > 0 else "[green]↓[/green]" if delta_vuln < 0 else "→"

    console.print("\n[bold]Report Comparison[/bold]")
    console.print(f"  A (newer): {report_a.name}  Risk: {a.overall_risk_score:.1f}  Vulnerable: {a.vulnerable}")
    console.print(f"  B (older): {report_b.name}  Risk: {b.overall_risk_score:.1f}  Vulnerable: {b.vulnerable}")
    console.print(f"\n  Risk Score delta: {risk_arrow} {abs(delta_risk):.1f}")
    console.print(f"  Vulnerable delta: {vuln_arrow} {abs(delta_vuln)}")

    a_ids = {f.scenario_id for f in a.findings if f.verdict == Verdict.VULNERABLE}
    b_ids = {f.scenario_id for f in b.findings if f.verdict == Verdict.VULNERABLE}
    new_vulns = a_ids - b_ids
    resolved = b_ids - a_ids

    if new_vulns:
        console.print(f"\n  [red]New vulnerabilities:[/red] {', '.join(sorted(new_vulns))}")
    if resolved:
        console.print(f"  [green]Resolved:[/green] {', '.join(sorted(resolved))}")
    if not new_vulns and not resolved:
        console.print("\n  [dim]No change in vulnerability set.[/dim]")
    console.print()


@app.command("trend")
def show_trend(
    n: int = typer.Option(10, "--runs", "-n", help="Number of recent runs to show"),
    db: Path = typer.Option(None, "--db", help="Path to trend database"),
) -> None:
    """Show vulnerability trend across recent runs."""
    from ...reporting.trend_tracker import TrendTracker

    tracker = TrendTracker(db)
    summary = tracker.trend_summary(n)

    if summary["runs"] == 0:
        console.print("[yellow]No runs recorded yet.[/yellow]")
        console.print("Run [cyan]aastf run[/cyan] to start tracking.")
        return

    console.print(f"\n[bold]Trend Summary[/bold] (last {summary['runs']} runs)")
    console.print(f"  Latest risk score:  {summary['latest_risk_score']:.1f}")
    console.print(f"  Average risk score: {summary['average_risk_score']:.1f}")
    console.print(f"  Avg vulnerability rate: {summary['average_vulnerability_rate']:.1f}%")
    trend_color = "green" if summary["trend"] == "improving" else "red" if summary["trend"] == "worsening" else "yellow"
    console.print(f"  Trend: [{trend_color}]{summary['trend'].upper()}[/{trend_color}]")
