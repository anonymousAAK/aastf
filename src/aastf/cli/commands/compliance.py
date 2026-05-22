"""aastf compliance — generate regulatory compliance reports."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("eu-ai-act")
def eu_ai_act_report(
    report_path: Path = typer.Argument(..., help="Path to a scan report JSON file"),
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Output format: markdown|json"
    ),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate EU AI Act Article 50 compliance report from scan results."""
    if not report_path.exists():
        console.print(f"[red]Report not found:[/red] {report_path}")
        raise typer.Exit(1)

    from pydantic import ValidationError

    from ...compliance.eu_ai_act import EUAIActReporter
    from ...models.result import ScanReport

    try:
        report = ScanReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    except (ValidationError, ValueError) as e:
        console.print(f"[red]Invalid report file:[/red] {e}")
        raise typer.Exit(1) from None

    reporter = EUAIActReporter()

    if format == "json":
        if output:
            reporter.write(report, output)
            console.print(f"[green]EU AI Act compliance report written:[/green] {output}")
        else:
            console.print(reporter.generate_json(report))
    elif format == "markdown":
        md = reporter.generate_markdown(report)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(md, encoding="utf-8")
            console.print(f"[green]EU AI Act compliance report written:[/green] {output}")
        else:
            console.print(md)
    else:
        console.print(f"[red]Unknown format:[/red] {format}. Supported: markdown, json")
        raise typer.Exit(1)
