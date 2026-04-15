"""Root CLI application."""

import typer

from .commands import report as report_cmd
from .commands import run as run_cmd
from .commands import scenario as scenario_cmd
from .commands import serve as serve_cmd

app = typer.Typer(
    name="aastf",
    help="Agentic AI Security Testing Framework — OWASP ASI Top 10",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(run_cmd.app, name="run", help="Execute a security scan against an agent")
app.add_typer(report_cmd.app, name="report", help="Render and compare scan reports")
app.add_typer(scenario_cmd.app, name="scenario", help="Manage and validate attack scenarios")
app.add_typer(serve_cmd.app, name="serve", help="Start the sandbox server for manual debugging")


@app.callback(invoke_without_command=True)
def version(
    show_version: bool = typer.Option(False, "--version", "-V", help="Show version and exit"),
) -> None:
    if show_version:
        from aastf import __version__
        typer.echo(f"aastf {__version__}")
        raise typer.Exit()


def main() -> None:
    app()
