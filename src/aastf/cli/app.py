"""Root CLI application."""

import typer

from .commands import scenario as scenario_cmd

app = typer.Typer(
    name="aastf",
    help="Agentic AI Security Testing Framework — OWASP ASI Top 10",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(scenario_cmd.app, name="scenario", help="Manage and validate attack scenarios")


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
