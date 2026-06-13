"""Root CLI application."""

from __future__ import annotations

import typer

from .commands import benchmark as benchmark_cmd
from .commands import compliance as compliance_cmd
from .commands import drift as drift_cmd
from .commands import init as init_cmd
from .commands import packs as packs_cmd
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

# run, init and serve are single commands — add directly so the invocation is
# `aastf <cmd>` (not `aastf serve serve`) and positional args aren't confused
# with a subcommand name.
app.command("run", help="Execute a security scan against an agent")(run_cmd.run)
app.command("init", help="Initialize AASTF configuration")(init_cmd.init)
app.command("serve", help="Start the sandbox server for manual debugging")(serve_cmd.serve)
app.add_typer(benchmark_cmd.app, name="benchmark", help="Cross-model security benchmarks")
app.add_typer(compliance_cmd.app, name="compliance", help="Generate compliance reports")
app.add_typer(drift_cmd.app, name="drift", help="Detect regressions between scan reports")
app.add_typer(report_cmd.app, name="report", help="Render and compare scan reports")
app.add_typer(packs_cmd.app, name="packs", help="Manage scenario packs")
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
