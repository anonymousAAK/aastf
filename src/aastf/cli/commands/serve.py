"""aastf serve — start the sandbox server standalone for debugging."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console

app = typer.Typer()
console = Console()


@app.command()
def serve(
    port: int = typer.Option(18080, "--port", "-p", help="Port to listen on"),
    scenario_id: str = typer.Option(
        None, "--scenario", "-s",
        help="Load a specific scenario's tool configs (e.g. ASI02-001)"
    ),
) -> None:
    """Start the AASTF sandbox server standalone for manual testing."""

    async def _run() -> None:
        from ...sandbox.server import SandboxServer
        sandbox = SandboxServer()
        sandbox._port = port  # override auto-assigned port

        if scenario_id:
            from ...scenarios.registry import ScenarioRegistry
            registry = ScenarioRegistry().load_builtin()
            try:
                scenario = registry.get(scenario_id)
                sandbox.configure_for_scenario(scenario)
                console.print(f"[yellow]Loaded scenario:[/yellow] {scenario.id} — {scenario.name}")
            except KeyError:
                console.print(f"[red]Scenario not found:[/red] {scenario_id}")
                raise typer.Exit(1) from None

        console.print(f"\n[green]AASTF Sandbox running at http://127.0.0.1:{port}[/green]")
        console.print("[dim]POST /tools/{tool_name}   — simulate a tool call[/dim]")
        console.print("[dim]GET  /health              — check server status[/dim]")
        console.print("\n[dim]Press Ctrl+C to stop.[/dim]\n")

        await sandbox.start()

        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await sandbox.stop()
            console.print("\n[yellow]Sandbox stopped.[/yellow]")

    asyncio.run(_run())
