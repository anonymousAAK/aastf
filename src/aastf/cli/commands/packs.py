"""aastf packs — manage scenario packs."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


def _manager():
    from ...packs import PackManager

    return PackManager()


@app.command("list")
def list_packs() -> None:
    """List installed and builtin scenario packs."""
    mgr = _manager()

    builtin = mgr.list_builtin()
    installed = mgr.list_installed()

    table = Table(title="Scenario Packs")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Scenarios", justify="right")
    table.add_column("Categories")
    table.add_column("Source", style="dim")

    for p in builtin:
        table.add_row(
            p.name,
            p.version,
            str(len(p.scenarios)),
            ", ".join(p.categories),
            "builtin",
        )

    for p in installed:
        # Skip if already shown as builtin
        if any(b.name == p.name for b in builtin):
            continue
        table.add_row(
            p.name,
            p.version,
            str(len(p.scenarios)),
            ", ".join(p.categories),
            "installed",
        )

    console.print(table)
    console.print(f"\n[dim]{len(builtin)} builtin, {len(installed)} installed[/dim]")


@app.command("info")
def pack_info(
    name: str = typer.Argument(..., help="Pack name (e.g. aastf/mcp)"),
) -> None:
    """Show details about a scenario pack."""
    mgr = _manager()

    pack = None
    source = "unknown"

    for p in mgr.list_builtin():
        if p.name == name:
            pack = p
            source = "builtin"
            break

    if pack is None:
        for p in mgr.list_installed():
            if p.name == name:
                pack = p
                source = "installed"
                break

    if pack is None:
        console.print(f"[red]Pack not found:[/red] {name}")
        raise typer.Exit(1)

    console.print(f"[bold cyan]{pack.name}[/bold cyan] v{pack.version}")
    console.print(f"[dim]{pack.description}[/dim]")
    console.print(f"Author: {pack.author}")
    console.print(f"Source: {source}")
    console.print(f"Categories: {', '.join(pack.categories)}")
    console.print(f"Scenarios ({len(pack.scenarios)}):")
    for sid in pack.scenarios:
        console.print(f"  - {sid}")
    if pack.signature:
        console.print(f"Signature: {pack.signature[:40]}...")
    else:
        console.print("[yellow]Unsigned[/yellow]")


@app.command("verify")
def verify_pack(
    name: str = typer.Argument(..., help="Pack name to verify"),
    key_file: Path = typer.Option(
        None, "--key", "-k", help="Path to HMAC key file (raw bytes)"
    ),
) -> None:
    """Verify the signature of a scenario pack."""
    mgr = _manager()

    pack = None
    for p in [*mgr.list_builtin(), *mgr.list_installed()]:
        if p.name == name:
            pack = p
            break

    if pack is None:
        console.print(f"[red]Pack not found:[/red] {name}")
        raise typer.Exit(1)

    if not pack.signature:
        console.print(f"[yellow]Pack {name!r} is unsigned.[/yellow]")
        raise typer.Exit(1)

    public_key = None
    if key_file:
        public_key = key_file.read_bytes()

    try:
        ok = mgr.verify(pack, public_key=public_key)
    except NotImplementedError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None

    if ok:
        console.print(f"[green]Pack {name!r} signature is valid.[/green]")
    else:
        console.print(f"[red]Pack {name!r} signature verification FAILED.[/red]")
        raise typer.Exit(1)


@app.command("export")
def export_pack(
    name: str = typer.Argument(..., help="Pack name to export"),
    output: Path = typer.Option(
        "pack.tar.gz", "--output", "-o", help="Output .tar.gz file path"
    ),
) -> None:
    """Export a scenario pack as a .tar.gz archive."""
    mgr = _manager()

    pack = None
    for p in [*mgr.list_builtin(), *mgr.list_installed()]:
        if p.name == name:
            pack = p
            break

    if pack is None:
        console.print(f"[red]Pack not found:[/red] {name}")
        raise typer.Exit(1)

    mgr.export(pack, output)
    console.print(f"[green]Pack {name!r} exported to:[/green] {output}")
