"""aastf init -- interactive project setup wizard."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

app = typer.Typer()
console = Console()

ADAPTERS = ["langgraph", "crewai", "openai_agents", "pydantic_ai"]

ASI_CATEGORIES = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Supply Chain Vulnerabilities",
    "ASI05": "Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
OUTPUT_FORMATS = ["console", "json", "sarif", "html"]


def _default_config() -> dict:
    """Return a config dict with sensible defaults."""
    return {
        "agent_module": "myapp.agent:create_agent",
        "adapter": "langgraph",
        "categories": [],
        "fail_on": "HIGH",
        "output_dir": "aastf-results",
        "formats": ["console", "json", "sarif"],
        "timeout": 30,
    }


def _pick_numbered(
    label: str,
    choices: list[str],
    descriptions: list[str] | None = None,
    default: int = 1,
) -> str:
    """Show a numbered menu and return the chosen value."""
    console.print(f"\n[bold]{label}[/bold]")
    for i, choice in enumerate(choices, 1):
        desc = f"  [dim]({descriptions[i - 1]})[/dim]" if descriptions else ""
        console.print(f"  [cyan]{i}[/cyan]) {choice}{desc}")
    raw = Prompt.ask(
        "Pick a number",
        default=str(default),
    )
    try:
        idx = int(raw)
        if 1 <= idx <= len(choices):
            return choices[idx - 1]
    except ValueError:
        pass
    console.print(f"[yellow]Invalid choice, using default: {choices[default - 1]}[/yellow]")
    return choices[default - 1]


def _pick_multiple(
    label: str,
    choices: list[str],
    defaults: list[str],
) -> list[str]:
    """Show a numbered list and let user pick multiple (comma-separated)."""
    console.print(f"\n[bold]{label}[/bold]")
    for i, choice in enumerate(choices, 1):
        marker = "*" if choice in defaults else " "
        console.print(f"  [cyan]{i}[/cyan]) {choice}  {marker}")
    console.print("[dim]  (* = included by default)[/dim]")
    raw = Prompt.ask(
        "Enter numbers separated by commas",
        default=",".join(str(choices.index(d) + 1) for d in defaults),
    )
    selected: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        try:
            idx = int(part)
            if 1 <= idx <= len(choices) and choices[idx - 1] not in selected:
                selected.append(choices[idx - 1])
        except ValueError:
            continue
    return selected if selected else defaults


def _interactive_config() -> dict:
    """Walk the user through interactive prompts and return a config dict."""
    config = _default_config()

    # 1. Agent module path
    console.print()
    config["agent_module"] = Prompt.ask(
        "[bold]Agent module path[/bold] (dotted.path:callable)",
        default=config["agent_module"],
    )

    # 2. Framework adapter
    config["adapter"] = _pick_numbered(
        "Framework adapter",
        ADAPTERS,
        default=1,
    )

    # 3. ASI categories
    test_all = Confirm.ask("\n[bold]Test all ASI categories?[/bold]", default=True)
    if not test_all:
        keys = list(ASI_CATEGORIES.keys())
        console.print("\n[bold]Select ASI categories to test:[/bold]")
        for i, (key, desc) in enumerate(ASI_CATEGORIES.items(), 1):
            console.print(f"  [cyan]{i:>2}[/cyan]) {key} - {desc}")
        raw = Prompt.ask("Enter numbers separated by commas (e.g. 1,3,5)")
        selected: list[str] = []
        for part in raw.split(","):
            part = part.strip()
            try:
                idx = int(part)
                if 1 <= idx <= len(keys) and keys[idx - 1] not in selected:
                    selected.append(keys[idx - 1])
            except ValueError:
                continue
        config["categories"] = selected

    # 4. Fail-on severity
    config["fail_on"] = _pick_numbered(
        "Minimum severity to fail CI",
        SEVERITIES,
        default=2,  # HIGH
    )

    # 5. Output directory
    config["output_dir"] = Prompt.ask(
        "\n[bold]Output directory[/bold]",
        default=config["output_dir"],
    )

    # 6. Output formats
    config["formats"] = _pick_multiple(
        "Output formats",
        OUTPUT_FORMATS,
        defaults=config["formats"],
    )

    # 7. Timeout per scenario
    raw_timeout = Prompt.ask(
        "\n[bold]Timeout per scenario (seconds)[/bold]",
        default=str(config["timeout"]),
    )
    try:
        config["timeout"] = int(raw_timeout)
    except ValueError:
        console.print("[yellow]Invalid number, using default: 30[/yellow]")
        config["timeout"] = 30

    return config


def _build_yaml(config: dict) -> str:
    """Build a YAML string from *config* without requiring pyyaml."""
    lines: list[str] = [
        "# AASTF Configuration",
        "# Generated by aastf init",
        "# Docs: https://github.com/anonymousAAK/aastf",
        "",
        "# Agent module path (dotted.path:callable)",
        f'agent_module: "{config["agent_module"]}"',
        "",
        "# Framework adapter",
        f"adapter: {config['adapter']}",
        "",
        "# ASI categories to test (empty = all)",
    ]
    cats = config.get("categories", [])
    if cats:
        lines.append("categories:")
        for c in cats:
            lines.append(f"  - {c}")
    else:
        lines.append("categories: []")
    lines += [
        "",
        "# Minimum severity to fail CI (CRITICAL, HIGH, MEDIUM, LOW, INFO)",
        f"fail_on: {config['fail_on']}",
        "",
        "# Output directory for reports",
        f"output_dir: {config['output_dir']}",
        "",
        "# Output formats",
        "formats:",
    ]
    for fmt in config.get("formats", ["console", "json", "sarif"]):
        lines.append(f"  - {fmt}")
    lines += [
        "",
        "# Per-scenario timeout in seconds",
        f"timeout: {config['timeout']}",
        "",
        "# Additional scenario directories (optional)",
        "# scenario_dirs:",
        "#   - ./custom-scenarios",
        "",
        "# Scenarios to exclude (optional)",
        "# exclude:",
        "#   - ASI08-003",
        "",
    ]
    return "\n".join(lines)


@app.command()
def init(
    output: Path = typer.Option(
        "aastf.yaml", "--output", "-o", help="Config file output path"
    ),
    non_interactive: bool = typer.Option(
        False, "--yes", "-y", help="Use defaults without prompting"
    ),
) -> None:
    """Initialize an AASTF configuration file."""
    console.print(
        Panel.fit(
            "[bold blue]AASTF[/bold blue] -- Agentic AI Security Testing Framework\n"
            "This wizard will create an aastf.yaml configuration file.",
            title="Setup Wizard",
        )
    )

    if (
        output.exists()
        and not non_interactive
        and not Confirm.ask(f"[yellow]{output} already exists. Overwrite?[/yellow]")
    ):
        raise typer.Exit(0)

    config = _default_config() if non_interactive else _interactive_config()

    yaml_content = _build_yaml(config)
    output.write_text(yaml_content, encoding="utf-8")

    console.print(f"\n[green]Done.[/green] Config written to [bold]{output}[/bold]")
    console.print("\n[dim]Next steps:[/dim]")
    console.print(f"  1. Edit {output} to set your agent module path")
    console.print(
        f"  2. Run: [cyan]aastf run {config['agent_module']}"
        f" --adapter {config['adapter']}[/cyan]"
    )
