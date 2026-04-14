"""Console reporter — Rich terminal output for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..models.result import ScanReport, Verdict

_SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}

_VERDICT_COLORS = {
    Verdict.VULNERABLE: "bold red",
    Verdict.SAFE: "green",
    Verdict.INCONCLUSIVE: "yellow",
    Verdict.ERROR: "bold magenta",
}

_VERDICT_SYMBOLS = {
    Verdict.VULNERABLE: "VULN",
    Verdict.SAFE: "SAFE",
    Verdict.INCONCLUSIVE: "----",
    Verdict.ERROR: "ERR!",
}


class ConsoleReporter:
    """Renders a ScanReport to the terminal using Rich."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def print_header(self, adapter: str, scenario_count: int) -> None:
        from aastf import __version__
        self._console.print(
            f"\n[bold cyan]AASTF v{__version__}[/bold cyan]  "
            f"[dim]|[/dim]  Adapter: [yellow]{adapter}[/yellow]  "
            f"[dim]|[/dim]  Scenarios: [cyan]{scenario_count}[/cyan]\n"
        )

    def print_report(self, report: ScanReport) -> None:
        self._print_results_table(report)
        self._print_summary(report)
        self._print_findings(report)

    def _print_results_table(self, report: ScanReport) -> None:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            show_lines=False,
            padding=(0, 1),
        )
        table.add_column("ID", style="cyan", no_wrap=True, min_width=10)
        table.add_column("Name", max_width=44)
        table.add_column("Category", no_wrap=True)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Result", no_wrap=True)
        table.add_column("ms", justify="right", no_wrap=True)

        for r in report.results:
            sev_color = _SEVERITY_COLORS.get(r.severity.value, "white")
            verdict_color = _VERDICT_COLORS.get(r.verdict, "white")
            verdict_sym = _VERDICT_SYMBOLS.get(r.verdict, "????")

            table.add_row(
                r.scenario_id,
                r.scenario_name[:44],
                r.category.value,
                f"[{sev_color}]{r.severity.value[:4]}[/{sev_color}]",
                f"[{verdict_color}]{verdict_sym}[/{verdict_color}]",
                f"{r.execution_time_ms:.0f}",
            )

        self._console.print(table)

    def _print_summary(self, report: ScanReport) -> None:
        vuln_count = report.vulnerable
        safe_count = report.safe
        inconcl = report.inconclusive
        errors = report.errors

        vuln_str = f"[bold red]{vuln_count} VULNERABLE[/bold red]" if vuln_count else f"[green]{vuln_count} VULNERABLE[/green]"
        safe_str = f"[green]{safe_count} SAFE[/green]"
        other_str = f"[yellow]{inconcl} INCONCLUSIVE[/yellow]"
        if errors:
            other_str += f"  [magenta]{errors} ERROR[/magenta]"

        risk_color = "red" if report.overall_risk_score >= 70 else "yellow" if report.overall_risk_score >= 40 else "green"
        readiness_color = {
            "non_compliant": "bold red",
            "at_risk": "yellow",
            "compliant": "green",
        }.get(report.eu_ai_act_readiness, "white")

        self._console.print(f"\n {vuln_str}  /  {safe_str}  /  {other_str}")
        self._console.print(
            f" Risk Score: [{risk_color}]{report.overall_risk_score:.1f} / 100[/{risk_color}]"
            f"   EU AI Act: [{readiness_color}]{report.eu_ai_act_readiness.upper().replace('_', ' ')}[/{readiness_color}]"
        )

    def _print_findings(self, report: ScanReport) -> None:
        if not report.findings:
            self._console.print("\n[green]No vulnerabilities found.[/green]\n")
            return

        self._console.print(f"\n[bold red]Findings ({len(report.findings)}):[/bold red]")
        for f in report.findings:
            sev_color = _SEVERITY_COLORS.get(f.severity.value, "white")
            self._console.print(
                f"\n  [{sev_color}][{f.severity.value}][/{sev_color}] "
                f"[cyan]{f.scenario_id}[/cyan] — {f.scenario_name}"
            )
            self._console.print(f"  [dim]Triggered by:[/dim] {f.triggered_by}")
            self._console.print(f"  [dim]Remediation:[/dim] {f.remediation[:120]}")
        self._console.print()
