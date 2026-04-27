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
    Verdict.REFUSAL_ECHO: "yellow",
    Verdict.SAFE: "green",
    Verdict.INCONCLUSIVE: "dim",
    Verdict.ERROR: "bold magenta",
}

_VERDICT_SYMBOLS = {
    Verdict.VULNERABLE: "✗",
    Verdict.REFUSAL_ECHO: "⚠",
    Verdict.SAFE: "✓",
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
        vuln_pct = report.vulnerability_rate
        re_pct = report.informational_risk_rate
        total = report.total_scenarios or 1
        safe_pct = round(report.safe / total * 100, 1)

        vuln_str = (
            f"[bold red]✗ {report.vulnerable} behavioral ({vuln_pct}%)[/bold red]"
            if report.vulnerable
            else "[green]✓ 0 behavioral[/green]"
        )
        re_str = (
            f"[yellow]⚠ {report.refusal_echo_count} refusal echo ({re_pct}%)[/yellow]"
            if report.refusal_echo_count
            else "[dim]⚠ 0 refusal echo[/dim]"
        )
        safe_str = f"[green]✓ {report.safe} clean ({safe_pct}%)[/green]"

        inconcl = report.inconclusive
        errors = report.errors
        other_parts = []
        if inconcl:
            other_parts.append(f"[dim]{inconcl} inconclusive[/dim]")
        if errors:
            other_parts.append(f"[magenta]{errors} error[/magenta]")

        risk_color = (
            "red"
            if report.overall_risk_score >= 70
            else "yellow"
            if report.overall_risk_score >= 40
            else "green"
        )
        readiness_color = {
            "non_compliant": "bold red",
            "at_risk": "yellow",
            "compliant": "green",
        }.get(report.eu_ai_act_readiness, "white")

        self._console.print(f"\n {vuln_str}  /  {re_str}  /  {safe_str}")
        if other_parts:
            self._console.print(f" {'  '.join(other_parts)}")
        self._console.print(
            f" Risk Score: [{risk_color}]{report.overall_risk_score:.1f} / 100[/{risk_color}]"
            f"   EU AI Act: [{readiness_color}]{report.eu_ai_act_readiness.upper().replace('_', ' ')}[/{readiness_color}]"
        )

    def _print_findings(self, report: ScanReport) -> None:
        vulnerable = [f for f in report.findings if f.verdict == Verdict.VULNERABLE]
        echo = [f for f in report.findings if f.verdict == Verdict.REFUSAL_ECHO]

        if not vulnerable and not echo:
            self._console.print("\n[green]No vulnerabilities found.[/green]\n")
            return

        if vulnerable:
            self._console.print(
                f"\n[bold red]Behavioral Vulnerabilities ({len(vulnerable)}):[/bold red]"
            )
            for f in vulnerable:
                sev_color = _SEVERITY_COLORS.get(f.severity.value, "white")
                self._console.print(
                    f"\n  [bold red]✗[/bold red] [{sev_color}]{f.severity.value}[/{sev_color}]"
                    f"  [cyan]{f.scenario_id}[/cyan] — {f.scenario_name}"
                )
                self._console.print(f"  [dim]Triggered by:[/dim] {f.triggered_by}")
                self._console.print(f"  [dim]Remediation:[/dim] {f.remediation[:120]}")

        if echo:
            self._console.print(f"\n[yellow]Output Sanitization Findings ({len(echo)}):[/yellow]")
            for f in echo:
                sev_color = _SEVERITY_COLORS.get(f.severity.value, "white")
                self._console.print(
                    f"\n  [yellow]⚠[/yellow] [{sev_color}]{f.severity.value}[/{sev_color}]"
                    f"  [cyan]{f.scenario_id}[/cyan] — {f.scenario_name}"
                )
                self._console.print(f"  [dim]Triggered by:[/dim] {f.triggered_by}")
                self._console.print(f"  [dim]Remediation:[/dim] {f.remediation[:120]}")

        self._console.print()
