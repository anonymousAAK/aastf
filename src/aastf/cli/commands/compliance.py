"""aastf compliance — generate regulatory compliance reports."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(no_args_is_help=True)
console = Console()


def _load_report(report_path: Path):
    """Load and validate a ScanReport from a JSON file.

    Returns the ScanReport on success or calls typer.Exit(1) on failure.
    """
    if not report_path.exists():
        console.print(f"[red]Report not found:[/red] {report_path}")
        raise typer.Exit(1)

    from pydantic import ValidationError

    from ...models.result import ScanReport

    try:
        return ScanReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    except (ValidationError, ValueError) as e:
        console.print(f"[red]Invalid report file:[/red] {e}")
        raise typer.Exit(1) from None


@app.command("eu-ai-act")
def eu_ai_act_report(
    report_path: Path = typer.Argument(..., help="Path to a scan report JSON file"),
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Output format: markdown|json"
    ),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate EU AI Act Article 50 compliance report from scan results."""
    report = _load_report(report_path)

    from ...compliance.eu_ai_act import EUAIActReporter

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


@app.command("singapore-imda")
def singapore_imda_report(
    report_path: Path = typer.Argument(..., help="Path to a scan report JSON file"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate Singapore IMDA AI Governance Framework report from scan results."""
    report = _load_report(report_path)

    from ...compliance.singapore_imda import IMDAReporter

    reporter = IMDAReporter()

    if output:
        # Write both JSON and Markdown
        json_path = output
        reporter.write(report, json_path)
        console.print(f"[green]IMDA report (JSON) written:[/green] {json_path}")

        md_path = json_path.with_suffix(".md")
        md_content = reporter.generate_markdown(report)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(md_content, encoding="utf-8")
        console.print(f"[green]IMDA report (Markdown) written:[/green] {md_path}")
    else:
        console.print(reporter.generate_markdown(report))


@app.command("nist-ai-rmf")
def nist_ai_rmf_report(
    report_path: Path = typer.Argument(..., help="Path to a scan report JSON file"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Generate NIST AI RMF compliance report from scan results."""
    report = _load_report(report_path)

    from ...compliance.nist_ai_rmf import NISTAIRMFReporter

    reporter = NISTAIRMFReporter()

    if output:
        json_path = output
        reporter.write(report, json_path)
        console.print(f"[green]NIST AI RMF report (JSON) written:[/green] {json_path}")

        md_path = json_path.with_suffix(".md")
        md_content = reporter.generate_markdown(report)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(md_content, encoding="utf-8")
        console.print(f"[green]NIST AI RMF report (Markdown) written:[/green] {md_path}")
    else:
        console.print(reporter.generate_markdown(report))


@app.command("pack")
def evidence_pack(
    report_path: Path = typer.Argument(..., help="Path to a scan report JSON file"),
    output: Path = typer.Option(
        "evidence-pack.zip", "--output", "-o", help="Output ZIP file path"
    ),
    articles: list[str] | None = typer.Option(
        None,
        "--articles",
        help="Selective EU AI Act articles to include (repeatable, e.g. --articles 9 --articles 12). Default: all.",
    ),
    format: str = typer.Option(
        "zip", "--format", "-f", help="Output format: zip (default) or dir"
    ),
    framework: list[str] | None = typer.Option(
        None,
        "--framework",
        help="Compliance frameworks to include (repeatable): eu-ai-act, singapore-imda, nist-ai-rmf. Default: all three.",
    ),
) -> None:
    """Generate a compliance evidence pack (ZIP or directory) from scan results.

    Bundles EU AI Act, Singapore IMDA, and NIST AI RMF compliance evidence
    into a single archive with SHA-256 manifest for tamper detection.
    """
    report = _load_report(report_path)

    # Parse article numbers
    article_ints: list[int] | None = None
    if articles:
        try:
            article_ints = [int(a) for a in articles]
        except ValueError:
            console.print("[red]--articles values must be integers (e.g. 9, 12, 15)[/red]")
            raise typer.Exit(1) from None

    # Default frameworks: all three
    frameworks = framework if framework else ["eu-ai-act", "singapore-imda", "nist-ai-rmf"]
    valid_frameworks = {"eu-ai-act", "singapore-imda", "nist-ai-rmf"}
    for fw in frameworks:
        if fw not in valid_frameworks:
            console.print(
                f"[red]Unknown framework:[/red] {fw}. "
                f"Supported: {', '.join(sorted(valid_frameworks))}"
            )
            raise typer.Exit(1)

    from ...compliance.evidence_pack import EvidencePackBuilder

    builder = EvidencePackBuilder()
    output_path = Path(output)

    if format == "dir":
        # For directory mode, use the path without .zip suffix
        dir_path = output_path.with_suffix("") if output_path.suffix == ".zip" else output_path
        # Build the ZIP first, then extract
        import tempfile
        import zipfile

        with tempfile.TemporaryDirectory(prefix="aastf-pack-") as tmpdir:
            tmp_zip = Path(tmpdir) / "pack.zip"
            builder.build(report, tmp_zip, articles=article_ints)

            # Add additional framework reports into the extracted directory
            dir_path.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(tmp_zip, "r") as zf:
                zf.extractall(dir_path)

            # Find the evidence-pack subdirectory
            pack_dir = dir_path / "evidence-pack"
            if not pack_dir.exists():
                pack_dir = dir_path

            _write_extra_frameworks(report, pack_dir, frameworks)

        console.print(f"[green]Evidence pack extracted to directory:[/green] {dir_path}")
    elif format == "zip":
        result_path = builder.build(report, output_path, articles=article_ints)

        # Add additional framework reports into the ZIP
        if "singapore-imda" in frameworks or "nist-ai-rmf" in frameworks:
            _add_extra_frameworks_to_zip(report, result_path, frameworks)

        console.print(f"[green]Evidence pack written:[/green] {result_path}")
    else:
        console.print(f"[red]Unknown format:[/red] {format}. Supported: zip, dir")
        raise typer.Exit(1)

    # Print summary
    _print_pack_summary(report, frameworks)


def _write_extra_frameworks(
    report, pack_dir: Path, frameworks: list[str]
) -> None:
    """Write additional framework reports to the evidence pack directory."""
    if "singapore-imda" in frameworks:
        from ...compliance.singapore_imda import IMDAReporter

        imda = IMDAReporter()
        imda_dir = pack_dir / "singapore-imda"
        imda_dir.mkdir(parents=True, exist_ok=True)
        imda.write(report, imda_dir / "imda-governance-report.json")
        md = imda.generate_markdown(report)
        (imda_dir / "imda-governance-report.md").write_text(md, encoding="utf-8")

    if "nist-ai-rmf" in frameworks:
        from ...compliance.nist_ai_rmf import NISTAIRMFReporter

        nist = NISTAIRMFReporter()
        nist_dir = pack_dir / "nist-ai-rmf"
        nist_dir.mkdir(parents=True, exist_ok=True)
        nist.write(report, nist_dir / "nist-ai-rmf-report.json")
        md = nist.generate_markdown(report)
        (nist_dir / "nist-ai-rmf-report.md").write_text(md, encoding="utf-8")


def _add_extra_frameworks_to_zip(
    report, zip_path: Path, frameworks: list[str]
) -> None:
    """Append additional framework reports into an existing ZIP archive."""
    import zipfile

    with zipfile.ZipFile(zip_path, "a", zipfile.ZIP_DEFLATED) as zf:
        if "singapore-imda" in frameworks:
            from ...compliance.singapore_imda import IMDAReporter

            imda = IMDAReporter()
            zf.writestr(
                "evidence-pack/singapore-imda/imda-governance-report.json",
                imda.generate_json(report),
            )
            zf.writestr(
                "evidence-pack/singapore-imda/imda-governance-report.md",
                imda.generate_markdown(report),
            )

        if "nist-ai-rmf" in frameworks:
            from ...compliance.nist_ai_rmf import NISTAIRMFReporter

            nist = NISTAIRMFReporter()
            zf.writestr(
                "evidence-pack/nist-ai-rmf/nist-ai-rmf-report.json",
                nist.generate_json(report),
            )
            zf.writestr(
                "evidence-pack/nist-ai-rmf/nist-ai-rmf-report.md",
                nist.generate_markdown(report),
            )


def _print_pack_summary(report, frameworks: list[str]) -> None:
    """Print a rich summary of the evidence pack contents."""
    from rich.table import Table

    table = Table(title="Evidence Pack Summary")
    table.add_column("Framework", style="cyan")
    table.add_column("Status", style="green")

    if "eu-ai-act" in frameworks:
        table.add_row("EU AI Act (Arts 9-15, 50)", "Included")
    if "singapore-imda" in frameworks:
        table.add_row("Singapore IMDA AI Governance", "Included")
    if "nist-ai-rmf" in frameworks:
        table.add_row("NIST AI RMF", "Included")

    console.print(table)
    console.print(
        f"\n[dim]Scan: {report.total_scenarios} scenarios, "
        f"{report.vulnerable} vulnerable, "
        f"risk score {report.overall_risk_score}[/dim]"
    )
