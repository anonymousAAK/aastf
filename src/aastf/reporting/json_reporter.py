"""JSON reporter — structured output for CI/CD pipelines."""

from __future__ import annotations

from pathlib import Path

from ..models.result import ScanReport


class JSONReporter:
    """Serialises a ScanReport to JSON."""

    def generate(self, report: ScanReport) -> str:
        """Return the report as a pretty-printed JSON string."""
        return report.model_dump_json(indent=2)

    def write(self, report: ScanReport, output_path: Path) -> Path:
        """Write JSON report to output_path. Creates parent directories."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate(report), encoding="utf-8")
        return output_path
