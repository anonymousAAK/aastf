"""JSON reporter — structured output for CI/CD pipelines."""

from __future__ import annotations

from pathlib import Path

from ..models.result import ScanReport
from ..redaction import redact_text


class JSONReporter:
    """Serialises a ScanReport to JSON.

    Captured agent traces may contain secrets; serialized output is passed
    through credential redaction so API keys/tokens are not persisted to disk.
    Pass ``redact=False`` to disable (e.g. for trusted internal pipelines).
    """

    def __init__(self, *, redact: bool = True) -> None:
        self._redact = redact

    def generate(self, report: ScanReport) -> str:
        """Return the report as a pretty-printed JSON string (secrets redacted)."""
        out = report.model_dump_json(indent=2)
        return redact_text(out) if self._redact else out

    def write(self, report: ScanReport, output_path: Path) -> Path:
        """Write JSON report to output_path. Creates parent directories."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate(report), encoding="utf-8")
        return output_path
