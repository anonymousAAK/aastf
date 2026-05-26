"""Benchmark reporters — Markdown, CSV, and HuggingFace dataset export."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .runner import BenchmarkResult

# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class MarkdownReporter:
    """Generates a Markdown report from benchmark results."""

    @staticmethod
    def generate(result: BenchmarkResult) -> str:
        lines: list[str] = []
        lines.append("# AASTF Benchmark Report")
        lines.append("")
        lines.append(f"**Run ID:** `{result.run_id}`  ")
        lines.append(f"**Started:** {result.started_at.isoformat()}  ")
        lines.append(f"**Completed:** {result.completed_at.isoformat()}  ")
        lines.append(f"**Total runs:** {result.summary.total_runs}  ")
        lines.append(f"**Models tested:** {result.summary.models_tested}  ")
        lines.append(f"**Frameworks tested:** {result.summary.frameworks_tested}  ")
        lines.append(f"**Scenarios tested:** {result.summary.scenarios_tested}  ")
        lines.append("")

        # Vulnerability rate by model
        lines.append("## Vulnerability Rate by Model")
        lines.append("")
        lines.append("| Model | Vulnerability Rate |")
        lines.append("|-------|-------------------|")
        for model, rate in sorted(result.summary.vulnerability_rate_by_model.items()):
            lines.append(f"| {model} | {rate}% |")
        lines.append("")

        # Vulnerability rate by category
        lines.append("## Vulnerability Rate by Category")
        lines.append("")
        lines.append("| Category | Vulnerability Rate |")
        lines.append("|----------|-------------------|")
        for cat, rate in sorted(result.summary.vulnerability_rate_by_category.items()):
            lines.append(f"| {cat} | {rate}% |")
        lines.append("")

        # Mean latency by model
        lines.append("## Mean Latency by Model")
        lines.append("")
        lines.append("| Model | Mean Latency (ms) |")
        lines.append("|-------|--------------------|")
        for model, lat in sorted(result.summary.mean_latency_by_model.items()):
            lines.append(f"| {model} | {lat} |")
        lines.append("")

        # Detail table (first 50 rows to keep readable)
        lines.append("## Detailed Results")
        lines.append("")
        lines.append("| Model | Framework | Scenario | Category | Verdict | Severity | Latency (ms) | Run |")
        lines.append("|-------|-----------|----------|----------|---------|----------|--------------|-----|")
        for entry in result.results[:50]:
            lines.append(
                f"| {entry.model} | {entry.framework} | {entry.scenario_id} "
                f"| {entry.category} | {entry.verdict} | {entry.severity} "
                f"| {entry.latency_ms} | {entry.run_index} |"
            )
        if len(result.results) > 50:
            lines.append("| ... | ... | ... | ... | ... | ... | ... | ... |")
            lines.append("")
            lines.append(f"*Showing 50 of {len(result.results)} results.*")
        lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


class CSVReporter:
    """Generates CSV output from benchmark results."""

    @staticmethod
    def generate(result: BenchmarkResult) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "model", "framework", "scenario_id", "category",
            "verdict", "severity", "latency_ms", "run_index",
        ])
        for entry in result.results:
            writer.writerow([
                entry.model, entry.framework, entry.scenario_id,
                entry.category, entry.verdict, entry.severity,
                entry.latency_ms, entry.run_index,
            ])
        return buf.getvalue()


# ---------------------------------------------------------------------------
# HuggingFace dataset export
# ---------------------------------------------------------------------------


class HuggingFaceExporter:
    """Exports benchmark results in HuggingFace Datasets format.

    Creates:
      - data.json  (JSON Lines, parquet-ready)
      - dataset_infos.json  (HF metadata)
      - README.md  (dataset card)
    """

    @staticmethod
    def export(result: BenchmarkResult, output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        # data.json — one JSON object per line (JSON Lines)
        data_path = output_dir / "data.json"
        with data_path.open("w", encoding="utf-8") as f:
            for entry in result.results:
                row = {
                    "model": entry.model,
                    "framework": entry.framework,
                    "scenario_id": entry.scenario_id,
                    "category": entry.category,
                    "verdict": entry.verdict,
                    "severity": entry.severity,
                    "latency_ms": entry.latency_ms,
                    "run_index": entry.run_index,
                }
                f.write(json.dumps(row) + "\n")

        # dataset_infos.json
        infos = {
            "default": {
                "description": "AASTF cross-model security benchmark results",
                "features": {
                    "model": {"dtype": "string", "_type": "Value"},
                    "framework": {"dtype": "string", "_type": "Value"},
                    "scenario_id": {"dtype": "string", "_type": "Value"},
                    "category": {"dtype": "string", "_type": "Value"},
                    "verdict": {"dtype": "string", "_type": "Value"},
                    "severity": {"dtype": "string", "_type": "Value"},
                    "latency_ms": {"dtype": "float64", "_type": "Value"},
                    "run_index": {"dtype": "int64", "_type": "Value"},
                },
                "num_rows": len(result.results),
                "dataset_size": data_path.stat().st_size,
            },
        }
        infos_path = output_dir / "dataset_infos.json"
        infos_path.write_text(json.dumps(infos, indent=2), encoding="utf-8")

        # README.md — dataset card
        readme = _build_dataset_card(result)
        readme_path = output_dir / "README.md"
        readme_path.write_text(readme, encoding="utf-8")


def _build_dataset_card(result: BenchmarkResult) -> str:
    """Build a HuggingFace dataset card."""
    models_list = ", ".join(sorted(result.summary.vulnerability_rate_by_model.keys()))
    return f"""---
license: mit
task_categories:
  - text-classification
tags:
  - agentic-ai
  - security
  - benchmark
  - owasp
size_categories:
  - 1K<n<10K
---

# AASTF Security Benchmark Dataset

Cross-model security benchmark results from the
[Agentic AI Security Testing Framework (AASTF)](https://github.com/anonymousAAK/aastf).

## Dataset Description

- **Run ID:** {result.run_id}
- **Models:** {models_list}
- **Total entries:** {result.summary.total_runs}
- **Scenarios tested:** {result.summary.scenarios_tested}
- **Frameworks tested:** {result.summary.frameworks_tested}

## Features

| Column | Type | Description |
|--------|------|-------------|
| model | string | Model display name |
| framework | string | Agent framework adapter |
| scenario_id | string | OWASP ASI scenario identifier |
| category | string | ASI category (ASI01-ASI10, MCP01-MCP06, CVE01) |
| verdict | string | VULNERABLE, SAFE, ERROR, INCONCLUSIVE, etc. |
| severity | string | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| latency_ms | float | Execution time in milliseconds |
| run_index | int | Repeat index (0-based) |

## Usage

```python
from datasets import load_dataset
ds = load_dataset("path/to/this/dataset")
```

## Citation

If you use this dataset, please cite AASTF:

```bibtex
@software{{aastf,
  title = {{AASTF: Agentic AI Security Testing Framework}},
  doi = {{10.5281/zenodo.20296480}},
}}
```
"""
