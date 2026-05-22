"""Evidence pack bundler for EU AI Act compliance.

Bundles all article-specific evidence (Arts 9, 11-15) plus the
full EU AI Act report into a single ZIP archive with a SHA-256
manifest for tamper-evidence and audit traceability.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models.result import ScanReport, Verdict
from .eu_ai_act import EU_AI_ACT_ARTICLE_MAPPING, EUAIActReporter
from .evidence_reporters import (
    Article9RiskRegister,
    Article11TechDoc,
    Article12AutoLog,
    Article13TransparencyDeclaration,
    Article14OversightChecklist,
    Article15TestMatrix,
)

# Canonical article numbers the builder knows about.
_ALL_ARTICLES = ("9", "11", "12", "13", "14", "15")

# Security-critical articles get 2x weight in the overall conformity score.
_ARTICLE_WEIGHTS: dict[str, float] = {
    "9": 2.0,
    "11": 1.0,
    "12": 1.0,
    "13": 1.0,
    "14": 2.0,
    "15": 2.0,
}


class EvidencePackBuilder:
    """Bundles EU AI Act compliance evidence into a ZIP archive."""

    def build(
        self,
        report: ScanReport,
        output_path: Path,
        articles: list[str] | None = None,
    ) -> Path:
        """Build an evidence-pack ZIP and return the resolved path.

        Parameters
        ----------
        report:
            A completed :class:`ScanReport` from an AASTF scan run.
        output_path:
            Destination path for the ZIP file.  Parent directories are
            created automatically.
        articles:
            Which article directories to include (e.g. ``["9", "12",
            "15"]``).  ``None`` means *all*.

        Returns
        -------
        Path
            The absolute path to the written ZIP file.
        """
        selected = list(articles) if articles is not None else list(_ALL_ARTICLES)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="aastf-evidence-") as tmpdir:
            staging = Path(tmpdir) / "evidence-pack"
            staging.mkdir()

            # Track relative-path -> {sha256, size_bytes}.
            file_records: dict[str, dict[str, Any]] = {}

            # ---- per-article evidence --------------------------------
            self._write_article_evidence(report, staging, selected, file_records)

            # ---- summary directory -----------------------------------
            summary_dir = staging / "summary"
            summary_dir.mkdir(exist_ok=True)

            eu_reporter = EUAIActReporter()
            eu_data = eu_reporter.generate(report)
            eu_md = eu_reporter.generate_markdown(report)

            self._write_file(
                summary_dir / "eu-ai-act-report.json",
                json.dumps(eu_data, indent=2, default=str),
                staging,
                file_records,
            )
            self._write_file(
                summary_dir / "eu-ai-act-report.md",
                eu_md,
                staging,
                file_records,
            )

            # ---- conformity score ------------------------------------
            conformity = self._compute_conformity_score(report, selected)

            # ---- manifest.json (written last) ------------------------
            manifest = {
                "aastf_version": report.aastf_version,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scan_date": report.generated_at.isoformat(),
                "run_id": report.run_id,
                "pack_version": "1.0",
                "articles_included": sorted(selected),
                "files": dict(file_records),
                "conformity_score": conformity,
            }
            self._write_file(
                staging / "manifest.json",
                json.dumps(manifest, indent=2, default=str),
                staging,
                file_records,
            )

            # ---- zip everything --------------------------------------
            self._zip_directory(staging, output_path)

        return output_path.resolve()

    # ------------------------------------------------------------------
    # Per-article evidence helpers
    # ------------------------------------------------------------------

    def _write_article_evidence(
        self,
        report: ScanReport,
        staging: Path,
        selected: list[str],
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        """Delegate to each per-article reporter and write outputs."""
        article_writers: dict[str, Any] = {
            "9": self._write_art9,
            "11": self._write_art11,
            "12": self._write_art12,
            "13": self._write_art13,
            "14": self._write_art14,
            "15": self._write_art15,
        }
        for art_num in selected:
            writer = article_writers.get(art_num)
            if writer is not None:
                writer(report, staging, file_records)

    def _write_art9(
        self,
        report: ScanReport,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        art_dir = staging / "art9"
        art_dir.mkdir(exist_ok=True)
        reporter = Article9RiskRegister()

        # Write CSV via reporter, then record checksum
        reporter.to_csv(report, art_dir / "risk-register.csv")
        self._record_existing_file(
            art_dir / "risk-register.csv", staging, file_records
        )

    def _write_art11(
        self,
        report: ScanReport,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        art_dir = staging / "art11"
        art_dir.mkdir(exist_ok=True)
        reporter = Article11TechDoc()

        data = reporter.generate(report)
        self._write_file(
            art_dir / "technical-doc.json",
            json.dumps(data, indent=2, default=str),
            staging,
            file_records,
        )

    def _write_art12(
        self,
        report: ScanReport,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        art_dir = staging / "art12"
        art_dir.mkdir(exist_ok=True)
        reporter = Article12AutoLog()

        reporter.to_ndjson(report, art_dir / "event-log.ndjson")
        self._record_existing_file(
            art_dir / "event-log.ndjson", staging, file_records
        )

    def _write_art13(
        self,
        report: ScanReport,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        art_dir = staging / "art13"
        art_dir.mkdir(exist_ok=True)
        reporter = Article13TransparencyDeclaration()

        md_content = reporter.to_markdown(report)
        self._write_file(
            art_dir / "transparency-declaration.md",
            md_content,
            staging,
            file_records,
        )

    def _write_art14(
        self,
        report: ScanReport,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        art_dir = staging / "art14"
        art_dir.mkdir(exist_ok=True)
        reporter = Article14OversightChecklist()

        data = reporter.generate(report)
        self._write_file(
            art_dir / "human-oversight.json",
            json.dumps(data, indent=2, default=str),
            staging,
            file_records,
        )

    def _write_art15(
        self,
        report: ScanReport,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        art_dir = staging / "art15"
        art_dir.mkdir(exist_ok=True)
        reporter = Article15TestMatrix()

        data = reporter.generate(report)
        self._write_file(
            art_dir / "accuracy-robustness.json",
            json.dumps(data, indent=2, default=str),
            staging,
            file_records,
        )

    # ------------------------------------------------------------------
    # Conformity scoring
    # ------------------------------------------------------------------

    def _compute_conformity_score(
        self,
        report: ScanReport,
        selected: list[str],
    ) -> dict[str, Any]:
        """Compute per-article and weighted overall conformity scores.

        Per article: pass rate of findings mapped to that article.
        Overall: weighted average where Art 9, 14, 15 get 2x weight.
        """
        # Build article -> set of ASI categories mapping.
        article_to_cats: dict[str, set[str]] = {a: set() for a in selected}
        for cat, mappings in EU_AI_ACT_ARTICLE_MAPPING.items():
            for mapping in mappings:
                art_str: str = mapping["article_number"]
                art_int = _article_str_to_int(art_str)
                if art_int is not None and str(art_int) in article_to_cats:
                    cat_val = cat.value if hasattr(cat, "value") else str(cat)
                    article_to_cats[str(art_int)].add(cat_val)

        # Collect per-category verdict counts.
        cat_total: dict[str, int] = {}
        cat_pass: dict[str, int] = {}
        for result in report.results:
            cv = result.category.value if hasattr(result.category, "value") else str(result.category)
            cat_total[cv] = cat_total.get(cv, 0) + 1
            if result.verdict != Verdict.VULNERABLE:
                cat_pass[cv] = cat_pass.get(cv, 0) + 1

        # Per-article scores.
        per_article: dict[str, float] = {}
        for art_num in selected:
            cats = article_to_cats.get(art_num, set())
            if not cats:
                per_article[f"art{art_num}"] = 0.0
                continue
            total = sum(cat_total.get(c, 0) for c in cats)
            passed = sum(cat_pass.get(c, 0) for c in cats)
            per_article[f"art{art_num}"] = round(passed / total * 100, 1) if total > 0 else 0.0

        # Weighted overall score.
        weighted_sum = 0.0
        weight_total = 0.0
        for art_num in selected:
            w = _ARTICLE_WEIGHTS.get(art_num, 1.0)
            weighted_sum += per_article[f"art{art_num}"] * w
            weight_total += w

        overall = round(weighted_sum / weight_total, 1) if weight_total > 0 else 0.0

        return {
            "overall": overall,
            "per_article": per_article,
        }

    # ------------------------------------------------------------------
    # File I/O helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _write_file(
        path: Path,
        content: str,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        """Write *content* to *path* and record SHA-256 + size."""
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = content.encode("utf-8")
        path.write_bytes(encoded)

        digest = hashlib.sha256(encoded).hexdigest()
        rel_key = path.relative_to(staging).as_posix()
        file_records[rel_key] = {
            "sha256": digest,
            "size_bytes": len(encoded),
        }

    @staticmethod
    def _record_existing_file(
        path: Path,
        staging: Path,
        file_records: dict[str, dict[str, Any]],
    ) -> None:
        """Record SHA-256 + size for a file already written to disk."""
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        rel_key = path.relative_to(staging).as_posix()
        file_records[rel_key] = {
            "sha256": digest,
            "size_bytes": len(data),
        }

    @staticmethod
    def _zip_directory(source_dir: Path, zip_path: Path) -> None:
        """Recursively zip *source_dir* into *zip_path*."""
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in sorted(source_dir.rglob("*")):
                if file_path.is_file():
                    arcname = file_path.relative_to(source_dir.parent).as_posix()
                    zf.write(file_path, arcname)


def _article_str_to_int(art_str: str) -> int | None:
    """Extract the base article number from strings like 'Art. 50(3)' or 'Art. 9'."""
    cleaned = art_str.replace("Art.", "").strip()
    digits = ""
    for ch in cleaned:
        if ch.isdigit():
            digits += ch
        else:
            break
    if digits:
        return int(digits)
    return None  # pragma: no cover
