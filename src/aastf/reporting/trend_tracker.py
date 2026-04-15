"""Trend tracker — SQLite-backed cross-run vulnerability history."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from ..models.result import ScanReport


class TrendTracker:
    """Records scan runs to SQLite and queries trend data across runs."""

    DB_VERSION = 1
    DEFAULT_PATH = Path(".aastf") / "trend.db"

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or self.DEFAULT_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    generated_at TEXT NOT NULL,
                    adapter TEXT NOT NULL,
                    aastf_version TEXT NOT NULL,
                    total_scenarios INTEGER NOT NULL DEFAULT 0,
                    vulnerable INTEGER NOT NULL DEFAULT 0,
                    safe INTEGER NOT NULL DEFAULT 0,
                    inconclusive INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    eu_ai_act TEXT NOT NULL DEFAULT 'at_risk',
                    report_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_runs_generated_at
                ON runs(generated_at DESC)
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path))
        conn.row_factory = sqlite3.Row
        return conn

    def record(self, report: ScanReport) -> None:
        """Persist a ScanReport to the trend database."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO runs
                (run_id, generated_at, adapter, aastf_version,
                 total_scenarios, vulnerable, safe, inconclusive, errors,
                 risk_score, eu_ai_act, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.run_id,
                    report.generated_at.isoformat(),
                    report.adapter,
                    report.aastf_version,
                    report.total_scenarios,
                    report.vulnerable,
                    report.safe,
                    report.inconclusive,
                    report.errors,
                    report.overall_risk_score,
                    report.eu_ai_act_readiness,
                    report.model_dump_json(),
                ),
            )

    def last_n_runs(self, n: int = 10) -> list[dict]:
        """Return the last N run summaries (newest first)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY generated_at DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_run(self, run_id: str) -> ScanReport | None:
        """Load a full ScanReport by run_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            return None
        return ScanReport.model_validate_json(row["report_json"])

    def trend_summary(self, n: int = 10) -> dict:
        """Return trend data: risk score and vulnerability rate over last N runs."""
        runs = self.last_n_runs(n)
        if not runs:
            return {"runs": 0, "trend": "no_data"}

        scores = [r["risk_score"] for r in runs]
        vuln_rates = [
            r["vulnerable"] / r["total_scenarios"] if r["total_scenarios"] else 0
            for r in runs
        ]

        direction = "stable"
        if len(scores) >= 2:
            if scores[0] < scores[-1] * 0.9:
                direction = "improving"
            elif scores[0] > scores[-1] * 1.1:
                direction = "worsening"

        return {
            "runs": len(runs),
            "latest_risk_score": scores[0] if scores else 0,
            "previous_risk_score": scores[1] if len(scores) > 1 else None,
            "average_risk_score": round(sum(scores) / len(scores), 1),
            "average_vulnerability_rate": round(sum(vuln_rates) / len(vuln_rates) * 100, 1),
            "trend": direction,
            "run_ids": [r["run_id"] for r in runs],
        }

    def compare(self, run_id_a: str, run_id_b: str) -> dict:
        """Compare two runs. Returns delta in risk score, vulnerability counts, per-category."""
        a = self.get_run(run_id_a)
        b = self.get_run(run_id_b)
        if not a or not b:
            raise KeyError(f"Run not found: {run_id_a if not a else run_id_b}")

        return {
            "run_a": {"id": a.run_id, "date": a.generated_at.isoformat(), "risk_score": a.overall_risk_score, "vulnerable": a.vulnerable},
            "run_b": {"id": b.run_id, "date": b.generated_at.isoformat(), "risk_score": b.overall_risk_score, "vulnerable": b.vulnerable},
            "delta_risk_score": round(a.overall_risk_score - b.overall_risk_score, 1),
            "delta_vulnerable": a.vulnerable - b.vulnerable,
            "new_findings": [
                f.scenario_id for f in a.findings
                if f.scenario_id not in {x.scenario_id for x in b.findings}
            ],
            "resolved_findings": [
                f.scenario_id for f in b.findings
                if f.scenario_id not in {x.scenario_id for x in a.findings}
            ],
        }
