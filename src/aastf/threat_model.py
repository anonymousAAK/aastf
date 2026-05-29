"""STRIDE threat model for AASTF itself and security assessment data models."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from enum import Enum

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:

    class StrEnum(str, Enum):  # noqa: N801
        """Backport for Python 3.10."""

        def __str__(self) -> str:
            return self.value


from typing import Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class STRIDECategory(StrEnum):
    """STRIDE threat categories."""

    SPOOFING = "SPOOFING"
    TAMPERING = "TAMPERING"
    REPUDIATION = "REPUDIATION"
    INFO_DISCLOSURE = "INFO_DISCLOSURE"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    ELEVATION_OF_PRIVILEGE = "ELEVATION_OF_PRIVILEGE"


class ThreatEntry(BaseModel):
    """A single threat in the STRIDE model."""

    id: str
    category: STRIDECategory
    title: str
    description: str
    affected_component: str
    likelihood: Literal["low", "medium", "high"]
    impact: Literal["low", "medium", "high"]
    mitigations: list[str] = Field(default_factory=list)
    status: Literal["mitigated", "accepted", "open"]


class ThreatModel(BaseModel):
    """A complete STRIDE threat model."""

    name: str
    version: str
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    entries: list[ThreatEntry] = Field(default_factory=list)

    def by_category(self, category: STRIDECategory) -> list[ThreatEntry]:
        """Return entries filtered by STRIDE category."""
        return [e for e in self.entries if e.category == category]

    def by_status(self, status: Literal["mitigated", "accepted", "open"]) -> list[ThreatEntry]:
        """Return entries filtered by status."""
        return [e for e in self.entries if e.status == status]

    def open_threats(self) -> list[ThreatEntry]:
        """Return all threats that are not yet mitigated."""
        return [e for e in self.entries if e.status != "mitigated"]


# ---------------------------------------------------------------------------
# Pre-built AASTF threat model (12 threats)
# ---------------------------------------------------------------------------

_AASTF_THREATS: list[ThreatEntry] = [
    # --- Spoofing ---
    ThreatEntry(
        id="STRIDE-S-001",
        category=STRIDECategory.SPOOFING,
        title="Malicious scenario injection",
        description=(
            "An attacker crafts a scenario YAML file that masquerades as a "
            "legitimate test but instead instructs the target agent to perform "
            "harmful actions, bypassing the intended security evaluation."
        ),
        affected_component="scenario loader",
        likelihood="medium",
        impact="high",
        mitigations=[
            "Validate scenario YAML against JSON-Schema before loading",
            "Restrict scenario directories via allowlist configuration",
            "Sign built-in scenario bundles and verify signatures on load",
        ],
        status="mitigated",
    ),
    ThreatEntry(
        id="STRIDE-S-002",
        category=STRIDECategory.SPOOFING,
        title="Fake adapter responses",
        description=(
            "A compromised or malicious adapter returns fabricated agent "
            "responses, causing AASTF to report a safe verdict for an agent "
            "that is actually vulnerable."
        ),
        affected_component="adapter interface",
        likelihood="low",
        impact="high",
        mitigations=[
            "Adapter response schema validation",
            "Canary token injection to verify round-trip fidelity",
        ],
        status="mitigated",
    ),
    # --- Tampering ---
    ThreatEntry(
        id="STRIDE-T-001",
        category=STRIDECategory.TAMPERING,
        title="Scenario YAML manipulation",
        description=(
            "An attacker modifies scenario YAML files on disk to weaken test "
            "payloads, ensuring the target agent always appears safe."
        ),
        affected_component="scenario storage",
        likelihood="medium",
        impact="high",
        mitigations=[
            "File integrity monitoring (hash checksums) for scenario bundles",
            "Read-only filesystem mount for built-in scenarios",
        ],
        status="mitigated",
    ),
    ThreatEntry(
        id="STRIDE-T-002",
        category=STRIDECategory.TAMPERING,
        title="Report falsification",
        description=(
            "Scan reports are modified after generation to hide vulnerabilities "
            "or inflate safety scores before being shared with stakeholders."
        ),
        affected_component="report generator",
        likelihood="low",
        impact="high",
        mitigations=[
            "Cryptographic signing of generated reports (HMAC/digital signature)",
            "Immutable audit log of all scan results",
        ],
        status="mitigated",
    ),
    # --- Repudiation ---
    ThreatEntry(
        id="STRIDE-R-001",
        category=STRIDECategory.REPUDIATION,
        title="Scan result manipulation without audit trail",
        description=(
            "A user re-runs scans selectively and deletes unfavorable results, "
            "leaving no trace that a vulnerability was ever detected."
        ),
        affected_component="result storage",
        likelihood="medium",
        impact="medium",
        mitigations=[
            "Append-only event log for all scan executions",
            "Timestamped, signed run manifests with run-id lineage",
        ],
        status="open",
    ),
    ThreatEntry(
        id="STRIDE-R-002",
        category=STRIDECategory.REPUDIATION,
        title="Unattributed configuration changes",
        description=(
            "Configuration changes to scoring thresholds or scenario sets "
            "are made without attribution, allowing someone to silently "
            "lower the security bar."
        ),
        affected_component="configuration",
        likelihood="medium",
        impact="medium",
        mitigations=[
            "Version-controlled configuration with git blame",
            "Audit log entries for all config mutations",
        ],
        status="open",
    ),
    # --- Information Disclosure ---
    ThreatEntry(
        id="STRIDE-I-001",
        category=STRIDECategory.INFO_DISCLOSURE,
        title="API key leakage in traces",
        description=(
            "Agent traces captured during scanning contain API keys, tokens, "
            "or other secrets that are inadvertently persisted in reports or "
            "logs and may be exposed to unauthorized parties."
        ),
        affected_component="trace capture",
        likelihood="high",
        impact="high",
        mitigations=[
            "Automatic secret redaction in trace serialization",
            "Configurable redaction patterns (regex-based)",
            "Never persist raw HTTP headers in default mode",
        ],
        status="mitigated",
    ),
    ThreatEntry(
        id="STRIDE-I-002",
        category=STRIDECategory.INFO_DISCLOSURE,
        title="Scenario payload exposure",
        description=(
            "Adversarial payloads embedded in scenario definitions could be "
            "leaked to end users via error messages, logs, or UI rendering, "
            "teaching attackers how to exploit the target agent."
        ),
        affected_component="scenario payloads",
        likelihood="medium",
        impact="medium",
        mitigations=[
            "Restrict payload visibility to authorized roles only",
            "Redact payloads in user-facing error messages",
        ],
        status="accepted",
    ),
    # --- Denial of Service ---
    ThreatEntry(
        id="STRIDE-D-001",
        category=STRIDECategory.DENIAL_OF_SERVICE,
        title="Resource exhaustion via large scenarios",
        description=(
            "An extremely large or deeply nested scenario YAML consumes "
            "excessive memory or CPU during parsing, rendering the AASTF "
            "scanner unavailable."
        ),
        affected_component="scenario parser",
        likelihood="medium",
        impact="medium",
        mitigations=[
            "Enforce maximum scenario file size (default 1 MB)",
            "Limit YAML nesting depth during parsing",
            "Timeout on scenario load operations",
        ],
        status="mitigated",
    ),
    ThreatEntry(
        id="STRIDE-D-002",
        category=STRIDECategory.DENIAL_OF_SERVICE,
        title="Infinite loop in agent under test",
        description=(
            "The target agent enters an infinite loop or runaway generation "
            "during a scenario, consuming unbounded resources on the host "
            "running AASTF."
        ),
        affected_component="harness executor",
        likelihood="high",
        impact="medium",
        mitigations=[
            "Per-scenario execution timeout (configurable, default 60s)",
            "Token/step budget enforcement in adapter layer",
        ],
        status="mitigated",
    ),
    # --- Elevation of Privilege ---
    ThreatEntry(
        id="STRIDE-E-001",
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        title="Sandbox escape via agent under test",
        description=(
            "The agent under test exploits the AASTF harness to break out of "
            "the sandboxed execution environment and access the host system, "
            "reading files, spawning processes, or exfiltrating data."
        ),
        affected_component="sandbox / harness",
        likelihood="low",
        impact="high",
        mitigations=[
            "Run agent under test in isolated subprocess / container",
            "Restrict filesystem and network access via OS-level policies",
            "Drop privileges before invoking agent adapter",
        ],
        status="open",
    ),
    ThreatEntry(
        id="STRIDE-E-002",
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        title="Converter chain code execution",
        description=(
            "Custom scenario converters or evaluator plugins execute arbitrary "
            "code supplied by an attacker, gaining the privileges of the AASTF "
            "process."
        ),
        affected_component="plugin / converter system",
        likelihood="low",
        impact="high",
        mitigations=[
            "Allowlist-based plugin loading (no arbitrary module imports)",
            "Static analysis / sandboxed execution of custom evaluators",
        ],
        status="open",
    ),
]

AASTF_THREAT_MODEL = ThreatModel(
    name="AASTF Framework Threat Model",
    version="2.0.0",
    created_at=datetime(2026, 5, 29, tzinfo=timezone.utc),
    entries=_AASTF_THREATS,
)


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

_LIKELIHOOD_ORDER = {"low": 0, "medium": 1, "high": 2}
_IMPACT_ORDER = {"low": 0, "medium": 1, "high": 2}

_RISK_SCORE: dict[tuple[str, str], str] = {
    ("low", "low"): "LOW",
    ("low", "medium"): "LOW",
    ("low", "high"): "MEDIUM",
    ("medium", "low"): "LOW",
    ("medium", "medium"): "MEDIUM",
    ("medium", "high"): "HIGH",
    ("high", "low"): "MEDIUM",
    ("high", "medium"): "HIGH",
    ("high", "high"): "CRITICAL",
}


class ThreatModelReporter:
    """Generate human-readable reports from a ThreatModel."""

    # ---- Markdown ---------------------------------------------------------

    @staticmethod
    def to_markdown(model: ThreatModel) -> str:
        """Render a full STRIDE threat-model report as Markdown."""
        lines: list[str] = [
            f"# {model.name}",
            "",
            f"**Version:** {model.version}  ",
            f"**Created:** {model.created_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Total threats:** {len(model.entries)}",
            "",
        ]

        for cat in STRIDECategory:
            entries = model.by_category(cat)
            if not entries:
                continue
            lines.append(f"## {cat.value.replace('_', ' ').title()}")
            lines.append("")
            for e in entries:
                risk = _RISK_SCORE.get((e.likelihood, e.impact), "UNKNOWN")
                lines.append(f"### {e.id}: {e.title}")
                lines.append("")
                lines.append(f"- **Status:** {e.status}")
                lines.append(f"- **Likelihood:** {e.likelihood}  |  **Impact:** {e.impact}  |  **Risk:** {risk}")
                lines.append(f"- **Affected component:** {e.affected_component}")
                lines.append("")
                lines.append(e.description)
                lines.append("")
                if e.mitigations:
                    lines.append("**Mitigations:**")
                    for m in e.mitigations:
                        lines.append(f"- {m}")
                    lines.append("")

        return "\n".join(lines)

    # ---- HTML -------------------------------------------------------------

    @staticmethod
    def to_html(model: ThreatModel) -> str:
        """Render a styled HTML threat-model report."""
        status_colors = {
            "mitigated": "#27ae60",
            "accepted": "#f39c12",
            "open": "#e74c3c",
        }

        rows: list[str] = []
        for e in model.entries:
            risk = _RISK_SCORE.get((e.likelihood, e.impact), "UNKNOWN")
            color = status_colors.get(e.status, "#999")
            mits = "<br>".join(f"&bull; {m}" for m in e.mitigations) if e.mitigations else "&mdash;"
            rows.append(
                f"<tr>"
                f"<td>{e.id}</td>"
                f"<td>{e.category.value}</td>"
                f"<td>{e.title}</td>"
                f"<td>{e.likelihood}</td>"
                f"<td>{e.impact}</td>"
                f"<td><strong>{risk}</strong></td>"
                f'<td><span style="color:{color};font-weight:bold">{e.status}</span></td>'
                f"<td>{mits}</td>"
                f"</tr>"
            )

        table_rows = "\n".join(rows)
        return (
            "<!DOCTYPE html>\n"
            "<html lang='en'>\n"
            "<head><meta charset='utf-8'>\n"
            f"<title>{model.name}</title>\n"
            "<style>\n"
            "body{font-family:system-ui,sans-serif;margin:2em;color:#222}\n"
            "table{border-collapse:collapse;width:100%}\n"
            "th,td{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top}\n"
            "th{background:#2c3e50;color:#fff}\n"
            "tr:nth-child(even){background:#f9f9f9}\n"
            "</style>\n"
            "</head>\n"
            "<body>\n"
            f"<h1>{model.name}</h1>\n"
            f"<p><strong>Version:</strong> {model.version} | "
            f"<strong>Created:</strong> {model.created_at.strftime('%Y-%m-%d %H:%M UTC')} | "
            f"<strong>Total threats:</strong> {len(model.entries)}</p>\n"
            "<table>\n"
            "<tr><th>ID</th><th>Category</th><th>Title</th>"
            "<th>Likelihood</th><th>Impact</th><th>Risk</th>"
            "<th>Status</th><th>Mitigations</th></tr>\n"
            f"{table_rows}\n"
            "</table>\n"
            "</body>\n"
            "</html>"
        )

    # ---- Risk matrix ------------------------------------------------------

    @staticmethod
    def risk_matrix(model: ThreatModel) -> str:
        """Return an ASCII likelihood x impact matrix with threat counts."""
        levels = ["low", "medium", "high"]
        matrix: dict[tuple[str, str], list[str]] = {
            (lk, im): [] for lk in levels for im in levels
        }
        for e in model.entries:
            matrix[(e.likelihood, e.impact)].append(e.id)

        header = f"{'Likelihood / Impact':<22}| {'Low':<16}| {'Medium':<16}| {'High':<16}"
        sep = "-" * len(header)
        rows: list[str] = [header, sep]
        for lk in ["high", "medium", "low"]:
            cells: list[str] = []
            for im in levels:
                ids = matrix[(lk, im)]
                cells.append(f"{len(ids):<16}" if not ids else f"{','.join(ids):<16}")
            rows.append(f"{lk:<22}| {'| '.join(cells)}")
        rows.append(sep)
        return "\n".join(rows)

    # ---- Summary ----------------------------------------------------------

    @staticmethod
    def summary(model: ThreatModel) -> dict:
        """Return aggregate statistics for the threat model."""
        by_category: dict[str, int] = {}
        by_status: dict[str, int] = {"mitigated": 0, "accepted": 0, "open": 0}
        by_likelihood: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
        by_impact: dict[str, int] = {"low": 0, "medium": 0, "high": 0}
        risk_counts: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        for e in model.entries:
            cat_key = e.category.value
            by_category[cat_key] = by_category.get(cat_key, 0) + 1
            by_status[e.status] += 1
            by_likelihood[e.likelihood] += 1
            by_impact[e.impact] += 1
            risk = _RISK_SCORE.get((e.likelihood, e.impact), "UNKNOWN")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

        return {
            "total": len(model.entries),
            "by_category": by_category,
            "by_status": by_status,
            "by_likelihood": by_likelihood,
            "by_impact": by_impact,
            "risk_distribution": risk_counts,
            "open_count": by_status["open"],
            "mitigated_count": by_status["mitigated"],
            "accepted_count": by_status["accepted"],
        }
