"""Coverage metrics dashboard for AASTF scan reports.

Computes tool coverage, attack vector coverage, ASI category coverage,
verdict distribution, and an overall composite coverage score.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models.result import ScanReport, TestResult, Verdict
from .models.scenario import ASICategory, InjectionPoint
from .scenarios.registry import ScenarioRegistry

# ---------------------------------------------------------------------------
# Attack vector mapping: InjectionPoint -> human-readable vector name
# ---------------------------------------------------------------------------

_VECTOR_MAP: dict[str, str] = {
    InjectionPoint.USER_MESSAGE: "direct_input",
    InjectionPoint.TOOL_RESPONSE: "tool_output",
    InjectionPoint.MEMORY: "memory_write",
    InjectionPoint.SYSTEM_PROMPT: "system_prompt",
}

# All known attack vectors (including inter-agent which is tag-derived)
ALL_VECTORS = ["direct_input", "tool_output", "inter_agent_message", "memory_write", "system_prompt"]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class VectorStats(BaseModel):
    """Statistics for a single attack vector."""

    name: str
    scenario_count: int = 0
    vulnerable_count: int = 0
    safe_count: int = 0


class AttackVectorCoverage(BaseModel):
    """Coverage across attack vectors."""

    vectors: dict[str, VectorStats] = Field(default_factory=dict)
    total_scenarios: int = 0


class CategoryStats(BaseModel):
    """Statistics for a single ASI category."""

    category: str
    scenario_count: int = 0
    vulnerable: int = 0
    safe: int = 0
    risk_score: float = 0.0


class ASICoverage(BaseModel):
    """Coverage across ASI categories."""

    categories: dict[str, CategoryStats] = Field(default_factory=dict)
    total_categories: int = 0
    covered_categories: int = 0


class ToolCoverage(BaseModel):
    """Coverage of tools tested under adversarial conditions."""

    total_tools: int = 0
    tested_tools: int = 0
    coverage_pct: float = 0.0
    untested_tools: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VULNERABLE_VERDICTS = {
    Verdict.VULNERABLE,
    Verdict.TOOL_POISONING,
    Verdict.SCHEMA_POISONING,
    Verdict.PREFERENCE_MANIPULATION,
    Verdict.REFUSAL_ECHO,
}


def _is_vulnerable(verdict: Verdict) -> bool:
    return verdict in _VULNERABLE_VERDICTS


def _vector_for_result(result: TestResult, registry: ScenarioRegistry | None) -> str:
    """Determine the attack vector for a test result."""
    if registry is not None and result.scenario_id in registry:
        scenario = registry.get(result.scenario_id)
        # Inter-agent detection via tags
        if any("inter-agent" in t.lower() or "inter_agent" in t.lower() for t in scenario.tags):
            return "inter_agent_message"
        return _VECTOR_MAP.get(str(scenario.inject_into), "direct_input")
    # Fallback: try to infer from category
    cat = result.category.value
    if cat == "ASI07":
        return "inter_agent_message"
    if cat == "ASI06":
        return "memory_write"
    return "direct_input"


# ---------------------------------------------------------------------------
# CoverageAnalyzer
# ---------------------------------------------------------------------------


class CoverageAnalyzer:
    """Compute coverage metrics from a completed scan report."""

    def __init__(
        self,
        report: ScanReport,
        registry: ScenarioRegistry | None = None,
    ) -> None:
        self._report = report
        self._registry = registry

    # ---- Tool coverage -----------------------------------------------------

    def tool_coverage(self) -> ToolCoverage:
        """Percentage of available tools tested under adversarial conditions."""
        all_tools: set[str] = set()
        tested_tools: set[str] = set()

        # Gather tools from registry scenarios
        if self._registry is not None:
            for s in self._registry.all():
                all_tools.update(s.available_tools)

        # Gather tools actually invoked during test runs
        for r in self._report.results:
            tested_tools.update(r.trace.tools_called())

        # Also include tools declared in scenarios that were actually run
        run_ids = {r.scenario_id for r in self._report.results}
        if self._registry is not None:
            for s in self._registry.all():
                if s.id in run_ids:
                    all_tools.update(s.available_tools)

        # If no registry, all_tools = tested_tools (100% by definition)
        if not all_tools:
            all_tools = tested_tools.copy()

        total = len(all_tools)
        tested = len(all_tools & tested_tools) if all_tools else 0
        untested = sorted(all_tools - tested_tools)
        pct = round((tested / total) * 100, 1) if total > 0 else 0.0

        return ToolCoverage(
            total_tools=total,
            tested_tools=tested,
            coverage_pct=pct,
            untested_tools=untested,
        )

    # ---- Attack vector coverage --------------------------------------------

    def attack_vector_coverage(self) -> AttackVectorCoverage:
        """Coverage across attack vectors (injection points)."""
        vectors: dict[str, VectorStats] = {
            v: VectorStats(name=v) for v in ALL_VECTORS
        }

        for r in self._report.results:
            vec = _vector_for_result(r, self._registry)
            if vec not in vectors:
                vectors[vec] = VectorStats(name=vec)
            vectors[vec].scenario_count += 1
            if _is_vulnerable(r.verdict):
                vectors[vec].vulnerable_count += 1
            elif r.verdict == Verdict.SAFE:
                vectors[vec].safe_count += 1

        return AttackVectorCoverage(
            vectors=vectors,
            total_scenarios=len(self._report.results),
        )

    # ---- ASI category coverage ---------------------------------------------

    def asi_coverage(self) -> ASICoverage:
        """Scenarios per ASI category with risk score."""
        cats: dict[str, CategoryStats] = {}
        all_categories = {c.value for c in ASICategory}

        for r in self._report.results:
            cat = r.category.value
            if cat not in cats:
                cats[cat] = CategoryStats(category=cat)
            cats[cat].scenario_count += 1
            if _is_vulnerable(r.verdict):
                cats[cat].vulnerable += 1
            elif r.verdict == Verdict.SAFE:
                cats[cat].safe += 1

        # Compute risk_score per category: vulnerable / total * 100
        for cs in cats.values():
            if cs.scenario_count > 0:
                cs.risk_score = round(
                    (cs.vulnerable / cs.scenario_count) * 100, 1
                )

        return ASICoverage(
            categories=cats,
            total_categories=len(all_categories),
            covered_categories=len(cats),
        )

    # ---- Verdict distribution ----------------------------------------------

    def verdict_distribution(self) -> dict[str, int]:
        """Count of each verdict type across all results."""
        dist: dict[str, int] = {}
        for r in self._report.results:
            key = str(r.verdict)
            dist[key] = dist.get(key, 0) + 1
        return dict(sorted(dist.items()))

    # ---- Overall score -----------------------------------------------------

    def overall_score(self) -> float:
        """Composite coverage score 0-100.

        Weights:
          - Tool coverage:           25%
          - Attack vector coverage:  25%
          - ASI category coverage:   30%
          - Safety rate:             20%
        """
        tc = self.tool_coverage()
        avc = self.attack_vector_coverage()
        asic = self.asi_coverage()

        # Tool coverage component (0-100)
        tool_score = tc.coverage_pct

        # Attack vector component: % of known vectors exercised
        exercised = sum(1 for v in avc.vectors.values() if v.scenario_count > 0)
        vector_score = round((exercised / len(ALL_VECTORS)) * 100, 1) if ALL_VECTORS else 0.0

        # ASI category component: % of categories covered
        cat_score = round(
            (asic.covered_categories / asic.total_categories) * 100, 1
        ) if asic.total_categories > 0 else 0.0

        # Safety rate: % of results that are SAFE
        total = len(self._report.results)
        safe_count = sum(1 for r in self._report.results if r.verdict == Verdict.SAFE)
        safety_score = round((safe_count / total) * 100, 1) if total > 0 else 0.0

        composite = (
            tool_score * 0.25
            + vector_score * 0.25
            + cat_score * 0.30
            + safety_score * 0.20
        )
        return round(min(composite, 100.0), 1)

    # ---- Serialization -----------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """Full coverage report as a JSON-serializable dict."""
        return {
            "tool_coverage": self.tool_coverage().model_dump(),
            "attack_vector_coverage": self.attack_vector_coverage().model_dump(),
            "asi_coverage": self.asi_coverage().model_dump(),
            "verdict_distribution": self.verdict_distribution(),
            "overall_score": self.overall_score(),
        }

    def to_console(self) -> str:
        """Rich-formatted console output for coverage metrics."""
        tc = self.tool_coverage()
        avc = self.attack_vector_coverage()
        asic = self.asi_coverage()
        vd = self.verdict_distribution()
        score = self.overall_score()

        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("  AASTF Coverage Dashboard")
        lines.append("=" * 60)
        lines.append("")

        # Overall score
        lines.append(f"  Overall Coverage Score: {score}/100")
        lines.append("")

        # Tool coverage
        lines.append("-- Tool Coverage --")
        lines.append(f"  Tested: {tc.tested_tools}/{tc.total_tools} ({tc.coverage_pct}%)")
        if tc.untested_tools:
            lines.append(f"  Untested: {', '.join(tc.untested_tools)}")
        lines.append("")

        # Attack vector coverage
        lines.append("-- Attack Vector Coverage --")
        for _vec_name, vs in sorted(avc.vectors.items()):
            if vs.scenario_count > 0:
                lines.append(
                    f"  {vs.name}: {vs.scenario_count} scenarios "
                    f"({vs.vulnerable_count} vuln, {vs.safe_count} safe)"
                )
            else:
                lines.append(f"  {vs.name}: not tested")
        lines.append("")

        # ASI category coverage
        lines.append("-- ASI Category Coverage --")
        lines.append(
            f"  Covered: {asic.covered_categories}/{asic.total_categories} categories"
        )
        for cat_id in sorted(asic.categories):
            cs = asic.categories[cat_id]
            bar = _risk_bar(cs.risk_score)
            lines.append(
                f"  {cs.category}: {cs.scenario_count} scenarios "
                f"| risk {cs.risk_score}% {bar}"
            )
        lines.append("")

        # Verdict distribution
        lines.append("-- Verdict Distribution --")
        for verdict_str, count in sorted(vd.items()):
            lines.append(f"  {verdict_str}: {count}")
        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)

    def to_html(self, output_path: Path) -> None:
        """Generate a self-contained HTML dashboard with heatmap."""
        tc = self.tool_coverage()
        avc = self.attack_vector_coverage()
        asic = self.asi_coverage()
        vd = self.verdict_distribution()
        score = self.overall_score()

        # Build ASI heatmap rows
        all_cats = sorted(ASICategory, key=lambda c: c.value)
        heatmap_rows: list[str] = []
        for cat in all_cats:
            cat_val = cat.value
            cat_name = html.escape(cat.display_name)
            if cat_val in asic.categories:
                cs = asic.categories[cat_val]
                risk = cs.risk_score
                color = _risk_color(risk)
                cell = (
                    f'<tr>'
                    f'<td class="cat-id">{html.escape(cat_val)}</td>'
                    f'<td>{cat_name}</td>'
                    f'<td style="background:{color};color:#fff;text-align:center;font-weight:bold;">'
                    f'{risk}%</td>'
                    f'<td>{cs.scenario_count}</td>'
                    f'<td>{cs.vulnerable}</td>'
                    f'<td>{cs.safe}</td>'
                    f'</tr>'
                )
            else:
                cell = (
                    f'<tr>'
                    f'<td class="cat-id">{html.escape(cat_val)}</td>'
                    f'<td>{cat_name}</td>'
                    f'<td style="background:#9e9e9e;color:#fff;text-align:center;">'
                    f'N/A</td>'
                    f'<td>0</td><td>0</td><td>0</td>'
                    f'</tr>'
                )
            heatmap_rows.append(cell)

        # Verdict distribution rows
        verdict_rows = ""
        for v_str, count in sorted(vd.items()):
            verdict_rows += f"<tr><td>{html.escape(v_str)}</td><td>{count}</td></tr>\n"

        # Vector rows
        vector_rows = ""
        for vec_name in ALL_VECTORS:
            vs = avc.vectors.get(vec_name, VectorStats(name=vec_name))
            status = "tested" if vs.scenario_count > 0 else "untested"
            vector_rows += (
                f"<tr class='{status}'>"
                f"<td>{html.escape(vs.name)}</td>"
                f"<td>{vs.scenario_count}</td>"
                f"<td>{vs.vulnerable_count}</td>"
                f"<td>{vs.safe_count}</td>"
                f"</tr>\n"
            )

        # Score gauge color
        gauge_color = _risk_color(100 - score)  # invert: high score = green

        page = _HTML_TEMPLATE.format(
            score=score,
            gauge_color=gauge_color,
            tool_tested=tc.tested_tools,
            tool_total=tc.total_tools,
            tool_pct=tc.coverage_pct,
            untested_tools=html.escape(", ".join(tc.untested_tools)) if tc.untested_tools else "None",
            heatmap_rows="\n".join(heatmap_rows),
            vector_rows=vector_rows,
            verdict_rows=verdict_rows,
            covered_cats=asic.covered_categories,
            total_cats=asic.total_categories,
            total_scenarios=avc.total_scenarios,
            json_dump=html.escape(json.dumps(self.to_json(), indent=2)),
        )

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(page, encoding="utf-8")


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _risk_bar(risk: float) -> str:
    """ASCII risk bar: 10 chars wide."""
    filled = int(risk / 10)
    return "[" + "#" * filled + "." * (10 - filled) + "]"


def _risk_color(risk: float) -> str:
    """Return CSS color for a risk percentage (0=green, 100=red)."""
    if risk <= 0:
        return "#4caf50"
    if risk <= 25:
        return "#8bc34a"
    if risk <= 50:
        return "#ff9800"
    if risk <= 75:
        return "#f44336"
    return "#b71c1c"


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AASTF Coverage Dashboard</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #f5f5f5; color: #333; padding: 24px; }}
  h1 {{ text-align: center; margin-bottom: 8px; }}
  .subtitle {{ text-align: center; color: #666; margin-bottom: 24px; }}
  .score-box {{ text-align: center; margin: 24px auto; padding: 24px;
                background: {gauge_color}; color: #fff; border-radius: 12px;
                max-width: 300px; font-size: 48px; font-weight: bold; }}
  .score-label {{ font-size: 14px; font-weight: normal; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px;
           max-width: 1100px; margin: 0 auto; }}
  .card {{ background: #fff; border-radius: 8px; padding: 20px;
           box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
  .card h2 {{ margin-bottom: 12px; font-size: 18px; color: #444; }}
  .full-width {{ grid-column: 1 / -1; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ background: #fafafa; font-weight: 600; }}
  .cat-id {{ font-family: monospace; font-weight: 600; }}
  tr.untested td {{ color: #999; }}
  .meta {{ font-size: 12px; color: #999; margin-top: 16px; }}
  pre {{ background: #263238; color: #eeffff; padding: 16px; border-radius: 6px;
         overflow-x: auto; font-size: 12px; max-height: 400px; }}
</style>
</head>
<body>
<h1>AASTF Coverage Dashboard</h1>
<p class="subtitle">Agentic AI Security Testing Framework</p>

<div class="score-box">
  {score}<span class="score-label"> / 100</span>
</div>

<div class="grid">

  <div class="card">
    <h2>Tool Coverage</h2>
    <p>{tool_tested} / {tool_total} tools tested ({tool_pct}%)</p>
    <p style="margin-top:8px;font-size:13px;color:#777;">Untested: {untested_tools}</p>
  </div>

  <div class="card">
    <h2>Attack Vector Coverage</h2>
    <p>{total_scenarios} total scenarios</p>
    <table>
      <tr><th>Vector</th><th>Scenarios</th><th>Vulnerable</th><th>Safe</th></tr>
      {vector_rows}
    </table>
  </div>

  <div class="card full-width">
    <h2>ASI Category Heatmap</h2>
    <p>{covered_cats} / {total_cats} categories covered</p>
    <table>
      <tr><th>ID</th><th>Category</th><th>Risk</th><th>Scenarios</th><th>Vulnerable</th><th>Safe</th></tr>
      {heatmap_rows}
    </table>
  </div>

  <div class="card">
    <h2>Verdict Distribution</h2>
    <table>
      <tr><th>Verdict</th><th>Count</th></tr>
      {verdict_rows}
    </table>
  </div>

  <div class="card">
    <h2>Raw JSON</h2>
    <pre>{json_dump}</pre>
  </div>

</div>

<p class="meta" style="text-align:center;margin-top:24px;">
  Generated by AASTF Coverage Analyzer
</p>
</body>
</html>
"""
