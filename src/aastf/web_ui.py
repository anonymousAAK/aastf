"""Web UI backend server for ``aastf view``.

> **Status: Stable surface — local/dev use only.** The dashboard renders scan
> results with the standard-library HTTP server: it is single-threaded, has no
> TLS, and is not hardened for untrusted input. Run it locally; do not expose it
> to production traffic. The rendered HTML/JSON output format is stable and
> covered by tests.

Serves scan results as an interactive HTML dashboard using only stdlib
(http.server, json, pathlib) — no Flask / FastAPI dependency.
"""

from __future__ import annotations

import html
import json
import logging
import secrets
import threading
import webbrowser
from datetime import datetime, timezone
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models.result import ScanReport, Verdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic config / data models
# ---------------------------------------------------------------------------


class DashboardData(BaseModel):
    """Serialisable wrapper around a rendered report snapshot."""

    report: dict[str, Any]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "2.0.0"


class WebUIConfig(BaseModel):
    """Configuration for the local web UI server."""

    host: str = "127.0.0.1"
    port: int = 8080
    auto_open: bool = True
    report_path: Path | None = None


# ---------------------------------------------------------------------------
# Verdict / risk helpers
# ---------------------------------------------------------------------------

_VULNERABLE_VERDICTS = {
    Verdict.VULNERABLE,
    Verdict.TOOL_POISONING,
    Verdict.SCHEMA_POISONING,
    Verdict.PREFERENCE_MANIPULATION,
    Verdict.REFUSAL_ECHO,
    Verdict.INFECTION_PROPAGATED,
    Verdict.COLLUSION,
    Verdict.WATCHDOG_BYPASS,
}

_VERDICT_COLORS: dict[str, str] = {
    "VULNERABLE": "#e74c3c",
    "REFUSAL_ECHO": "#e67e22",
    "SAFE": "#2ecc71",
    "INCONCLUSIVE": "#95a5a6",
    "ERROR": "#7f8c8d",
    "TOOL_POISONING": "#c0392b",
    "SCHEMA_POISONING": "#d35400",
    "PREFERENCE_MANIPULATION": "#f39c12",
    "INFECTION_PROPAGATED": "#8e44ad",
    "COLLUSION": "#2c3e50",
    "WATCHDOG_BYPASS": "#e74c3c",
}


def _risk_color(risk: float) -> str:
    if risk <= 0:
        return "#4caf50"
    if risk <= 25:
        return "#8bc34a"
    if risk <= 50:
        return "#ff9800"
    if risk <= 75:
        return "#f44336"
    return "#b71c1c"


def _gauge_color(score: float) -> str:
    """Color for overall risk score gauge (0=green, 100=red)."""
    return _risk_color(score)


# ---------------------------------------------------------------------------
# HTML generators
# ---------------------------------------------------------------------------


def _verdict_distribution(report: ScanReport) -> dict[str, int]:
    dist: dict[str, int] = {}
    for r in report.results:
        key = str(r.verdict)
        dist[key] = dist.get(key, 0) + 1
    return dict(sorted(dist.items()))


def _category_stats(report: ScanReport) -> dict[str, dict[str, int]]:
    cats: dict[str, dict[str, int]] = {}
    for r in report.results:
        cat = r.category.value
        if cat not in cats:
            cats[cat] = {"total": 0, "vulnerable": 0, "safe": 0}
        cats[cat]["total"] += 1
        if r.verdict in _VULNERABLE_VERDICTS:
            cats[cat]["vulnerable"] += 1
        elif r.verdict == Verdict.SAFE:
            cats[cat]["safe"] += 1
    return dict(sorted(cats.items()))


class WebUIServer:
    """Local HTTP server that serves scan results as an interactive dashboard.

    .. warning:: Development only

        This server uses Python's stdlib ``http.server`` module, which is
        **not suitable for production use**. It is single-threaded, has no
        TLS support, and lacks hardened request handling.

        For production deployments, serve the dashboard behind a proper ASGI
        server such as **uvicorn** or **gunicorn** and place it behind a
        reverse proxy (e.g. nginx, Caddy, or a cloud load balancer) that
        provides TLS termination, rate limiting, and access control.
    """

    def __init__(self, config: WebUIConfig) -> None:
        self.config = config
        self._report: ScanReport | None = None
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._csrf_token: str = secrets.token_hex(32)

    def load_report(self, report: ScanReport) -> None:
        """Load a scan report for serving."""
        self._report = report

    # ------------------------------------------------------------------ HTML

    def generate_dashboard_html(self, report: ScanReport) -> str:
        """Full HTML dashboard with summary, pie chart, bar chart, table, gauge."""
        vd = _verdict_distribution(report)
        cats = _category_stats(report)
        risk = report.overall_risk_score
        gauge_col = _gauge_color(risk)

        # SVG pie chart for verdict distribution
        pie_svg = self._build_pie_svg(vd)

        # SVG bar chart for categories
        bar_svg = self._build_bar_svg(cats)

        # Risk gauge SVG
        gauge_svg = self._build_gauge_svg(risk, gauge_col)

        # Results table rows
        table_rows = self._build_results_table(report)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AASTF Dashboard</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#f5f5f5; color:#333; padding:24px; }}
h1 {{ text-align:center; margin-bottom:8px; }}
.subtitle {{ text-align:center; color:#666; margin-bottom:24px; }}
.grid {{ display:grid; grid-template-columns:1fr 1fr; gap:24px;
         max-width:1200px; margin:0 auto; }}
.card {{ background:#fff; border-radius:8px; padding:20px;
         box-shadow:0 1px 3px rgba(0,0,0,.12); }}
.card h2 {{ margin-bottom:12px; font-size:18px; color:#444; }}
.full-width {{ grid-column:1/-1; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th,td {{ padding:8px 12px; text-align:left; border-bottom:1px solid #eee; }}
th {{ background:#fafafa; font-weight:600; }}
.stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; }}
.stat-box {{ text-align:center; padding:16px; border-radius:8px; background:#fafafa; }}
.stat-box .num {{ font-size:32px; font-weight:bold; }}
.stat-box .lbl {{ font-size:12px; color:#888; text-transform:uppercase; }}
.gauge-wrap {{ text-align:center; margin:16px 0; }}
nav {{ text-align:center; margin-bottom:24px; }}
nav a {{ display:inline-block; margin:0 8px; padding:8px 16px; background:#1a73e8;
         color:#fff; text-decoration:none; border-radius:4px; font-size:14px; }}
nav a:hover {{ background:#1557b0; }}
.filter-row {{ margin-bottom:12px; }}
.filter-row input {{ padding:6px 12px; border:1px solid #ddd; border-radius:4px;
                     width:300px; font-size:14px; }}
.verdict-badge {{ display:inline-block; padding:2px 8px; border-radius:3px;
                  color:#fff; font-size:12px; font-weight:600; }}
.meta {{ font-size:12px; color:#999; text-align:center; margin-top:24px; }}
</style>
</head>
<body>
<h1>AASTF Dashboard</h1>
<p class="subtitle">Agentic AI Security Testing Framework</p>
<nav>
  <a href="/">Dashboard</a>
  <a href="/explorer">Scenario Explorer</a>
  <a href="/coverage">Coverage Heatmap</a>
  <a href="/blast-radius">Blast Radius</a>
</nav>

<div class="grid">

  <div class="card full-width">
    <div class="stat-grid">
      <div class="stat-box">
        <div class="num">{report.total_scenarios}</div>
        <div class="lbl">Total Scenarios</div>
      </div>
      <div class="stat-box" style="color:#e74c3c">
        <div class="num">{report.vulnerable}</div>
        <div class="lbl">Vulnerable</div>
      </div>
      <div class="stat-box" style="color:#2ecc71">
        <div class="num">{report.safe}</div>
        <div class="lbl">Safe</div>
      </div>
      <div class="stat-box">
        <div class="num">{report.errors}</div>
        <div class="lbl">Errors</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Risk Score</h2>
    <div class="gauge-wrap">{gauge_svg}</div>
  </div>

  <div class="card">
    <h2>Verdict Distribution</h2>
    {pie_svg}
  </div>

  <div class="card full-width">
    <h2>Category Breakdown</h2>
    {bar_svg}
  </div>

  <div class="card full-width">
    <h2>Scenario Results</h2>
    <div class="filter-row">
      <input type="text" id="tbl-filter" placeholder="Filter scenarios..."
             oninput="filterTable(this.value)">
    </div>
    <table id="results-table">
      <thead>
        <tr><th>Scenario ID</th><th>Name</th><th>Category</th>
            <th>Severity</th><th>Verdict</th><th>Time (ms)</th></tr>
      </thead>
      <tbody>{table_rows}</tbody>
    </table>
  </div>

</div>

<p class="meta">Generated by AASTF v{html.escape(report.aastf_version)}
 at {html.escape(str(report.generated_at))}</p>
<script>
function filterTable(q) {{
  var rows = document.querySelectorAll('#results-table tbody tr');
  q = q.toLowerCase();
  rows.forEach(function(r) {{
    r.style.display = r.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    def generate_scenario_explorer_html(self, report: ScanReport) -> str:
        """Searchable / filterable scenario list page."""
        rows = self._build_results_table(report)
        verdicts_json = html.escape(json.dumps(list({str(r.verdict) for r in report.results})))
        cats_json = html.escape(json.dumps(sorted({r.category.value for r in report.results})))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AASTF Scenario Explorer</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#f5f5f5; color:#333; padding:24px; }}
h1 {{ text-align:center; margin-bottom:16px; }}
nav {{ text-align:center; margin-bottom:24px; }}
nav a {{ display:inline-block; margin:0 8px; padding:8px 16px; background:#1a73e8;
         color:#fff; text-decoration:none; border-radius:4px; font-size:14px; }}
.filters {{ max-width:1100px; margin:0 auto 16px; display:flex; gap:12px; flex-wrap:wrap; }}
.filters input,.filters select {{ padding:6px 12px; border:1px solid #ddd;
                                   border-radius:4px; font-size:14px; }}
.filters input {{ flex:1; min-width:200px; }}
table {{ width:100%; max-width:1100px; margin:0 auto; border-collapse:collapse;
         font-size:14px; background:#fff; border-radius:8px; overflow:hidden;
         box-shadow:0 1px 3px rgba(0,0,0,.12); }}
th,td {{ padding:8px 12px; text-align:left; border-bottom:1px solid #eee; }}
th {{ background:#fafafa; font-weight:600; }}
.verdict-badge {{ display:inline-block; padding:2px 8px; border-radius:3px;
                  color:#fff; font-size:12px; font-weight:600; }}
</style>
</head>
<body>
<h1>Scenario Explorer</h1>
<nav>
  <a href="/">Dashboard</a>
  <a href="/explorer">Explorer</a>
  <a href="/coverage">Coverage</a>
  <a href="/blast-radius">Blast Radius</a>
</nav>
<div class="filters">
  <input type="text" id="search" placeholder="Search scenarios..."
         oninput="applyFilters()">
  <select id="verdict-filter" onchange="applyFilters()">
    <option value="">All Verdicts</option>
  </select>
  <select id="cat-filter" onchange="applyFilters()">
    <option value="">All Categories</option>
  </select>
</div>
<table id="explorer-table">
  <thead>
    <tr><th>Scenario ID</th><th>Name</th><th>Category</th>
        <th>Severity</th><th>Verdict</th><th>Time (ms)</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<script>
(function() {{
  var verdicts = JSON.parse('{verdicts_json}'.replace(/&amp;/g,'&').replace(/&quot;/g,'"'));
  var cats = JSON.parse('{cats_json}'.replace(/&amp;/g,'&').replace(/&quot;/g,'"'));
  var vf = document.getElementById('verdict-filter');
  verdicts.sort();
  verdicts.forEach(function(v) {{
    var o = document.createElement('option'); o.value=v; o.textContent=v; vf.appendChild(o);
  }});
  var cf = document.getElementById('cat-filter');
  cats.forEach(function(c) {{
    var o = document.createElement('option'); o.value=c; o.textContent=c; cf.appendChild(o);
  }});
}})();
function applyFilters() {{
  var q = document.getElementById('search').value.toLowerCase();
  var v = document.getElementById('verdict-filter').value;
  var c = document.getElementById('cat-filter').value;
  var rows = document.querySelectorAll('#explorer-table tbody tr');
  rows.forEach(function(r) {{
    var text = r.textContent.toLowerCase();
    var verdict = r.getAttribute('data-verdict') || '';
    var cat = r.getAttribute('data-category') || '';
    var show = text.indexOf(q) >= 0
               && (v === '' || verdict === v)
               && (c === '' || cat === c);
    r.style.display = show ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    def generate_coverage_html(self, report: ScanReport) -> str:
        """Coverage heatmap page."""
        cats = _category_stats(report)
        heatmap_rows = ""
        for cat_id, st in cats.items():
            total = st["total"]
            vuln = st["vulnerable"]
            safe = st["safe"]
            risk = round((vuln / total) * 100, 1) if total > 0 else 0.0
            color = _risk_color(risk)
            heatmap_rows += (
                f'<tr><td style="font-family:monospace;font-weight:600">'
                f'{html.escape(cat_id)}</td>'
                f'<td style="background:{color};color:#fff;text-align:center;'
                f'font-weight:bold">{risk}%</td>'
                f'<td>{total}</td><td>{vuln}</td><td>{safe}</td></tr>\n'
            )

        vd = _verdict_distribution(report)
        verdict_rows = ""
        for v_str, count in vd.items():
            verdict_rows += f"<tr><td>{html.escape(v_str)}</td><td>{count}</td></tr>\n"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AASTF Coverage Heatmap</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#f5f5f5; color:#333; padding:24px; }}
h1 {{ text-align:center; margin-bottom:16px; }}
nav {{ text-align:center; margin-bottom:24px; }}
nav a {{ display:inline-block; margin:0 8px; padding:8px 16px; background:#1a73e8;
         color:#fff; text-decoration:none; border-radius:4px; font-size:14px; }}
.grid {{ display:grid; grid-template-columns:1fr 1fr; gap:24px;
         max-width:1100px; margin:0 auto; }}
.card {{ background:#fff; border-radius:8px; padding:20px;
         box-shadow:0 1px 3px rgba(0,0,0,.12); }}
.card h2 {{ margin-bottom:12px; font-size:18px; color:#444; }}
.full-width {{ grid-column:1/-1; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th,td {{ padding:8px 12px; text-align:left; border-bottom:1px solid #eee; }}
th {{ background:#fafafa; font-weight:600; }}
</style>
</head>
<body>
<h1>Coverage Heatmap</h1>
<nav>
  <a href="/">Dashboard</a>
  <a href="/explorer">Explorer</a>
  <a href="/coverage">Coverage</a>
  <a href="/blast-radius">Blast Radius</a>
</nav>
<div class="grid">
  <div class="card full-width">
    <h2>ASI Category Heatmap</h2>
    <table>
      <tr><th>Category</th><th>Risk</th><th>Scenarios</th>
          <th>Vulnerable</th><th>Safe</th></tr>
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
    <h2>Summary</h2>
    <p>Total scenarios: {report.total_scenarios}</p>
    <p>Vulnerability rate: {report.vulnerability_rate}%</p>
    <p>Risk score: {report.overall_risk_score}</p>
  </div>
</div>
</body>
</html>"""

    def generate_blast_radius_html(self, report: ScanReport) -> str:
        """Blast radius SVG visualization page."""
        # Build a simplified agent graph from results
        agents: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        cat_set: set[str] = set()
        for r in report.results:
            cat = r.category.value
            if cat not in cat_set:
                cat_set.add(cat)
                is_vuln = r.verdict in _VULNERABLE_VERDICTS
                color = "#e74c3c" if is_vuln else "#2ecc71"
                agents.append({"id": cat, "color": color, "affected": is_vuln})

        cat_list = sorted(cat_set)
        for i in range(len(cat_list) - 1):
            edges.append({"source": cat_list[i], "target": cat_list[i + 1],
                          "contaminated": False})

        nodes_json = html.escape(json.dumps(agents))
        edges_json = html.escape(json.dumps(edges))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AASTF Blast Radius</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#1a1a2e; color:#eee; padding:24px; }}
h1 {{ text-align:center; margin-bottom:16px; color:#e94560; }}
nav {{ text-align:center; margin-bottom:24px; }}
nav a {{ display:inline-block; margin:0 8px; padding:8px 16px; background:#0f3460;
         color:#fff; text-decoration:none; border-radius:4px; font-size:14px; }}
svg {{ width:100%; height:500px; display:block; margin:0 auto; }}
.legend {{ text-align:center; margin-top:16px; font-size:13px; }}
.legend span {{ margin:0 12px; }}
</style>
</head>
<body>
<h1>Blast Radius</h1>
<nav>
  <a href="/">Dashboard</a>
  <a href="/explorer">Explorer</a>
  <a href="/coverage">Coverage</a>
  <a href="/blast-radius">Blast Radius</a>
</nav>
<svg id="svg"></svg>
<div class="legend">
  <span style="color:#e74c3c">&#9679; Vulnerable</span>
  <span style="color:#2ecc71">&#9679; Safe</span>
</div>
<script>
(function() {{
  var nodes = JSON.parse('{nodes_json}'.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"'));
  var edges = JSON.parse('{edges_json}'.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"'));
  var svg = document.getElementById('svg');
  var ns = 'http://www.w3.org/2000/svg';
  var W = svg.clientWidth || 800, H = 500;
  var R = 28, n = nodes.length;
  if (n === 0) return;
  var cx = W/2, cy = H/2, radius = Math.min(W,H)/2 - 60;
  if (n === 1) radius = 0;
  for (var i=0;i<n;i++) {{
    var angle = (2*Math.PI*i/n) - Math.PI/2;
    nodes[i].x = cx + radius*Math.cos(angle);
    nodes[i].y = cy + radius*Math.sin(angle);
  }}
  var map = {{}};
  nodes.forEach(function(nd) {{ map[nd.id] = nd; }});
  edges.forEach(function(e) {{
    var s=map[e.source], t=map[e.target];
    if(!s||!t)return;
    var line=document.createElementNS(ns,'line');
    line.setAttribute('x1',s.x); line.setAttribute('y1',s.y);
    line.setAttribute('x2',t.x); line.setAttribute('y2',t.y);
    line.setAttribute('stroke', e.contaminated?'#e74c3c':'#334');
    line.setAttribute('stroke-width','1.5');
    svg.appendChild(line);
  }});
  nodes.forEach(function(nd) {{
    var c=document.createElementNS(ns,'circle');
    c.setAttribute('cx',nd.x); c.setAttribute('cy',nd.y);
    c.setAttribute('r',R); c.setAttribute('fill',nd.color);
    c.setAttribute('stroke','#222'); c.setAttribute('stroke-width','2');
    svg.appendChild(c);
    var t=document.createElementNS(ns,'text');
    t.setAttribute('x',nd.x); t.setAttribute('y',nd.y);
    t.setAttribute('fill','#fff'); t.setAttribute('font-size','11');
    t.setAttribute('text-anchor','middle'); t.setAttribute('dominant-baseline','central');
    t.textContent=nd.id;
    svg.appendChild(t);
  }});
}})();
</script>
</body>
</html>"""

    # ------------------------------------------------------------------ server

    def start(self) -> None:
        """Start HTTP server (blocking)."""
        if self.config.host != "127.0.0.1":
            logger.warning(
                "Web UI binding to %s — stdlib http.server is NOT suitable for "
                "public-facing deployments. Use a reverse proxy for production.",
                self.config.host,
            )
        handler = partial(APIHandler, server_ref=self)
        self._server = HTTPServer((self.config.host, self.config.port), handler)
        url = f"http://{self.config.host}:{self.config.port}"
        logger.info("AASTF Web UI running at %s", url)
        if self.config.auto_open:
            webbrowser.open(url)
        self._server.serve_forever()

    def start_background(self) -> None:
        """Start in a daemon thread."""
        if self.config.host != "127.0.0.1":
            logger.warning(
                "Web UI binding to %s — stdlib http.server is NOT suitable for "
                "public-facing deployments. Use a reverse proxy for production.",
                self.config.host,
            )
        handler = partial(APIHandler, server_ref=self)
        self._server = HTTPServer((self.config.host, self.config.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        url = f"http://{self.config.host}:{self.config.port}"
        logger.info("AASTF Web UI running in background at %s", url)
        if self.config.auto_open:
            webbrowser.open(url)

    def stop(self) -> None:
        """Shut down the server."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
        self._thread = None

    # ---------------------------------------------------------------- private

    def _build_pie_svg(self, vd: dict[str, int]) -> str:
        """Build an inline SVG pie chart for verdict distribution."""
        total = sum(vd.values())
        if total == 0:
            return '<svg width="250" height="250"><text x="125" y="125" text-anchor="middle">No data</text></svg>'

        size = 250
        cx = cy = size / 2
        r = 100
        svg_parts = [f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">']

        start_angle = -90.0
        import math

        for verdict_str, count in vd.items():
            if count == 0:
                continue
            pct = count / total
            sweep = pct * 360.0
            end_angle = start_angle + sweep
            large = 1 if sweep > 180 else 0

            x1 = cx + r * math.cos(math.radians(start_angle))
            y1 = cy + r * math.sin(math.radians(start_angle))
            x2 = cx + r * math.cos(math.radians(end_angle))
            y2 = cy + r * math.sin(math.radians(end_angle))

            color = _VERDICT_COLORS.get(verdict_str, "#95a5a6")

            if pct >= 1.0:
                svg_parts.append(
                    f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}"/>'
                )
            else:
                svg_parts.append(
                    f'<path d="M{cx},{cy} L{x1:.1f},{y1:.1f} '
                    f'A{r},{r} 0 {large} 1 {x2:.1f},{y2:.1f} Z" '
                    f'fill="{color}"/>'
                )
            start_angle = end_angle

        # Legend below
        ly = 10
        for verdict_str, count in vd.items():
            if count == 0:
                continue
            color = _VERDICT_COLORS.get(verdict_str, "#95a5a6")
            svg_parts.append(
                f'<rect x="0" y="{ly}" width="8" height="8" fill="{color}"/>'
                f'<text x="12" y="{ly + 8}" font-size="9" fill="#333">'
                f'{html.escape(verdict_str)}: {count}</text>'
            )
            ly += 14

        svg_parts.append("</svg>")
        return "\n".join(svg_parts)

    def _build_bar_svg(self, cats: dict[str, dict[str, int]]) -> str:
        """Build inline SVG horizontal bar chart for categories."""
        if not cats:
            return '<svg width="600" height="40"><text x="300" y="20" text-anchor="middle">No data</text></svg>'

        bar_h = 24
        gap = 6
        label_w = 70
        max_val = max((st["total"] for st in cats.values()), default=1)
        chart_w = 600
        bar_area = chart_w - label_w - 20
        h = (bar_h + gap) * len(cats) + 10

        parts = [f'<svg width="{chart_w}" height="{h}" viewBox="0 0 {chart_w} {h}">']
        y = 5
        for cat_id, st in cats.items():
            total = st["total"]
            vuln = st["vulnerable"]
            safe = st["safe"]
            w_total = int((total / max_val) * bar_area) if max_val > 0 else 0
            w_vuln = int((vuln / max_val) * bar_area) if max_val > 0 else 0
            w_safe = int((safe / max_val) * bar_area) if max_val > 0 else 0

            parts.append(
                f'<text x="0" y="{y + 16}" font-size="12" fill="#333">'
                f'{html.escape(cat_id)}</text>'
            )
            # Total bar (grey)
            parts.append(
                f'<rect x="{label_w}" y="{y}" width="{w_total}" height="{bar_h}" '
                f'fill="#e0e0e0" rx="3"/>'
            )
            # Vulnerable overlay (red)
            if w_vuln > 0:
                parts.append(
                    f'<rect x="{label_w}" y="{y}" width="{w_vuln}" height="{bar_h}" '
                    f'fill="#e74c3c" rx="3"/>'
                )
            # Safe overlay (green, after vuln)
            if w_safe > 0:
                parts.append(
                    f'<rect x="{label_w + w_vuln}" y="{y}" width="{w_safe}" '
                    f'height="{bar_h}" fill="#2ecc71" rx="3"/>'
                )
            # Count label
            parts.append(
                f'<text x="{label_w + w_total + 4}" y="{y + 16}" font-size="11" '
                f'fill="#666">{total}</text>'
            )
            y += bar_h + gap
        parts.append("</svg>")
        return "\n".join(parts)

    def _build_gauge_svg(self, risk: float, color: str) -> str:
        """Build a semicircular gauge SVG."""
        import math

        size = 200
        cx = size / 2
        cy = size / 2 + 20
        r = 70
        # Arc from -180 to 0 degrees (left half circle)
        pct = min(risk / 100.0, 1.0)
        sweep_angle = pct * 180.0
        end_rad = math.radians(-180 + sweep_angle)

        x_start = cx - r
        y_start = cy
        x_end = cx + r * math.cos(end_rad)
        y_end = cy + r * math.sin(end_rad)

        large = 1 if sweep_angle > 180 else 0

        return f"""<svg width="{size}" height="{size // 2 + 40}" viewBox="0 0 {size} {size // 2 + 40}">
  <path d="M{x_start},{y_start} A{r},{r} 0 0 1 {cx + r},{cy}"
        fill="none" stroke="#e0e0e0" stroke-width="14" stroke-linecap="round"/>
  <path d="M{x_start},{y_start} A{r},{r} 0 {large} 1 {x_end:.1f},{y_end:.1f}"
        fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"/>
  <text x="{cx}" y="{cy + 5}" text-anchor="middle" font-size="28"
        font-weight="bold" fill="{color}">{risk}</text>
  <text x="{cx}" y="{cy + 22}" text-anchor="middle" font-size="11"
        fill="#888">Risk Score</text>
</svg>"""

    def _build_results_table(self, report: ScanReport) -> str:
        """Build HTML table rows for scenario results."""
        rows = []
        for r in report.results:
            verdict_str = str(r.verdict)
            color = _VERDICT_COLORS.get(verdict_str, "#95a5a6")
            rows.append(
                f'<tr data-verdict="{html.escape(verdict_str)}" '
                f'data-category="{html.escape(r.category.value)}">'
                f'<td style="font-family:monospace">{html.escape(r.scenario_id)}</td>'
                f'<td>{html.escape(r.scenario_name)}</td>'
                f'<td>{html.escape(r.category.value)}</td>'
                f'<td>{html.escape(str(r.severity))}</td>'
                f'<td><span class="verdict-badge" style="background:{color}">'
                f'{html.escape(verdict_str)}</span></td>'
                f'<td>{r.execution_time_ms:.0f}</td></tr>'
            )
        return "\n".join(rows)


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


class APIHandler(BaseHTTPRequestHandler):
    """Routes requests to the appropriate handler."""

    def __init__(self, *args: Any, server_ref: WebUIServer, **kwargs: Any) -> None:
        self._ui = server_ref
        super().__init__(*args, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        logger.debug(format, *args)

    def _send_security_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "img-src 'self'; font-src 'none'; connect-src 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_html(self, content: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str, indent=2)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-cache")
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _get_report(self) -> ScanReport | None:
        return self._ui._report

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]

        if path == "/":
            report = self._get_report()
            if report is None:
                self._send_html("<h1>No report loaded</h1>", 404)
                return
            self._send_html(self._ui.generate_dashboard_html(report))

        elif path == "/api/report":
            report = self._get_report()
            if report is None:
                self._send_json({"error": "no report loaded"}, 404)
                return
            self._send_json(report.model_dump(mode="json"))

        elif path == "/api/scenarios":
            report = self._get_report()
            if report is None:
                self._send_json({"error": "no report loaded"}, 404)
                return
            scenarios = [
                {
                    "scenario_id": r.scenario_id,
                    "scenario_name": r.scenario_name,
                    "category": r.category.value,
                    "severity": str(r.severity),
                    "verdict": str(r.verdict),
                    "execution_time_ms": r.execution_time_ms,
                }
                for r in report.results
            ]
            self._send_json(scenarios)

        elif path == "/explorer":
            report = self._get_report()
            if report is None:
                self._send_html("<h1>No report loaded</h1>", 404)
                return
            self._send_html(self._ui.generate_scenario_explorer_html(report))

        elif path == "/coverage":
            report = self._get_report()
            if report is None:
                self._send_html("<h1>No report loaded</h1>", 404)
                return
            self._send_html(self._ui.generate_coverage_html(report))

        elif path == "/blast-radius":
            report = self._get_report()
            if report is None:
                self._send_html("<h1>No report loaded</h1>", 404)
                return
            self._send_html(self._ui.generate_blast_radius_html(report))

        elif path == "/api/health":
            self._send_json({"status": "ok", "version": "2.0.0"})

        else:
            self._send_json({"error": "not found"}, 404)


# ---------------------------------------------------------------------------
# CLI integration helper
# ---------------------------------------------------------------------------


def view_command(
    report_path: str | Path | None = None,
    host: str = "127.0.0.1",
    port: int = 8080,
    no_open: bool = False,
) -> None:
    """Entry point for ``aastf view`` — load a report JSON and serve it.

    Parameters
    ----------
    report_path:
        Path to a JSON scan report. If *None*, look for the latest
        ``aastf-report-*.json`` in the current directory.
    host:
        Bind address.
    port:
        Port number.
    no_open:
        If *True*, do not auto-open the browser.
    """
    from pathlib import Path as _P

    if report_path is None:
        candidates = sorted(_P(".").glob("aastf-report-*.json"), reverse=True)
        if not candidates:
            msg = "No report file found. Run `aastf run` first or specify --report."
            raise FileNotFoundError(msg)
        report_path = candidates[0]

    report_path = _P(report_path)
    raw = json.loads(report_path.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(raw)

    config = WebUIConfig(host=host, port=port, auto_open=not no_open, report_path=report_path)
    server = WebUIServer(config)
    server.load_report(report)
    logger.info("Loaded report from %s (%d results)", report_path, len(report.results))
    server.start()
