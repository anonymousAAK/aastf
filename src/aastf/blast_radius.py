"""Blast-radius reporter with visualization for multi-agent fault propagation."""

from __future__ import annotations

import html
import json
import logging
from collections import deque
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .harness.multi_agent import TopologyConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------


class PropagationStep(BaseModel):
    """A single hop in the fault propagation chain."""

    hop: int
    source: str
    target: str
    contaminated: bool


class FaultInjectionResult(BaseModel):
    """Result of a fault-injection run against a multi-agent topology."""

    scenario_id: str
    faults_injected: list[Any] = Field(default_factory=list)
    propagation: list[PropagationStep] = Field(default_factory=list)
    affected_agents: list[str] = Field(default_factory=list)
    max_depth: int = 0
    max_breadth: int = 0
    severity_amplification: float = 1.0
    cascade_detected: bool = False
    verdict: str = "safe"


# ---------------------------------------------------------------------------
# Report models
# ---------------------------------------------------------------------------


class GraphEdge(BaseModel):
    """An edge in the propagation graph."""

    source: str
    target: str
    contaminated: bool
    hop: int


class AgentImpact(BaseModel):
    """Per-agent impact assessment."""

    agent_id: str
    role: str
    affected: bool
    hops_from_injection: int
    severity_at_agent: str


class BlastRadiusReport(BaseModel):
    """Full blast-radius analysis report."""

    injection_point: str
    total_agents: int
    affected_agents: int
    blast_radius_pct: float
    max_propagation_depth: int
    propagation_breadth: int
    compound_risk_score: float
    risk_level: str
    propagation_graph: list[GraphEdge] = Field(default_factory=list)
    per_agent_impact: dict[str, AgentImpact] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class BlastRadiusAnalyzer:
    """Computes blast-radius metrics from a fault-injection result and topology."""

    def __init__(
        self,
        fault_result: FaultInjectionResult,
        topology: TopologyConfig,
    ) -> None:
        self._result = fault_result
        self._topology = topology

    # ------------------------------------------------------------------ public

    def compute(self) -> BlastRadiusReport:
        """Compute the full blast-radius report."""
        total = len(self._topology.agents)
        affected_set = set(self._result.affected_agents)
        affected_count = len(affected_set)

        # Determine injection point (first propagation source, or first affected agent)
        injection_point = self._find_injection_point()

        # Build adjacency from topology edges
        adjacency: dict[str, list[str]] = {a.id: [] for a in self._topology.agents}
        for edge in self._topology.edges:
            if edge.source in adjacency:
                adjacency[edge.source].append(edge.target)

        # BFS from injection point to compute hops
        hops_map: dict[str, int] = {injection_point: 0}
        queue: deque[str] = deque([injection_point])
        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, []):
                if neighbor not in hops_map:
                    hops_map[neighbor] = hops_map[current] + 1
                    queue.append(neighbor)

        # Build propagation graph edges
        prop_edges: list[GraphEdge] = []
        contaminated_edges: set[tuple[str, str]] = set()
        for step in self._result.propagation:
            contaminated_edges.add((step.source, step.target))

        for edge in self._topology.edges:
            is_contaminated = (edge.source, edge.target) in contaminated_edges
            hop = hops_map.get(edge.source, 0)
            prop_edges.append(
                GraphEdge(
                    source=edge.source,
                    target=edge.target,
                    contaminated=is_contaminated,
                    hop=hop,
                )
            )

        # Per-agent impact
        per_agent: dict[str, AgentImpact] = {}
        for agent in self._topology.agents:
            is_affected = agent.id in affected_set
            hops = hops_map.get(agent.id, -1)
            severity = self._severity_for_hops(hops, is_affected)
            per_agent[agent.id] = AgentImpact(
                agent_id=agent.id,
                role=agent.role,
                affected=is_affected,
                hops_from_injection=hops if hops >= 0 else -1,
                severity_at_agent=severity,
            )

        # Metrics
        blast_pct = (affected_count / total * 100.0) if total > 0 else 0.0
        max_depth = self._result.max_depth
        breadth = self._result.max_breadth

        compound = self._compute_compound_risk(
            depth=max_depth,
            breadth=breadth,
            severity_amp=self._result.severity_amplification,
            blast_pct=blast_pct,
        )
        risk = self._risk_level(compound)

        return BlastRadiusReport(
            injection_point=injection_point,
            total_agents=total,
            affected_agents=affected_count,
            blast_radius_pct=round(blast_pct, 2),
            max_propagation_depth=max_depth,
            propagation_breadth=breadth,
            compound_risk_score=round(compound, 2),
            risk_level=risk,
            propagation_graph=prop_edges,
            per_agent_impact=per_agent,
        )

    def to_json(self) -> dict[str, Any]:
        """Return the report as a JSON-serializable dict."""
        report = self.compute()
        return report.model_dump(mode="json")

    def to_html(self, output_path: Path) -> None:
        """Write a self-contained HTML blast-radius visualization."""
        report = self.compute()

        # Prepare data for JS
        nodes_js: list[dict[str, Any]] = []
        for agent in self._topology.agents:
            impact = report.per_agent_impact.get(agent.id)
            is_injection = agent.id == report.injection_point
            is_affected = impact.affected if impact else False
            color = "#ff6600" if is_injection else ("#e74c3c" if is_affected else "#2ecc71")
            nodes_js.append(
                {
                    "id": agent.id,
                    "role": agent.role,
                    "color": color,
                    "affected": is_affected,
                    "injection": is_injection,
                }
            )

        edges_js: list[dict[str, Any]] = []
        for ge in report.propagation_graph:
            edges_js.append(
                {
                    "source": ge.source,
                    "target": ge.target,
                    "contaminated": ge.contaminated,
                    "hop": ge.hop,
                }
            )

        stats = {
            "injection_point": report.injection_point,
            "total_agents": report.total_agents,
            "affected_agents": report.affected_agents,
            "blast_radius_pct": report.blast_radius_pct,
            "max_propagation_depth": report.max_propagation_depth,
            "propagation_breadth": report.propagation_breadth,
            "compound_risk_score": report.compound_risk_score,
            "risk_level": report.risk_level,
        }

        html_content = _build_html(
            nodes=nodes_js,
            edges=edges_js,
            stats=stats,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html_content, encoding="utf-8")
        logger.info("Blast-radius HTML written to %s", output_path)

    def to_console(self) -> str:
        """Return a text summary of the blast-radius report."""
        report = self.compute()
        lines: list[str] = [
            "=== Blast Radius Report ===",
            f"Injection Point : {report.injection_point}",
            f"Total Agents    : {report.total_agents}",
            f"Affected Agents : {report.affected_agents}",
            f"Blast Radius    : {report.blast_radius_pct}%",
            f"Max Depth       : {report.max_propagation_depth}",
            f"Breadth         : {report.propagation_breadth}",
            f"Risk Score      : {report.compound_risk_score}",
            f"Risk Level      : {report.risk_level.upper()}",
            "",
            "--- Per-Agent Impact ---",
        ]
        for aid, impact in report.per_agent_impact.items():
            marker = "[X]" if impact.affected else "[ ]"
            lines.append(
                f"  {marker} {aid} ({impact.role}) "
                f"hops={impact.hops_from_injection} severity={impact.severity_at_agent}"
            )
        lines.append("=" * 28)
        return "\n".join(lines)

    # ----------------------------------------------------------------- private

    def _find_injection_point(self) -> str:
        """Determine the injection point agent ID."""
        if self._result.propagation:
            return self._result.propagation[0].source
        if self._result.affected_agents:
            return self._result.affected_agents[0]
        if self._topology.agents:
            return self._topology.agents[0].id
        return "unknown"

    @staticmethod
    def _severity_for_hops(hops: int, affected: bool) -> str:
        if not affected:
            return "none"
        if hops <= 0:
            return "critical"
        if hops == 1:
            return "high"
        if hops == 2:
            return "medium"
        return "low"

    @staticmethod
    def _compute_compound_risk(
        depth: int,
        breadth: int,
        severity_amp: float,
        blast_pct: float,
    ) -> float:
        """Compute 0-100 compound risk score weighted by depth * breadth * severity."""
        if blast_pct == 0.0:
            return 0.0
        raw = (depth * 10 + breadth * 8) * severity_amp * (blast_pct / 100.0)
        return min(100.0, max(0.0, raw))

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 75.0:
            return "critical"
        if score >= 50.0:
            return "high"
        if score >= 25.0:
            return "medium"
        return "low"


# ---------------------------------------------------------------------------
# HTML builder (self-contained, no external deps)
# ---------------------------------------------------------------------------


def _build_html(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    stats: dict[str, Any],
) -> str:
    """Build a self-contained HTML page with inline SVG graph visualization."""
    nodes_json = html.escape(json.dumps(nodes), quote=True)
    edges_json = html.escape(json.dumps(edges), quote=True)
    stats_json = html.escape(json.dumps(stats), quote=True)

    risk_color_map = {
        "low": "#2ecc71",
        "medium": "#f39c12",
        "high": "#e67e22",
        "critical": "#e74c3c",
    }
    risk_color = risk_color_map.get(stats.get("risk_level", "low"), "#2ecc71")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Blast Radius Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #1a1a2e; color: #eee; display: flex; height: 100vh; }}
#sidebar {{ width: 300px; background: #16213e; padding: 20px; overflow-y: auto;
            border-right: 2px solid #0f3460; }}
#sidebar h1 {{ font-size: 18px; margin-bottom: 16px; color: #e94560; }}
.stat {{ margin-bottom: 12px; }}
.stat-label {{ font-size: 11px; text-transform: uppercase; color: #888; }}
.stat-value {{ font-size: 22px; font-weight: bold; }}
.risk-badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px;
              font-weight: bold; font-size: 14px; color: #fff;
              background: {risk_color}; }}
#graph-area {{ flex: 1; position: relative; }}
svg {{ width: 100%; height: 100%; }}
.edge-line {{ stroke: #334; stroke-width: 1.5; }}
.edge-contaminated {{ stroke: #e74c3c; stroke-width: 2.5;
                      stroke-dasharray: 8 4;
                      animation: dash 1s linear infinite; }}
@keyframes dash {{ to {{ stroke-dashoffset: -12; }} }}
.node-circle {{ stroke: #222; stroke-width: 2; cursor: pointer; }}
.node-label {{ fill: #eee; font-size: 11px; text-anchor: middle;
              dominant-baseline: central; pointer-events: none; }}
.legend {{ position: absolute; bottom: 16px; left: 16px; background: rgba(22,33,62,0.9);
          padding: 12px; border-radius: 6px; font-size: 12px; }}
.legend-item {{ display: flex; align-items: center; margin-bottom: 4px; }}
.legend-dot {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
marker {{ overflow: visible; }}
</style>
</head>
<body>
<div id="sidebar">
  <h1>Blast Radius Report</h1>
  <div class="stat"><div class="stat-label">Injection Point</div>
    <div class="stat-value" id="s-injection"></div></div>
  <div class="stat"><div class="stat-label">Total Agents</div>
    <div class="stat-value" id="s-total"></div></div>
  <div class="stat"><div class="stat-label">Affected Agents</div>
    <div class="stat-value" id="s-affected"></div></div>
  <div class="stat"><div class="stat-label">Blast Radius</div>
    <div class="stat-value" id="s-pct"></div></div>
  <div class="stat"><div class="stat-label">Max Depth</div>
    <div class="stat-value" id="s-depth"></div></div>
  <div class="stat"><div class="stat-label">Breadth</div>
    <div class="stat-value" id="s-breadth"></div></div>
  <div class="stat"><div class="stat-label">Risk Score</div>
    <div class="stat-value" id="s-score"></div></div>
  <div class="stat"><div class="stat-label">Risk Level</div>
    <div class="risk-badge" id="s-risk"></div></div>
</div>
<div id="graph-area">
  <svg id="svg"></svg>
  <div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:#ff6600"></div>Injection Point</div>
    <div class="legend-item"><div class="legend-dot" style="background:#e74c3c"></div>Contaminated</div>
    <div class="legend-item"><div class="legend-dot" style="background:#2ecc71"></div>Safe</div>
  </div>
</div>
<script>
(function() {{
  var nodes = JSON.parse('{nodes_json}'.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"'));
  var edges = JSON.parse('{edges_json}'.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"'));
  var stats = JSON.parse('{stats_json}'.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"'));

  document.getElementById('s-injection').textContent = stats.injection_point;
  document.getElementById('s-total').textContent = stats.total_agents;
  document.getElementById('s-affected').textContent = stats.affected_agents;
  document.getElementById('s-pct').textContent = stats.blast_radius_pct + '%';
  document.getElementById('s-depth').textContent = stats.max_propagation_depth;
  document.getElementById('s-breadth').textContent = stats.propagation_breadth;
  document.getElementById('s-score').textContent = stats.compound_risk_score;
  document.getElementById('s-risk').textContent = stats.risk_level.toUpperCase();

  var svg = document.getElementById('svg');
  var W = svg.clientWidth || 800, H = svg.clientHeight || 600;
  var R = 24, pad = 60;

  /* Circular layout */
  var n = nodes.length;
  var cx = W / 2, cy = H / 2, radius = Math.min(W, H) / 2 - pad;
  if (n === 1) radius = 0;
  for (var i = 0; i < n; i++) {{
    var angle = (2 * Math.PI * i / n) - Math.PI / 2;
    nodes[i].x = cx + radius * Math.cos(angle);
    nodes[i].y = cy + radius * Math.sin(angle);
  }}
  var nodeMap = {{}};
  nodes.forEach(function(nd) {{ nodeMap[nd.id] = nd; }});

  /* Simple force iterations to spread overlapping nodes */
  for (var iter = 0; iter < 50; iter++) {{
    for (var a = 0; a < n; a++) {{
      for (var b = a + 1; b < n; b++) {{
        var dx = nodes[b].x - nodes[a].x;
        var dy = nodes[b].y - nodes[a].y;
        var dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < R * 3) {{
          var force = (R * 3 - dist) * 0.05;
          var fx = (dx / dist) * force;
          var fy = (dy / dist) * force;
          nodes[a].x -= fx; nodes[a].y -= fy;
          nodes[b].x += fx; nodes[b].y += fy;
        }}
      }}
    }}
    /* Keep in bounds */
    for (var k = 0; k < n; k++) {{
      nodes[k].x = Math.max(pad, Math.min(W - pad, nodes[k].x));
      nodes[k].y = Math.max(pad, Math.min(H - pad, nodes[k].y));
    }}
  }}

  /* Arrow marker */
  var ns = 'http://www.w3.org/2000/svg';
  var defs = document.createElementNS(ns, 'defs');
  var marker = document.createElementNS(ns, 'marker');
  marker.setAttribute('id', 'arrow');
  marker.setAttribute('viewBox', '0 0 10 10');
  marker.setAttribute('refX', '10'); marker.setAttribute('refY', '5');
  marker.setAttribute('markerWidth', '8'); marker.setAttribute('markerHeight', '8');
  marker.setAttribute('orient', 'auto-start-reverse');
  var path = document.createElementNS(ns, 'path');
  path.setAttribute('d', 'M 0 0 L 10 5 L 0 10 z');
  path.setAttribute('fill', '#666');
  marker.appendChild(path);
  var marker2 = marker.cloneNode(true);
  marker2.setAttribute('id', 'arrow-red');
  marker2.querySelector('path').setAttribute('fill', '#e74c3c');
  defs.appendChild(marker); defs.appendChild(marker2);
  svg.appendChild(defs);

  /* Draw edges */
  edges.forEach(function(e) {{
    var s = nodeMap[e.source], t = nodeMap[e.target];
    if (!s || !t) return;
    var dx = t.x - s.x, dy = t.y - s.y;
    var dist = Math.sqrt(dx * dx + dy * dy) || 1;
    var sx = s.x + (dx / dist) * R, sy = s.y + (dy / dist) * R;
    var tx = t.x - (dx / dist) * (R + 8), ty = t.y - (dy / dist) * (R + 8);
    var line = document.createElementNS(ns, 'line');
    line.setAttribute('x1', sx); line.setAttribute('y1', sy);
    line.setAttribute('x2', tx); line.setAttribute('y2', ty);
    line.setAttribute('class', e.contaminated ? 'edge-line edge-contaminated' : 'edge-line');
    line.setAttribute('marker-end', e.contaminated ? 'url(#arrow-red)' : 'url(#arrow)');
    svg.appendChild(line);
  }});

  /* Draw nodes */
  nodes.forEach(function(nd) {{
    var circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', nd.x); circle.setAttribute('cy', nd.y);
    circle.setAttribute('r', R);
    circle.setAttribute('fill', nd.color);
    circle.setAttribute('class', 'node-circle');
    svg.appendChild(circle);
    var text = document.createElementNS(ns, 'text');
    text.setAttribute('x', nd.x); text.setAttribute('y', nd.y);
    text.setAttribute('class', 'node-label');
    text.textContent = nd.id.length > 8 ? nd.id.slice(0, 7) + '...' : nd.id;
    svg.appendChild(text);
    /* Role label below */
    var role = document.createElementNS(ns, 'text');
    role.setAttribute('x', nd.x); role.setAttribute('y', nd.y + R + 14);
    role.setAttribute('class', 'node-label');
    role.setAttribute('font-size', '9px');
    role.setAttribute('fill', '#888');
    role.textContent = nd.role;
    svg.appendChild(role);
  }});
}})();
</script>
</body>
</html>"""
