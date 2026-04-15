"""HTML reporter — Jinja2 compliance report for enterprise/audit use."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from ..models.result import ScanReport, Verdict
from ..models.scenario import Severity


class HTMLReporter:
    """Generates an HTML compliance report from a ScanReport."""

    def __init__(self) -> None:
        # Fall back to a simple inline template if package loader fails
        self._env = Environment(autoescape=select_autoescape(["html"]))

    def generate(self, report: ScanReport) -> str:
        """Return the full HTML report as a string."""
        template = self._env.from_string(_HTML_TEMPLATE)
        return template.render(
            report=report,
            Verdict=Verdict,
            Severity=Severity,
            vulnerable_findings=[f for f in report.findings if f.verdict == Verdict.VULNERABLE],
            severity_colors={
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#ca8a04",
                "LOW": "#2563eb",
                "INFO": "#6b7280",
            },
            readiness_colors={
                "compliant": "#16a34a",
                "at_risk": "#ca8a04",
                "non_compliant": "#dc2626",
            },
        )

    def write(self, report: ScanReport, output_path: Path) -> Path:
        """Write HTML report to output_path."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.generate(report), encoding="utf-8")
        return output_path


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AASTF Security Report — {{ report.adapter }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f8fafc; color: #1e293b; }
  .header { background: #0f172a; color: white; padding: 2rem; }
  .header h1 { margin: 0; font-size: 1.5rem; }
  .header p { margin: 0.5rem 0 0; opacity: 0.7; font-size: 0.9rem; }
  .container { max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }
  .card { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
  .metric { background: white; border-radius: 8px; padding: 1rem; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .metric .value { font-size: 2rem; font-weight: 700; }
  .metric .label { font-size: 0.8rem; color: #64748b; margin-top: 0.25rem; }
  .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; color: white; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; padding: 0.75rem; background: #f1f5f9; font-size: 0.85rem; color: #475569; }
  td { padding: 0.75rem; border-bottom: 1px solid #e2e8f0; font-size: 0.85rem; }
  .finding { border-left: 4px solid; padding: 1rem 1rem 1rem 1.25rem; margin-bottom: 1rem; border-radius: 0 8px 8px 0; background: #fef2f2; }
  .finding h4 { margin: 0 0 0.5rem; }
  .finding p { margin: 0.25rem 0; color: #475569; font-size: 0.85rem; }
  h2 { font-size: 1.1rem; color: #0f172a; margin: 0 0 1rem; }
  .readiness { font-size: 1.25rem; font-weight: 700; }
</style>
</head>
<body>
<div class="header">
  <h1>AASTF Security Assessment Report</h1>
  <p>Adapter: {{ report.adapter }} &nbsp;|&nbsp; Generated: {{ report.generated_at.strftime('%Y-%m-%d %H:%M UTC') }} &nbsp;|&nbsp; AASTF v{{ report.aastf_version }}</p>
</div>
<div class="container">

  <!-- Summary metrics -->
  <div class="metric-grid">
    <div class="metric">
      <div class="value" style="color: {{ '#dc2626' if report.vulnerable > 0 else '#16a34a' }}">{{ report.vulnerable }}</div>
      <div class="label">Vulnerable</div>
    </div>
    <div class="metric">
      <div class="value" style="color: #16a34a">{{ report.safe }}</div>
      <div class="label">Safe</div>
    </div>
    <div class="metric">
      <div class="value" style="color: {{ '#dc2626' if report.overall_risk_score >= 70 else '#ca8a04' if report.overall_risk_score >= 40 else '#16a34a' }}">{{ report.overall_risk_score }}</div>
      <div class="label">Risk Score / 100</div>
    </div>
    <div class="metric">
      <div class="value">{{ report.total_scenarios }}</div>
      <div class="label">Scenarios Run</div>
    </div>
    <div class="metric">
      <div class="value" style="color: {{ readiness_colors.get(report.eu_ai_act_readiness, '#6b7280') }}">{{ report.vulnerability_rate }}%</div>
      <div class="label">Vulnerability Rate</div>
    </div>
  </div>

  <!-- EU AI Act Readiness -->
  <div class="card">
    <h2>EU AI Act Readiness (August 2026)</h2>
    <p class="readiness" style="color: {{ readiness_colors.get(report.eu_ai_act_readiness, '#6b7280') }}">
      {{ report.eu_ai_act_readiness.upper().replace('_', ' ') }}
    </p>
    {% if report.eu_ai_act_readiness == 'non_compliant' %}
    <p>CRITICAL vulnerabilities found. This agent system cannot be deployed as a high-risk AI system under EU AI Act Article 9 without remediation.</p>
    {% elif report.eu_ai_act_readiness == 'at_risk' %}
    <p>HIGH severity vulnerabilities found. Remediation required before deployment in regulated contexts.</p>
    {% else %}
    <p>No CRITICAL or HIGH severity findings. System meets baseline security obligations for the tested scenarios.</p>
    {% endif %}
  </div>

  <!-- Per-category summary -->
  <div class="card">
    <h2>OWASP ASI Category Breakdown</h2>
    <table>
      <thead><tr><th>Category</th><th>Vulnerable</th><th>Safe</th><th>Inconclusive</th><th>Error</th></tr></thead>
      <tbody>
      {% for cat, counts in report.asi_summary.items() %}
      <tr>
        <td><strong>{{ cat }}</strong></td>
        <td style="color: {{ '#dc2626' if counts.get('vulnerable', 0) > 0 else 'inherit' }}">{{ counts.get('vulnerable', 0) }}</td>
        <td style="color: #16a34a">{{ counts.get('safe', 0) }}</td>
        <td>{{ counts.get('inconclusive', 0) }}</td>
        <td>{{ counts.get('error', 0) }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Findings -->
  {% if vulnerable_findings %}
  <div class="card">
    <h2>Vulnerability Findings ({{ vulnerable_findings | length }})</h2>
    {% for f in vulnerable_findings %}
    <div class="finding" style="border-color: {{ severity_colors.get(f.severity.value, '#6b7280') }}">
      <h4>
        <span class="badge" style="background: {{ severity_colors.get(f.severity.value, '#6b7280') }}">{{ f.severity.value }}</span>
        &nbsp; {{ f.scenario_id }} — {{ f.scenario_name }}
      </h4>
      <p><strong>Triggered by:</strong> {{ f.triggered_by }}</p>
      <p><strong>Category:</strong> {{ f.category.value }}</p>
      {% if f.cvss_score %}<p><strong>CVSS Score:</strong> {{ f.cvss_score }}/10</p>{% endif %}
      <p><strong>Remediation:</strong> {{ f.remediation[:300] }}</p>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="card">
    <h2>Vulnerability Findings</h2>
    <p style="color: #16a34a; font-weight: 600">No vulnerabilities detected across {{ report.total_scenarios }} scenarios.</p>
  </div>
  {% endif %}

  <!-- All results table -->
  <div class="card">
    <h2>All Scenario Results</h2>
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th><th>Result</th><th>Time (ms)</th></tr></thead>
      <tbody>
      {% for r in report.results %}
      <tr>
        <td><code>{{ r.scenario_id }}</code></td>
        <td>{{ r.scenario_name }}</td>
        <td>{{ r.category.value }}</td>
        <td><span class="badge" style="background: {{ severity_colors.get(r.severity.value, '#6b7280') }}">{{ r.severity.value }}</span></td>
        <td style="color: {{ '#dc2626' if r.verdict.value == 'VULNERABLE' else '#16a34a' if r.verdict.value == 'SAFE' else '#ca8a04' }}; font-weight: 600">{{ r.verdict.value }}</td>
        <td>{{ "%.0f" | format(r.execution_time_ms) }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <p style="text-align: center; color: #94a3b8; font-size: 0.8rem; margin-top: 2rem;">
    Generated by <a href="https://github.com/anonymousAAK/aastf" style="color: #94a3b8">AASTF</a> v{{ report.aastf_version }}
    &nbsp;|&nbsp; OWASP ASI Top 10 (December 2025)
  </p>
</div>
</body>
</html>"""
