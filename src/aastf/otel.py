"""
OpenTelemetry exporter for AASTF.

Converts AASTF traces to OpenTelemetry-compatible spans, exposes Prometheus
text-format metrics, and generates Grafana dashboard templates — all without
requiring the OpenTelemetry SDK as a runtime dependency.
"""

from __future__ import annotations

import http.server
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from .models.result import ScanReport
from .models.trace import AgentTrace, TraceEvent

# ---------------------------------------------------------------------------
# Span model
# ---------------------------------------------------------------------------


class AastfSpan(BaseModel):
    """OTel-compatible span derived from an AASTF trace or trace event."""

    trace_id: str
    span_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_span_id: str | None = None
    operation_name: str
    service_name: str = "aastf"
    start_time_unix_nano: int = 0
    end_time_unix_nano: int = 0
    duration_ms: float = 0.0
    status: str = "OK"  # OK | ERROR | UNSET
    attributes: dict[str, Any] = Field(default_factory=dict)
    events: list[dict[str, Any]] = Field(default_factory=list)

    def to_otlp_dict(self) -> dict[str, Any]:
        """Serialise to the OTLP JSON span wire format."""
        return {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "parentSpanId": self.parent_span_id or "",
            "name": self.operation_name,
            "kind": 1,  # SPAN_KIND_INTERNAL
            "startTimeUnixNano": str(self.start_time_unix_nano),
            "endTimeUnixNano": str(self.end_time_unix_nano),
            "status": {"code": 1 if self.status == "OK" else 2, "message": ""},
            "attributes": [
                {"key": k, "value": {"stringValue": str(v)}}
                for k, v in self.attributes.items()
            ],
            "events": self.events,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dt_to_unix_nano(dt: datetime) -> int:
    """Convert a datetime to Unix nanoseconds."""
    return int(dt.replace(tzinfo=dt.tzinfo or timezone.utc).timestamp() * 1_000_000_000)


def _event_to_span_event(event: TraceEvent) -> dict[str, Any]:
    """Convert a TraceEvent to an OTel span event dict."""
    return {
        "timeUnixNano": str(_dt_to_unix_nano(event.timestamp)),
        "name": str(event.event_type),
        "attributes": [
            {"key": "event.name", "value": {"stringValue": event.name}},
            {"key": "event.run_id", "value": {"stringValue": event.run_id}},
        ],
    }


# ---------------------------------------------------------------------------
# OTelExporter
# ---------------------------------------------------------------------------


class OTelExporter:
    """Pure-Python OpenTelemetry exporter for AASTF scan data."""

    # ------------------------------------------------------------------ spans

    @staticmethod
    def traces_to_spans(traces: list[AgentTrace]) -> list[AastfSpan]:
        """Convert a list of *AgentTrace* objects to *AastfSpan* objects.

        Each trace becomes a root span.  Each tool invocation within the trace
        becomes a child span.  Trace events are attached as OTel span events
        on the root span.
        """
        spans: list[AastfSpan] = []
        for trace in traces:
            start_nano = _dt_to_unix_nano(trace.started_at)
            end_nano = (
                _dt_to_unix_nano(trace.ended_at) if trace.ended_at else start_nano
            )
            duration = trace.duration_ms or 0.0

            root_span = AastfSpan(
                trace_id=trace.trace_id.replace("-", ""),
                span_id=uuid.uuid4().hex[:16],
                operation_name=f"scenario.{trace.scenario_id}",
                start_time_unix_nano=start_nano,
                end_time_unix_nano=end_nano,
                duration_ms=duration,
                status="ERROR" if trace.error else "OK",
                attributes={
                    "aastf.scenario_id": trace.scenario_id,
                    "aastf.adapter": trace.adapter,
                    "aastf.iteration_count": str(trace.iteration_count),
                },
                events=[_event_to_span_event(e) for e in trace.events],
            )
            spans.append(root_span)

            # Child spans for tool invocations
            for inv in trace.tool_invocations:
                inv_duration = inv.duration_ms or 0.0
                child_span = AastfSpan(
                    trace_id=root_span.trace_id,
                    parent_span_id=root_span.span_id,
                    operation_name=f"tool.{inv.tool_name}",
                    start_time_unix_nano=start_nano,
                    end_time_unix_nano=start_nano + int(inv_duration * 1_000_000),
                    duration_ms=inv_duration,
                    status="ERROR" if inv.error else "OK",
                    attributes={
                        "aastf.tool_name": inv.tool_name,
                        "aastf.tool_call_id": inv.tool_call_id,
                        "aastf.sandbox_intercepted": str(inv.sandbox_intercepted),
                        "aastf.sequence": str(inv.sequence),
                    },
                )
                spans.append(child_span)

        return spans

    # ----------------------------------------------------------------- export

    @staticmethod
    def export_otlp(
        spans: list[AastfSpan],
        endpoint: str,
        *,
        send: bool = False,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        """Build an OTLP/HTTP JSON export payload, optionally POSTing it.

        The payload dict is always returned so callers can inspect it. When
        ``send=True`` the payload is also POSTed to *endpoint* as
        ``application/json`` using the standard library (no hard ``requests``
        dependency). Network/HTTP errors are raised to the caller.
        """
        resource_spans = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "aastf"},
                            },
                        ],
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "aastf.otel", "version": "0.10.0"},
                            "spans": [s.to_otlp_dict() for s in spans],
                        },
                    ],
                },
            ],
        }
        if send:
            OTelExporter._post_otlp(endpoint, resource_spans, timeout)
        return resource_spans

    @staticmethod
    def _post_otlp(
        endpoint: str, payload: dict[str, Any], timeout: float = 5.0,
    ) -> int:
        """POST an OTLP/HTTP JSON *payload* to *endpoint*; return HTTP status."""
        import json
        import urllib.request

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return getattr(resp, "status", 200)

    # ----------------------------------------------------------- prometheus

    @staticmethod
    def prometheus_metrics(report: ScanReport) -> str:
        """Render Prometheus text-format metrics from a *ScanReport*.

        Returns a string suitable for ``/metrics`` HTTP endpoint consumption
        by Prometheus.
        """
        lines: list[str] = []

        def _gauge(name: str, help_text: str, value: float | int) -> None:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")

        def _counter(name: str, help_text: str, value: float | int) -> None:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")

        _gauge(
            "aastf_total_scenarios",
            "Total number of scenarios executed in the scan.",
            report.total_scenarios,
        )
        _counter(
            "aastf_vulnerable_total",
            "Number of scenarios with VULNERABLE verdict.",
            report.vulnerable,
        )
        _counter(
            "aastf_safe_total",
            "Number of scenarios with SAFE verdict.",
            report.safe,
        )
        _counter(
            "aastf_inconclusive_total",
            "Number of scenarios with INCONCLUSIVE verdict.",
            report.inconclusive,
        )
        _counter(
            "aastf_errors_total",
            "Number of scenarios that errored.",
            report.errors,
        )
        _counter(
            "aastf_refusal_echo_total",
            "Number of scenarios with REFUSAL_ECHO verdict.",
            report.refusal_echo_count,
        )
        _gauge(
            "aastf_risk_score",
            "Overall risk score (0-100).",
            report.overall_risk_score,
        )
        _gauge(
            "aastf_vulnerability_rate",
            "Percentage of scenarios that were vulnerable.",
            report.vulnerability_rate,
        )

        # Per-verdict breakdown
        verdict_counts: dict[str, int] = {}
        for result in report.results:
            v = str(result.verdict)
            verdict_counts[v] = verdict_counts.get(v, 0) + 1

        if verdict_counts:
            lines.append("# HELP aastf_verdict_count Count of each verdict type.")
            lines.append("# TYPE aastf_verdict_count gauge")
            for verdict, count in sorted(verdict_counts.items()):
                lines.append(f'aastf_verdict_count{{verdict="{verdict}"}} {count}')

        # Per-category breakdown
        if report.asi_summary:
            lines.append(
                "# HELP aastf_category_vulnerable Vulnerable count per ASI category."
            )
            lines.append("# TYPE aastf_category_vulnerable gauge")
            for cat, counts in sorted(report.asi_summary.items()):
                vuln = counts.get("vulnerable", 0)
                lines.append(f'aastf_category_vulnerable{{category="{cat}"}} {vuln}')

        # Per-result execution time
        if report.results:
            lines.append(
                "# HELP aastf_scenario_duration_ms Execution duration per scenario in ms."
            )
            lines.append("# TYPE aastf_scenario_duration_ms gauge")
            for r in report.results:
                lines.append(
                    f'aastf_scenario_duration_ms{{scenario="{r.scenario_id}"}} {r.execution_time_ms}'
                )

        lines.append("")  # trailing newline
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Lightweight Prometheus HTTP server
# ---------------------------------------------------------------------------


class PrometheusMetricsServer:
    """Minimal HTTP server that exposes ``/metrics`` in Prometheus text format.

    Usage::

        server = PrometheusMetricsServer(port=9090)
        server.update(report)   # call after each scan
        server.start()          # runs in background thread
        ...
        server.stop()
    """

    def __init__(self, port: int = 9090, host: str = "127.0.0.1") -> None:
        # Bind to loopback by default. The /metrics endpoint is unauthenticated,
        # so exposing it on all interfaces (0.0.0.0) would leak scan results
        # network-wide — which AASTF's own static analyzer flags as a finding.
        # Set host explicitly to expose it behind a trusted proxy.
        self.port = port
        self.host = host
        self._metrics_text: str = ""
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def update(self, report: ScanReport) -> None:
        """Refresh the metrics text from a new *ScanReport*."""
        self._metrics_text = OTelExporter.prometheus_metrics(report)

    def _handler_factory(self) -> type:
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/metrics":
                    body = outer._metrics_text.encode()
                    self.send_response(200)
                    self.send_header(
                        "Content-Type",
                        "text/plain; version=0.0.4; charset=utf-8",
                    )
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass  # silence request logs

        return _Handler

    def start(self) -> None:
        """Start serving ``/metrics`` in a daemon thread."""
        handler = self._handler_factory()
        self._server = http.server.HTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Shut down the server."""
        if self._server:
            self._server.shutdown()
            self._server = None


# ---------------------------------------------------------------------------
# GrafanaDashboard
# ---------------------------------------------------------------------------


class GrafanaDashboard:
    """Generates a Grafana dashboard JSON template for AASTF metrics."""

    @staticmethod
    def _panel(
        title: str,
        panel_id: int,
        grid_x: int,
        grid_y: int,
        width: int,
        height: int,
        *,
        panel_type: str = "timeseries",
        expr: str = "",
        legend: str = "",
        description: str = "",
    ) -> dict[str, Any]:
        """Build a single Grafana panel dict."""
        panel: dict[str, Any] = {
            "id": panel_id,
            "title": title,
            "type": panel_type,
            "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
            "gridPos": {"h": height, "w": width, "x": grid_x, "y": grid_y},
            "description": description,
            "targets": [
                {
                    "expr": expr,
                    "legendFormat": legend or title,
                    "refId": "A",
                },
            ],
        }
        if panel_type == "piechart":
            panel["options"] = {
                "pieType": "pie",
                "tooltip": {"mode": "single"},
                "legend": {"displayMode": "list", "placement": "right"},
            }
        if panel_type == "stat":
            panel["options"] = {
                "colorMode": "value",
                "graphMode": "none",
                "textMode": "auto",
            }
        return panel

    @classmethod
    def generate(cls, title: str = "AASTF Security Scan") -> dict[str, Any]:
        """Return a complete Grafana dashboard JSON structure.

        Panels:
        1. Vulnerability count by category (bar chart)
        2. Pass / fail ratio (pie chart)
        3. Scan duration (stat)
        4. Verdict distribution (pie chart)
        5. Overall risk score (gauge)
        6. Scenario execution times (timeseries)
        """
        panels = [
            cls._panel(
                title="Vulnerabilities by Category",
                panel_id=1,
                grid_x=0,
                grid_y=0,
                width=12,
                height=8,
                panel_type="barchart",
                expr='aastf_category_vulnerable',
                legend="{{category}}",
                description="Number of VULNERABLE verdicts per ASI category.",
            ),
            cls._panel(
                title="Pass / Fail Ratio",
                panel_id=2,
                grid_x=12,
                grid_y=0,
                width=12,
                height=8,
                panel_type="piechart",
                expr='aastf_safe_total',
                legend="Safe",
                description="Ratio of SAFE to VULNERABLE scenarios.",
            ),
            cls._panel(
                title="Scan Duration",
                panel_id=3,
                grid_x=0,
                grid_y=8,
                width=6,
                height=4,
                panel_type="stat",
                expr='sum(aastf_scenario_duration_ms)',
                legend="Total Duration (ms)",
                description="Total execution time across all scenarios.",
            ),
            cls._panel(
                title="Verdict Distribution",
                panel_id=4,
                grid_x=6,
                grid_y=8,
                width=12,
                height=8,
                panel_type="piechart",
                expr='aastf_verdict_count',
                legend="{{verdict}}",
                description="Distribution of all verdict types.",
            ),
            cls._panel(
                title="Overall Risk Score",
                panel_id=5,
                grid_x=18,
                grid_y=8,
                width=6,
                height=4,
                panel_type="gauge",
                expr='aastf_risk_score',
                legend="Risk",
                description="Overall risk score from 0 to 100.",
            ),
            cls._panel(
                title="Scenario Execution Times",
                panel_id=6,
                grid_x=0,
                grid_y=16,
                width=24,
                height=8,
                panel_type="timeseries",
                expr='aastf_scenario_duration_ms',
                legend="{{scenario}}",
                description="Per-scenario execution duration in milliseconds.",
            ),
        ]

        dashboard: dict[str, Any] = {
            "dashboard": {
                "id": None,
                "uid": "aastf-security-scan",
                "title": title,
                "tags": ["aastf", "security", "ai-safety"],
                "timezone": "browser",
                "schemaVersion": 39,
                "version": 1,
                "refresh": "30s",
                "time": {"from": "now-1h", "to": "now"},
                "templating": {
                    "list": [
                        {
                            "name": "DS_PROMETHEUS",
                            "type": "datasource",
                            "query": "prometheus",
                        },
                    ],
                },
                "panels": panels,
            },
            "overwrite": True,
        }
        return dashboard
