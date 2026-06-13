# AASTF -- Test Results

**2815 tests collected -- 2815 passing -- 0 failures -- lint clean (ruff)**

Last run: May 2026 -- Python 3.10+ -- pytest 8.x

---

## Summary

| Metric | Value |
|--------|-------|
| Total tests | 2815 |
| Passing | 2815 |
| Failures | 0 |
| Skipped | 0 |
| Ruff lint | Clean |

---

## Modules Under Test

The test suite covers every module in the framework:

| Area | Modules |
|------|---------|
| Core | scoring, runner, harness, synthesizer, scenario_quality, converters |
| Adapters (7) | langgraph, crewai, openai_agents, pydantic_ai, mcp, google_adk, ms_agent |
| Compliance | EU AI Act evidence packs, Singapore IMDA, NIST AI RMF |
| Scenarios | 136+ built-in (ASI, MCP, CVE, MAS, A2A prefixes) |
| v0.9.0 features | fault_injection, blast_radius, mitre (ATT&CK mapping), chaos |
| v0.10.0 features | otel, alerting, drift_alerts, steerability |
| Multi-agent | multi_agent harness, orchestrators (crescendo, tap, pair) |
| Observability | drift, events, replay, coverage, dual scoring, packs, benchmark |
| Advanced | ai_vss, mutation, cost_scheduler, rl_trainer, leaderboard |
| Infrastructure | cloud_runner, cloud, enterprise, web_ui |
| Analysis | static_analysis, threat_model |

---

## Test Suites

Tests are organized under `tests/unit/`, `tests/self_audit/`, and `tests/integration/`.

Key suites include:

- **Scoring** -- CVSS scoring, EU AI Act readiness, dual scoring, Hypothesis property tests
- **Runner** -- accumulation logic, SARIF/JSON/HTML reporters
- **Evaluators** -- all 10 ASI evaluators, registry validation
- **Models** -- scenario, result, and trace model validation
- **Adapters** -- import guards and structure tests for all 7 framework adapters
- **Loader** -- YAML scenario loading, directory recursion, template rendering
- **Registry** -- filtering by category, severity, tags; builtin scenario validation
- **Collector** -- TraceCollector, astream_events ingestion
- **Trend tracker** -- SQLite record/retrieve/compare/summary
- **Compliance** -- EU AI Act Art 9-15 evidence packs, IMDA, NIST
- **Fault injection** -- FaultType, FaultConfig, PropagationTracker, FaultInjectionEngine
- **Blast radius** -- HTML SVG graph, compound risk scoring
- **MITRE ATT&CK** -- ASI_TO_MITRE mapping, MITREEnricher, EnrichedFinding/Report
- **Chaos** -- 8 chaos types, ResilienceScorer, ChaosReport
- **Multi-agent** -- topology harness, MASpi/A2A scenarios
- **Orchestrators** -- crescendo, tap, pair
- **Drift / Events / Replay** -- drift detection, event bus, replay engine
- **Coverage / Packs / Benchmark** -- coverage tracking, scenario packs, benchmarks
- **OTel / Alerting / Drift alerts** -- OpenTelemetry exporter, Slack/PagerDuty/webhook, baseline-drift
- **Steerability** -- steerability benchmarking
- **AI-VSS / Mutation / Cost scheduler / RL trainer** -- advanced analysis modules
- **Leaderboard / Cloud runner / Enterprise / Web UI** -- infrastructure modules
- **Static analysis / Threat model** -- code-level analysis
- **Self-audit** -- structural validation of scenario library (IDs, coverage, severity distribution)

---

## Test Environment

```
Python:  3.10+
pytest:  8.x
ruff:    clean
OS:      Windows 11
```

## Running Tests

```bash
# Unit + self-audit (no API key needed)
pytest tests/unit/ tests/self_audit/ -v

# Integration tests (requires LLM API key)
pytest tests/integration/ -v -m integration

# All with coverage
pytest tests/ --cov=aastf --cov-report=term-missing
```
