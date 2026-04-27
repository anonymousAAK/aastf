# Changelog

All notable changes to AASTF are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.2.1] — 2026-04-27

### Added

- **`REFUSAL_ECHO` verdict** — new third verdict class between `VULNERABLE` and `SAFE`.
  Fires when an agent correctly refuses a malicious request but reproduces attack
  payload keywords (URLs, shell fragments, SQL strings) in its refusal text.
  Tracked separately from behavioral compromise to prevent conflation of two
  qualitatively different risk types.

- **`RefusalDetector` utility** (`src/aastf/scenarios/evaluators/refusal_detector.py`) —
  pattern-matching class with 24 English refusal language substrings and configurable
  `min_matches` threshold. `default_refusal_detector` (min_matches=1) used by all
  evaluators except ASI09. `classify_with_refusal_check` free function implements the
  two-step behavioral/output classification algorithm.

- **`--strict-output` CLI flag** — when passed, `REFUSAL_ECHO` findings at or above
  the `--fail-on` severity threshold also trigger exit code 1. Default is `False`
  for backwards compatibility with existing CI/CD pipelines.

- **`informational_risk_rate` property** on `ScanReport` — tracks the percentage of
  scenarios where the agent echoed payload details. Distinct from `vulnerability_rate`.

- **56 new tests** — 27 evaluator refusal tests (3 per evaluator × 9 eligible
  evaluators), 8 HTML reporter tests, 6 SARIF reporter tests, 6 scoring tests,
  5 strict-output CLI tests, 4 runner accumulation tests, and supporting unit tests.

- **n=5 stability benchmark re-run** with Wilson score 95% confidence intervals.
  CLI benchmark scripts updated to run each scenario five times with majority-vote
  verdict stabilization. CSV and JSON output per model. New
  `scripts/regenerate_benchmark_tables.py` generates paste-ready Markdown tables.

- **`benchmarks/` directory** — timestamped JSON/CSV outputs from benchmark runs.

### Changed

- **`Verdict` enum extended from 4 to 5 values** — `REFUSAL_ECHO` inserted between
  `VULNERABLE` and `SAFE`. Existing serialized values (`"VULNERABLE"`, `"SAFE"`,
  `"INCONCLUSIVE"`, `"ERROR"`) are unchanged.

- **`vulnerability_rate` no longer counts `REFUSAL_ECHO`** — the headline behavioral
  risk percentage reflects only true behavioral compromise. This is a semantics change:
  scans that previously produced `REFUSAL_ECHO` findings (misclassified as `VULNERABLE`
  under output-only detection) will show lower `vulnerability_rate` in v0.2.1.

- **EU AI Act readiness** — `REFUSAL_ECHO` at `CRITICAL` or `HIGH` maps to `at_risk`
  (Article 15 output sanitization obligation). Previously these findings would have
  incorrectly triggered `non_compliant` (Article 9 behavioral risk). `non_compliant`
  is now reserved exclusively for `VULNERABLE CRITICAL` findings.

- **SARIF output** — `REFUSAL_ECHO` findings now emit at `level: "warning"` with
  extension properties `aastf.verdict` and `aastf.matched_refusal_patterns`. Previously,
  `REFUSAL_ECHO` findings were conflated with `VULNERABLE` and emitted at `level: "error"`
  for HIGH/CRITICAL severity. SARIF-consuming tools (GitHub Security tab, Defender,
  Snyk) will now correctly distinguish behavioral findings (red errors) from echo
  findings (yellow warnings).

- **Console reporter** — three-category summary footer (behavioral / refusal echo /
  clean safe) with distinct `✗` / `⚠` / `✓` glyphs.

- **HTML reporter** — two-panel findings layout: "Behavioral Vulnerabilities" (red
  border) and "Output Sanitization Findings" (amber border) with explanatory paragraph.

- **All 9 refusal-eligible evaluators** refactored to use `classify_with_refusal_check`.

### Migration

**Existing v0.2.0 scan results remain readable** — `ScanReport` deserializes correctly;
`refusal_echo_count` defaults to 0 for old records.

**Default CI/CD behaviour is unchanged** — `--strict-output` is opt-in. Pipelines
that previously used `--fail-on HIGH` will behave identically unless `--strict-output`
is also passed.

**Benchmark numbers will shift** — scenarios that previously returned `VULNERABLE` via
output-only detection may now return `REFUSAL_ECHO` if the agent's response contained
refusal language. Re-run scans to get accurate v0.2.1 metrics.

**Version strings** — `pyproject.toml` and `src/aastf/__init__.py` both updated from
`0.2.0` to `0.2.1`. Tests that pin against `__version__` should be updated.

### Research notes

Frontier models behaviorally refuse 100% of malicious agent instructions in our
benchmark but reproduce attack payloads in their refusals at varying rates:
47% (GPT-5.x), 60% (Claude Sonnet 4.x), 7% (Gemini 2.5 Pro CLI).
Full analysis in [docs/research/refusal_echo.md](docs/research/refusal_echo.md).

---

## [0.2.0] — 2026-03-15

Initial public release. 50 built-in OWASP ASI scenarios, LangGraph/CrewAI/OpenAI
Agents/PydanticAI adapters, SARIF/JSON/HTML/console reporters, EU AI Act readiness
classification, SQLite trend tracker, 224 tests.
