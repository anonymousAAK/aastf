# AASTF — Testing

AASTF ships with an extensive automated test suite. Rather than hand-maintaining
per-test counts (which drift immediately), this page documents how the suite is
organised and how to run it. The headline number in the README is verified
automatically by `tests/adversarial/test_h_docs.py`, which fails CI if the README
drifts from the actual collected test count.

To get the current count and status yourself:

```bash
pip install -e ".[dev,langgraph]"
python -m pytest tests/ --collect-only -q | tail -1   # e.g. "2843 tests collected"
python -m pytest -q                                    # run the full suite
```

## Test layout

| Directory | What it covers |
|-----------|----------------|
| `tests/unit/` | Per-module unit tests: models, scoring, evaluators, adapters, reporters, registry, CLI, compliance, drift, scheduler, otel, web UI, etc. |
| `tests/adversarial/` | Adversarial suites that probe the tool itself — correctness, schema fuzzing, bypass attempts, runtime behaviour, supply-chain/loader safety, and docs-truthfulness (`test_h_docs.py`). |
| `tests/contracts/` | Cross-cutting contracts (e.g. every adapter is registered and exposes the expected interface). |
| `tests/self_audit/` | Structural validation of the built-in scenario library — ID uniqueness, category prefixes, required fields, and that every evaluator runs against empty and clean traces without crashing. |
| `tests/integration/` | Tests that exercise the live sandbox/MCP server. |

Property-based tests use [Hypothesis](https://hypothesis.readthedocs.io); the
scoring invariants (risk score always in `[0, 100]`, monotonic in findings,
`REFUSAL_ECHO <= VULNERABLE`) live in `tests/unit/test_scoring_hypothesis.py`.

## Markers

Defined in `pyproject.toml`:

- `integration` — requires a real LLM API key (skipped by default).
- `slow` — takes more than 10s.

```bash
# Unit + self-audit only (no API key, fast)
python -m pytest tests/unit/ tests/self_audit/ -q

# Integration tests (requires an LLM API key)
python -m pytest tests/integration/ -v -m integration

# With coverage
pip install pytest-cov
python -m pytest tests/ --cov=aastf --cov-report=term-missing
```

## Linting

```bash
ruff check src/ tests/
```

CI runs the full suite and `ruff` on every push and pull request across Python
3.10–3.13 (see `.github/workflows/ci.yml`).
