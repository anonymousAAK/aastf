# AASTF Benchmarks

This directory contains benchmark configurations for running AASTF across multiple models and agentic frameworks. The primary configuration, `benchmark-8x4.yaml`, tests 8 LLMs against 4 frameworks using the full AASTF scenario library (ASI, MCP, CVE).

## Reproducible, key-free reference run (no API keys)

For a benchmark you can run end-to-end with **no API keys and no network**, use the
built-in deterministic `local` provider:

```bash
scripts/run_local_benchmark.sh
```

> **SYNTHETIC / REFERENCE ONLY.** The `local` provider
> (`aastf.benchmark.providers.DeterministicProvider`) does **not** call any model
> API. It produces verdicts as a pure, seeded function of the
> `(model_id, framework, scenario_id)` triple. These are reproducible fixtures
> for exercising the benchmark pipeline — **not** measurements of any real model.
> Every artifact it generates is labelled `synthetic`.

The script:

1. Runs `benchmarks/benchmark-local-reference.yaml` (all models use `provider: local`).
2. Writes a byte-stable result to `benchmarks/results/local-reference.json`.
3. Regenerates `benchmarks/results/local-reference-summary.md` **from that result
   data** (no hand-written numbers).

Re-running is idempotent — verify with:

```bash
scripts/run_local_benchmark.sh
git diff --exit-code benchmarks/results/
```

Because the provider is seeded, the same config always yields identical verdicts
and (jittered-but-deterministic) latencies across machines and Python runs.

### Provider / agent-factory contract (for real providers)

The runner delegates each `(model, framework, scenario)` cell to a pluggable
provider implementing `aastf.benchmark.providers.AgentProvider`:

```python
class AgentProvider(Protocol):
    name: str
    async def evaluate(self, model, framework, scenario, run_index) -> ProviderOutcome: ...
```

- If **all** configured models use `provider: local`, the runner auto-wires the
  key-free deterministic provider — no `NotImplementedError`, no keys.
- A **real** provider (calling an actual model API) is supplied by the caller:
  `BenchmarkRunner(config, provider=MyProvider())`. It must read its key from the
  env var named by `model.api_key_env` (failing fast if absent — a raised
  exception degrades a single cell to `ERROR`, not the whole run), drive the
  framework agent for `framework` against the scenario, and return a
  `ProviderOutcome` with `synthetic=False`.

Real providers are intentionally not shipped here (they need keys and network).

## Quick Start

```bash
# 1. Install AASTF with all framework extras
pip install "aastf[langgraph,crewai,openai_agents,pydantic_ai]"

# 2. Export API keys (see Required Environment Variables below)
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_API_KEY="..."
export TOGETHER_API_KEY="..."
export MISTRAL_API_KEY="..."

# 3. Run the benchmark (models/frameworks/scenarios are defined in the config)
aastf benchmark run --config benchmarks/benchmark-8x4.yaml

# To run a subset, copy the config and trim its `models:` / `frameworks:` lists,
# then point `run` at the trimmed file.
```

## Required Environment Variables

| Variable | Provider | Models |
|----------|----------|--------|
| `OPENAI_API_KEY` | OpenAI | GPT-4o, GPT-4o-mini |
| `ANTHROPIC_API_KEY` | Anthropic | Claude 3.5 Sonnet, Claude 3 Haiku |
| `GOOGLE_API_KEY` | Google AI Studio | Gemini 1.5 Pro, Gemini 1.5 Flash |
| `TOGETHER_API_KEY` | Together AI | Llama 3.1 70B |
| `MISTRAL_API_KEY` | Mistral AI | Mistral Large |

You only need the keys for the models you intend to benchmark. Missing keys cause those cells in the matrix to be skipped, not failed.

## Configuration Reference

The `benchmark-8x4.yaml` file controls all benchmark parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `runs_per_scenario` | 3 | Repetitions per scenario for statistical robustness |
| `timeout_seconds` | 60 | Max wall-clock time per scenario run |
| `parallel_workers` | 4 | Concurrent framework-level workers |
| `retry_on_timeout` | true | Retry timed-out runs |
| `max_retries` | 2 | Maximum retry attempts |
| `severity_filter` | null (all) | Filter by severity: LOW, MEDIUM, HIGH, CRITICAL |

## Expected Output

Results are written to `benchmark-results/` (configurable via `output.base_dir`):

```
benchmark-results/
  summary.json              # Aggregate stats: vuln rate, echo rate, latency
  summary.csv               # Same data in CSV for pandas / R
  results.sarif             # SARIF for GitHub Security tab upload
  report.html               # Visual report with embedded heatmap
  heatmap.png               # Model x Framework vulnerability rate matrix
  pareto.png                # Safety-vs-latency Pareto frontier
  raw/
    gpt-4o__langgraph.json         # Per-cell raw verdicts
    gpt-4o__crewai.json
    claude-3-5-sonnet__langgraph.json
    ...                            # One file per model-framework pair
```

### Key Metrics

- **vulnerability_rate** -- Percentage of runs with a `VULNERABLE` verdict.
- **refusal_echo_rate** -- Percentage of runs with a `REFUSAL_ECHO` verdict (informational risk; model refused but echoed the payload).
- **safe_rate** -- Percentage of runs with a `SAFE` verdict.
- **mean_latency_ms** -- Average end-to-end response time per scenario.
- **p95_latency_ms** -- 95th percentile latency.
- **timeout_rate** -- Percentage of runs that exceeded the timeout.

### Interpreting the Heatmap

The heatmap (`heatmap.png`) shows `vulnerability_rate` for each model-framework pair. Darker cells indicate higher vulnerability. Use this to identify:

- Which models are most resilient across frameworks.
- Which frameworks expose models to more tool-use risks.
- Outlier cells where a specific model-framework combination is notably unsafe.

### Interpreting the Pareto Frontier

The Pareto chart (`pareto.png`) plots `safe_rate` (y-axis) against `mean_latency_ms` (x-axis). Models on the Pareto frontier offer the best safety-latency tradeoff. Points below the frontier are dominated (slower and less safe).

## Cost Estimation

Approximate cost for a full 8x4 run with `runs_per_scenario: 3` and ~100 scenarios:

| Model | Per-scenario (USD) | Full run (USD) |
|-------|-------------------|----------------|
| GPT-4o | ~$0.015 | ~$4.50 |
| GPT-4o-mini | ~$0.002 | ~$0.60 |
| Claude 3.5 Sonnet | ~$0.012 | ~$3.60 |
| Claude 3 Haiku | ~$0.001 | ~$0.30 |
| Gemini 1.5 Pro | ~$0.010 | ~$3.00 |
| Gemini 1.5 Flash | ~$0.001 | ~$0.30 |
| Llama 3.1 70B | ~$0.004 | ~$1.20 |
| Mistral Large | ~$0.008 | ~$2.40 |
| **Total** | | **~$16.00** |

Costs are estimates based on typical prompt lengths. Actual costs depend on model pricing at time of run.

## Custom Benchmarks

Create your own benchmark config by copying and modifying `benchmark-8x4.yaml`:

```bash
cp benchmarks/benchmark-8x4.yaml benchmarks/my-benchmark.yaml
# Edit models, frameworks, scenario_packs, etc.
aastf benchmark run --config benchmarks/my-benchmark.yaml
```

To benchmark a single model against a single framework for quick iteration:

```bash
aastf run your_app.agent:create_agent \
  --adapter langgraph \
  --category ASI01 \
  --format json \
  --output-dir quick-results/
```

## CI Integration

Run benchmarks in CI to track safety regressions over time:

```yaml
# .github/workflows/benchmark.yml
name: Weekly Benchmark
on:
  schedule:
    - cron: '0 6 * * 1'   # Every Monday at 06:00 UTC

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install "aastf[langgraph,crewai,openai_agents,pydantic_ai]"
      - run: aastf benchmark run --config benchmarks/benchmark-8x4.yaml
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GOOGLE_API_KEY: ${{ secrets.GOOGLE_API_KEY }}
          TOGETHER_API_KEY: ${{ secrets.TOGETHER_API_KEY }}
          MISTRAL_API_KEY: ${{ secrets.MISTRAL_API_KEY }}
      - uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: benchmark-results/
```
