# Quick Start

Get your first security scan running in under 5 minutes.

## Installation

```bash
pip install aastf
```

Requires Python 3.10+.

To install with framework-specific adapters:

```bash
# LangGraph support
pip install "aastf[langgraph]"

# CrewAI support
pip install "aastf[crewai]"

# OpenAI Agents SDK support
pip install "aastf[openai-agents]"

# PydanticAI support
pip install "aastf[pydantic-ai]"

# All adapters
pip install "aastf[all]"
```

## Initialize Configuration

```bash
aastf init
```

This launches an interactive wizard that creates an `aastf.yaml` with your project settings. Use `--yes` to accept defaults without prompting:

```bash
aastf init --yes
```

## Run Your First Scan

```bash
aastf run myapp.agent:create_agent --adapter langgraph
```

Replace `myapp.agent:create_agent` with the dotted path to your agent factory function.

### Supported Adapters

| Adapter | Framework | Flag |
|---------|-----------|------|
| LangGraph | LangChain/LangGraph | `--adapter langgraph` |
| CrewAI | CrewAI | `--adapter crewai` |
| OpenAI Agents | OpenAI Agents SDK | `--adapter openai_agents` |
| PydanticAI | PydanticAI | `--adapter pydantic_ai` |

## Understanding Results

AASTF produces five verdict types:

- **VULNERABLE**: Agent performed the malicious action (critical finding)
- **REFUSAL_ECHO**: Agent refused but leaked payload details in its refusal text (informational)
- **SAFE**: Agent correctly resisted the attack
- **INCONCLUSIVE**: Could not determine the outcome (ambiguous trace)
- **ERROR**: Framework error during testing

## Output Formats

```bash
# Console + JSON (default)
aastf run myapp:agent --format console --format json

# Add SARIF for GitHub Security tab
aastf run myapp:agent --format sarif

# Add HTML for sharing
aastf run myapp:agent --format html
```

Reports are written to `aastf-results/run-YYYYMMDD-HHMMSS/` by default.

## Dry Run

Preview which scenarios would execute without running them:

```bash
aastf run myapp:agent --dry-run
```

## Explore Scenarios

List all built-in attack scenarios:

```bash
aastf scenario list
```

Filter by category or severity:

```bash
aastf scenario list --category ASI02
aastf scenario list --severity HIGH
```

Show full details for a specific scenario:

```bash
aastf scenario show ASI02-001
```

## CI/CD Integration

### GitHub Actions

```yaml
- uses: anonymousAAK/aastf/.github/actions/aastf-scan@master
  with:
    agent-module: 'myapp.agent:create_agent'
    fail-on: 'HIGH'
```

See [GitHub Action docs](github-action.md) for full configuration.

## Next Steps

- [Configuration Reference](configuration.md) — all CLI flags and aastf.yaml fields
- [EU AI Act Compliance](compliance.md) — compliance readiness scoring
