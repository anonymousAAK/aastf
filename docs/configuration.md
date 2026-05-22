# Configuration Reference

AASTF can be configured via CLI flags or an `aastf.yaml` configuration file.

## CLI Commands

### `aastf run`

Execute a security scan against an agent.

```bash
aastf run <agent_module> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `agent_module` | Dotted path to agent factory (e.g. `myapp.agent:create_agent`) |

**Options:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--adapter` | `-a` | `langgraph` | Framework adapter: `langgraph`, `crewai`, `openai_agents`, `pydantic_ai` |
| `--category` | `-c` | _(all)_ | ASI categories to test (repeatable, e.g. `--category ASI01 --category ASI02`) |
| `--fail-on` | | `HIGH` | Exit code 1 if any finding at this severity or above |
| `--format` | `-f` | `console json` | Output formats: `console`, `json`, `sarif`, `html` (repeatable) |
| `--output-dir` | `-o` | `aastf-results` | Directory for report output |
| `--timeout` | `-t` | `30.0` | Per-scenario timeout in seconds |
| `--scenario-dir` | | _(none)_ | Additional scenario directory (repeatable) |
| `--exclude` | | _(none)_ | Scenario IDs to exclude (repeatable, e.g. `--exclude ASI08-003`) |
| `--dry-run` | | `false` | Show scenarios without executing |
| `--strict-output` | | `false` | Also fail on REFUSAL_ECHO findings at `--fail-on` threshold or above |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | All scenarios passed or findings below `--fail-on` threshold |
| `1` | One or more findings at or above `--fail-on` severity |
| `2` | Configuration or framework error |

### `aastf init`

Initialize an AASTF configuration file interactively.

```bash
aastf init [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | `aastf.yaml` | Config file output path |
| `--yes` | `-y` | `false` | Use defaults without prompting |

### `aastf scenario list`

List all available attack scenarios.

```bash
aastf scenario list [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--category` | `-c` | _(all)_ | Filter by ASI category (e.g. `ASI02`) |
| `--severity` | `-s` | _(all)_ | Minimum severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--tag` | `-t` | _(none)_ | Filter by tag (repeatable) |

### `aastf scenario validate`

Validate a YAML scenario file against the AASTF schema.

```bash
aastf scenario validate <path>
```

### `aastf scenario show`

Show full details for a specific scenario.

```bash
aastf scenario show <scenario_id>
```

### `aastf report show`

Re-render a scan report in a different format.

```bash
aastf report show <report_path> [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `console` | Output format: `console`, `html`, `sarif` |
| `--output` | `-o` | _(auto)_ | Output file path |

### `aastf report compare`

Compare two scan reports and show the vulnerability delta.

```bash
aastf report compare <report_a> <report_b>
```

Shows new vulnerabilities, resolved vulnerabilities, and risk score delta between two runs.

### `aastf report trend`

Show vulnerability trend across recent runs.

```bash
aastf report trend [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--runs` | `-n` | `10` | Number of recent runs to show |
| `--db` | | _(auto)_ | Path to trend database |

### `aastf serve`

Start the sandbox server standalone for manual debugging.

```bash
aastf serve [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-p` | `18080` | Port to listen on |
| `--scenario` | `-s` | _(none)_ | Load a specific scenario's tool configs (e.g. `ASI02-001`) |

### `aastf --version`

Show the installed AASTF version.

```bash
aastf --version
```

## `aastf.yaml` Configuration File

Generate a configuration file with `aastf init`. The file supports the following fields:

```yaml
# Agent module path (dotted.path:callable)
agent_module: "myapp.agent:create_agent"

# Framework adapter
adapter: langgraph

# ASI categories to test (empty = all)
categories: []

# Minimum severity to fail CI (CRITICAL, HIGH, MEDIUM, LOW, INFO)
fail_on: HIGH

# Output directory for reports
output_dir: aastf-results

# Output formats
formats:
  - console
  - json
  - sarif

# Per-scenario timeout in seconds
timeout: 30

# Additional scenario directories (optional)
# scenario_dirs:
#   - ./custom-scenarios

# Scenarios to exclude (optional)
# exclude:
#   - ASI08-003
```

## Severity Levels

Severity levels control the `--fail-on` threshold and scenario prioritization:

| Level | Numeric | Description |
|-------|---------|-------------|
| `CRITICAL` | 5 | Immediate exploitation risk, full agent compromise |
| `HIGH` | 4 | Significant security impact, likely exploitable |
| `MEDIUM` | 3 | Moderate impact, requires specific conditions |
| `LOW` | 2 | Minor impact, limited exploitability |
| `INFO` | 1 | Informational finding, no direct security impact |

## ASI Categories

All 10 OWASP Agentic Security Initiative categories:

| ID | Name | Description |
|----|------|-------------|
| `ASI01` | Agent Goal Hijack | Prompt injection that redirects agent behavior |
| `ASI02` | Tool Misuse & Exploitation | Agent tricked into calling tools maliciously |
| `ASI03` | Identity & Privilege Abuse | Privilege escalation via agent impersonation |
| `ASI04` | Supply Chain Vulnerabilities | Compromised tools, plugins, or dependencies |
| `ASI05` | Code Execution (RCE) | Agent tricked into executing arbitrary code |
| `ASI06` | Memory & Context Poisoning | Poisoned memory or context windows |
| `ASI07` | Inter-Agent Communication | Insecure multi-agent message passing |
| `ASI08` | Cascading Failures | Infinite loops, resource exhaustion, chain failures |
| `ASI09` | Human-Agent Trust Exploitation | Social engineering via agent output |
| `ASI10` | Rogue Agents | Agents acting outside their authorized scope |

## CVSS Scoring

Each finding receives a CVSS-adapted score (0.0-10.0):

| Severity | VULNERABLE score | REFUSAL_ECHO score (35% discount) |
|----------|-----------------|-----------------------------------|
| CRITICAL | 9.5 | 3.32 |
| HIGH | 7.5 | 2.62 |
| MEDIUM | 5.0 | 1.75 |
| LOW | 3.0 | 1.05 |
| INFO | 1.0 | 0.35 |

The overall run risk score (0-100) is a severity-weighted average of all actionable findings, normalized against the maximum possible score.
