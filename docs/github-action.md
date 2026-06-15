# AASTF GitHub Action

Run agentic AI security testing in your CI/CD pipeline with automatic SARIF upload to GitHub Code Scanning.

## Quick Start

Add this workflow to `.github/workflows/aastf-scan.yml`:

```yaml
name: AASTF Security Scan

on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: anonymousAAK/aastf/.github/actions/aastf-scan@master
        with:
          agent-module: 'myapp.agent:create_agent'
          adapter: 'langgraph'
          fail-on: 'HIGH'
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `agent-module` | Yes | - | Dotted path to agent factory (e.g. `myapp.agent:create_agent`) |
| `adapter` | No | `langgraph` | Framework adapter (`langgraph`, `crewai`, `openai_agents`, `pydantic_ai`) |
| `categories` | No | _(all)_ | Comma-separated ASI categories (e.g. `ASI01,ASI02`) |
| `fail-on` | No | `HIGH` | Minimum severity to fail the check (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `python-version` | No | `3.12` | Python version to use |
| `aastf-version` | No | `latest` | AASTF version to install (e.g. `0.4.1`) |
| `upload-sarif` | No | `true` | Upload SARIF to GitHub Code Scanning |
| `extra-args` | No | - | Additional arguments passed to `aastf run` |

## Outputs

| Output | Description |
|--------|-------------|
| `report-path` | Path to the JSON report file |
| `sarif-path` | Path to the SARIF report file |
| `risk-score` | Overall risk score (0-100) |
| `vulnerable-count` | Number of vulnerable findings |
| `exit-code` | AASTF exit code: `0` = safe, `1` = findings above threshold, `2` = error |

## Examples

### Test specific ASI categories

```yaml
- uses: anonymousAAK/aastf/.github/actions/aastf-scan@master
  with:
    agent-module: 'myapp.agent:create_agent'
    categories: 'ASI01,ASI03,ASI05'
    fail-on: 'MEDIUM'
```

### Matrix strategy across multiple adapters

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    strategy:
      matrix:
        adapter: [langgraph, crewai, openai_agents, pydantic_ai]
    steps:
      - uses: actions/checkout@v4

      - uses: anonymousAAK/aastf/.github/actions/aastf-scan@master
        with:
          agent-module: 'myapp.agent:create_agent'
          adapter: ${{ matrix.adapter }}
          fail-on: 'HIGH'
```

### Pin a specific AASTF version

```yaml
- uses: anonymousAAK/aastf/.github/actions/aastf-scan@master
  with:
    agent-module: 'myapp.agent:create_agent'
    aastf-version: '2.0.0'
```

### Pass extra arguments

```yaml
- uses: anonymousAAK/aastf/.github/actions/aastf-scan@master
  with:
    agent-module: 'myapp.agent:create_agent'
    extra-args: '--timeout 60 --exclude ASI07-001 --exclude ASI07-002'
```

### Use outputs in subsequent steps

```yaml
- uses: anonymousAAK/aastf/.github/actions/aastf-scan@master
  id: scan

- name: Comment on PR
  if: always() && github.event_name == 'pull_request'
  uses: actions/github-script@v7
  with:
    script: |
      github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body: `AASTF scan: risk score **${{ steps.scan.outputs.risk-score }}**, ` +
              `**${{ steps.scan.outputs.vulnerable-count }}** findings`
      })
```

## How SARIF Shows Up in GitHub

When `upload-sarif` is `true` (the default), scan results appear in the **Security** tab of your repository under **Code scanning alerts**. Each vulnerability finding includes:

- The ASI category (e.g. ASI01 - Prompt Injection)
- Severity level
- Description and remediation guidance
- Links to OWASP ASI references

Pull requests will show findings inline as code scanning annotations, blocking merges when branch protection rules require it.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All scenarios passed or findings are below the `fail-on` threshold |
| `1` | One or more findings at or above the `fail-on` severity |
| `2` | Framework error (invalid agent module, adapter failure, etc.) |
