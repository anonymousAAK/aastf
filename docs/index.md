# AASTF — Agentic AI Security Testing Framework

**Test your AI agents against OWASP Top 10 for Agentic Applications before they reach production.**

AASTF is an open-source, vendor-neutral security testing framework that catches prompt injection, tool misuse, privilege escalation, and 7 more attack categories. Interception depth differs by framework: **LangGraph has full event-level interception**, the **generic** adapter is supported for any agent that conforms to the agent-factory contract, and the **CrewAI, OpenAI Agents, PydanticAI, Google ADK, and Microsoft Agent** adapters are **experimental**.

## Quick Start

```bash
pip install aastf
aastf run myapp.agent:create_agent --adapter langgraph
```

## Why AASTF?

| Feature | AASTF | Others |
|---------|-------|--------|
| OWASP ASI 10/10 | Yes | Partial |
| Framework-native interception | Yes — full for LangGraph; others experimental | Generic/black-box |
| SARIF output (GitHub Security) | Yes | Rare |
| 100% local execution | Yes | Often phones home |
| EU AI Act readiness | Yes | None |
| MIT licensed | Yes | Varies |

## Features

- **50+ attack scenarios** mapped to OWASP ASI01-ASI10
- **Framework adapters**: LangGraph (full interception) and a supported generic adapter; CrewAI, OpenAI Agents SDK, PydanticAI, Google ADK, and Microsoft Agent are experimental
- **Real HTTP sandbox**: Tests against actual HTTP tool calls, not mocks
- **Multiple output formats**: Console, JSON, SARIF, HTML
- **EU AI Act readiness scoring**: Know your compliance posture
- **CVSS scoring**: Industry-standard vulnerability ratings
- **Trend tracking**: Track security posture over time
- **CI/CD ready**: GitHub Action + SARIF upload to GitHub Security tab

## OWASP ASI Categories

AASTF covers the complete OWASP Agentic Security Initiative Top 10:

| ID | Category |
|----|----------|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse & Exploitation |
| ASI03 | Identity & Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution (RCE) |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

## Next Steps

- [Quick Start](quickstart.md) — first scan in under 5 minutes
- [Configuration Reference](configuration.md) — all CLI flags and aastf.yaml fields
- [GitHub Action](github-action.md) — CI/CD integration
- [EU AI Act Compliance](compliance.md) — compliance readiness scoring
