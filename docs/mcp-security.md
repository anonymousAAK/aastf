# MCP Security Testing

## Overview

The Model Context Protocol (MCP) enables AI agents to interact with external tools and resources through a standardized protocol. While powerful, MCP introduces several attack surfaces that AASTF systematically tests.

## Attack Taxonomy

AASTF's MCP scenarios are derived from three authoritative sources:

1. **MSB (MCP Security Benchmark)** — Zhang et al., ICLR 2026. 12 attack classes, 405 tools.
2. **MCPSecBench** — 17 attack types across 4 surfaces.
3. **OWASP MCP Top 10** — Community-driven MCP security risks.

### MCP01: Tool Signature Poisoning

Tool descriptions are the primary interface between MCP servers and AI agents. Poisoned descriptions can:
- Embed hidden instructions that override agent behavior
- Shadow legitimate tools with malicious alternatives
- Hide adversarial prompts in parameter schema descriptions

**Scenarios:** MCP01-001 through MCP01-003

### MCP02: Tool Parameter Manipulation

Tool input schemas define what parameters a tool accepts. Attacks include:
- Type confusion (sending objects where strings are expected)
- Schema extension via additionalProperties
- Default value poisoning with adversarial content

**Scenarios:** MCP02-001 through MCP02-003

### MCP03: Tool Response Injection

Tool responses are a primary injection vector because agents process them as trusted data:
- Prompt injection embedded in response content
- Response-triggered tool chaining (one tool's response triggers another)
- Malformed responses causing fallback to unsafe behavior

**Scenarios:** MCP03-001 through MCP03-003

### MCP04: Resource Injection

MCP resources (files, database records, etc.) can carry poisoned content:
- Embedded instructions in resource content
- URI traversal to access unauthorized resources
- Cross-server resource confusion

**Scenarios:** MCP04-001 through MCP04-003

### MCP05: Advanced Attacks (MCPSecBench)

Based on MCPSecBench taxonomy and CyberArk research:
- Full-schema poisoning rewrites entire tool definitions
- Preference manipulation biases tool selection
- Server impersonation violates trust boundaries
- Social engineering via tool descriptions
- Cross-server data exfiltration

**Scenarios:** MCP05-001 through MCP05-005

### MCP06: OWASP MCP Top 10 + Real CVEs

Real-world attack patterns from disclosed vulnerabilities:
- **Rug Pull:** Silent tool redefinition after user approval
- **Tool Shadowing:** Cross-server name collisions
- **Sampling Abuse:** Unauthorized model inference
- **Elicitation Phishing:** Credential harvesting via prompts
- **STDIO Injection:** Command injection on local MCP servers (CVE-2025-6514)
- **OAuth Leakage:** Token scraping from logs/memory
- **Consent Fatigue:** Flooding approvals to slip malicious tools
- **Shadow Servers:** Unapproved MCP deployments

**Scenarios:** MCP06-001 through MCP06-008

## Using the MCP Adapter

```python
# your_agent.py
async def mcp_agent_factory(tools, resources):
    """Factory function for MCP-based agent."""
    async def agent(prompt, base_url):
        # Your agent logic here
        # tools = list of MCP tool descriptions
        # resources = list of MCP resource contents
        # Return (output, tool_calls) tuple
        return output, tool_calls
    return agent
```

```bash
# Run MCP scan
aastf run your_agent:mcp_agent_factory --adapter mcp

# Run only MCP scenarios
aastf run your_agent:mcp_agent_factory --adapter mcp --category ASI01 --category ASI02 --category ASI03
```

## Compliance Mapping

All MCP scenarios include:
- **CWE IDs** — Common Weakness Enumeration mapping
- **NIST AI RMF** — Risk Management Framework categories
- **OWASP ASI** — Agentic Security Initiative categories

## References

- [OWASP Top 10 for MCP Servers](https://genai.owasp.org/resource/owasp-top-10-for-mcp-servers/)
- [MSB: MCP Security Benchmark (Zhang et al., ICLR 2026)](https://arxiv.org/abs/2504.03767)
- [MCPSecBench: Security Benchmark for MCP](https://arxiv.org/abs/2504.09186)
- [CVE-2025-6514: mcp-remote RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)
