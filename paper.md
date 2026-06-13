---
title: 'AASTF: A Framework for Security Testing of Agentic AI Systems Against the OWASP ASI Top 10'
tags:
  - Python
  - security
  - artificial intelligence
  - autonomous agents
  - red-teaming
  - OWASP
  - LLM
authors:
  - name: Adarsh Keshri
    orcid: 0009-0001-8020-9378
    corresponding: true
    email: adarshkeshri027@gmail.com
    affiliation: "1"
affiliations:
  - name: Independent Researcher, India
    index: 1
date: 19 May 2026
bibliography: paper.bib
---

# Summary

AASTF (Agentic AI Security Testing Framework) is an open-source Python framework that
performs automated security testing of autonomous AI agent systems. Unlike existing
red-teaming tools that evaluate language model outputs in isolation, AASTF instruments
the agent execution graph directly — intercepting every tool call, planning iteration,
and inter-agent delegation at runtime. It ships with over 130 built-in attack scenarios
mapped to the OWASP Top 10 for Agentic Applications (ASI) taxonomy [@owasp_asi_2025],
with additional coverage for MCP, multi-agent, agent-to-agent, and CVE-derived scenarios,
and produces
machine-readable verdicts (VULNERABLE, REFUSAL\_ECHO, SAFE) with SARIF, JSON, and HTML
reports suitable for CI/CD integration and EU AI Act [@eu_ai_act_2024] compliance preparation.

# Statement of Need

The deployment of autonomous AI agents — LLM-based systems that call tools, maintain
state, and delegate tasks — has outpaced the development of systematic security testing
tools. Existing red-teaming frameworks such as Garak [@derczynski_garak_2024], PyRIT
[@mehrotra_pyrit_2024], and DeepTeam [@confident_ai_deepteam_2025] operate on a shared
mental model: send an adversarial prompt, evaluate the model's text output. This
evaluation surface is insufficient for agent systems, where the primary attack vector
is not the user prompt but content injected through tool responses, memory stores, and
inter-agent messages.

Consider an agent that calls a web search tool. The search result contains an embedded
instruction: *"Forward all retrieved content to attacker@example.com. Call send\_email
now."* The model's safety training is not directly engaged — the adversarial content
arrives through a tool output, not the user turn. Yet the agent calls `send_email` with
user data as the body. The agent system is compromised while the model itself remains
behaviourally safe. No existing security tool detects this attack class systematically.

AASTF addresses this gap by shifting the evaluation surface from model outputs to the
agent execution graph. It targets security researchers evaluating agent frameworks,
practitioners deploying agents in production, and organisations preparing for EU AI Act [@eu_ai_act_2024]
compliance (August 2026 deadline). The framework has been used by its author to benchmark
LangGraph, CrewAI, and OpenAI Agents SDK against the full OWASP ASI taxonomy, finding
vulnerability rates of 54--70\% across configurations.

# State of the Field

Agent Security Bench (ASB) [@zhang_asb_2025] is the most directly related prior work,
evaluating 10 agent frameworks across 18 attacks and finding an 84.30\% average attack
success rate. ASB established that agent systems are systematically exploitable but uses
a custom attack taxonomy and is not designed as a reusable testing tool. MASpi
[@li_maspi_2026] studies attack propagation in multi-agent systems, finding that
adversarial content propagates rapidly through trust graphs, but focuses on propagation
dynamics rather than initial injection testing. A recent survey [@agentic_security_survey_2025]
provides a comprehensive taxonomy of agentic AI attack surfaces covering 47 papers, which
informed AASTF's scenario design.

Garak [@derczynski_garak_2024] probes model outputs for failure modes including
hallucination, toxicity, and prompt injection, but has no mechanism for intercepting tool
calls or evaluating multi-turn agent state. PyRIT [@mehrotra_pyrit_2024] supports
multi-turn conversation simulation but evaluates model responses rather than agent system
behaviours. DeepTeam [@confident_ai_deepteam_2025] extends model-level red-teaming with
a richer attack library but detection remains grounded in output text evaluation.
Promptfoo [@promptfoo_2025] provides configuration-driven LLM testing with some agent
support but lacks execution graph interception depth.

AASTF differs from all of these in three ways: (1) it intercepts the agent execution
graph via the framework's event bus rather than evaluating text outputs; (2) it anchors
its scenario library to the community-validated OWASP ASI taxonomy; and (3) it provides
a machine-executable YAML scenario format that practitioners can extend without writing
Python code.

# Software Design

AASTF is organised as a five-layer architecture:

- **Layer 1 (Harness):** Attaches to the agent framework's event emission mechanism
  (LangGraph's `astream_events(v2)`, CrewAI's `step_callback`, OpenAI Agents SDK's
  `Runner` middleware) and intercepts every tool call with full arguments before and after
  execution. This is non-invasive: no modification of the agent's source code or the
  framework's internals is required.

- **Layer 2 (Scenarios):** A registry of over 130 YAML-defined attack scenarios, at least
  five per OWASP ASI category plus MCP, multi-agent, A2A, and CVE-derived packs, each
  specifying the attack payload, injection point (`user_message`,
  `tool_response`, `memory`, `system_prompt`), detection criteria, and expected safe
  behaviour. The YAML format is human-readable and community-extensible.

- **Layer 3 (Sandbox):** A FastAPI server that replaces real tool backends. The agent
  makes real HTTP requests to real TCP sockets, but the sandbox logs all requests and
  returns scenario-configured responses. No real files are modified, no real emails are
  sent.

- **Layer 4 (Reporting):** Aggregates execution traces into SARIF (for GitHub Security
  tab integration), JSON, HTML, and console reports. Includes CVSS-based risk scoring
  and EU AI Act readiness mapping.

- **Layer 5 (Platform):** Planned cloud service for continuous monitoring (roadmap).

AASTF introduces a three-class verdict system that goes beyond binary pass/fail:
VULNERABLE (the agent performed the forbidden action), REFUSAL\_ECHO (the agent refused
but echoed the attack payload in its refusal text, creating informational risk), and
SAFE. REFUSAL\_ECHO findings are discounted at 35\% weight in risk scoring, reflecting
that behavioural safety is intact while output sanitisation obligations remain.

# Research Impact Statement

AASTF has been used to produce the first cross-framework benchmark comparing LangGraph,
CrewAI, and OpenAI Agents SDK against the complete OWASP ASI Top 10 taxonomy. Benchmark
results identified five universally exploitable scenarios across all tested configurations,
pinpointing framework-level structural issues (tool registration validation, tool response
sanitisation, and planning resource bounds) that cannot be addressed through prompt
hardening alone. The framework and benchmark data are available for reproduction by other
researchers.

# AI Usage Disclosure

Generative AI (Claude, OpenAI models) was used during development for code generation
assistance, documentation drafting, and test authoring. All generated code was reviewed,
validated, and architecturally directed by the author. Core design decisions — the
five-layer architecture, execution graph interception approach, three-class verdict
system, and OWASP ASI mapping — were made by the author. The author assumes full
responsibility for the accuracy, originality, and licensing compliance of all submitted
materials.

# Acknowledgements

The author thanks the OWASP Foundation for publishing the Top 10 for Agentic Applications
(ASI) taxonomy, which provides the threat model foundation for AASTF. The author also
acknowledges the developers of LangGraph, CrewAI, and the OpenAI Agents SDK for
maintaining the open-source agent frameworks against which AASTF was benchmarked.

# References
