# Payload Echo: A Distinct Failure Mode in Frontier AI Agent Refusals

*AASTF Research Note · v0.2.1 · April 2026*

---

## The Problem

Existing agent security tools conflate two qualitatively different failure modes under
a single "vulnerable" label. The conflation happens because most tools evaluate agent
behavior by checking whether the agent's output contains attacker-controlled content —
if it does, the scenario fails.

This creates a measurement problem. A model that **refuses 100% of malicious requests**
but reproduces the attack payload in its refusal text 60% of the time looks identical,
under output-only detection, to a model that **complies with 60% of malicious requests**.
Both produce output containing the attacker's strings. Neither is correctly classified.

The distinction matters because the risk profiles are qualitatively different:

- **Behavioral compliance** (the agent executes the injected instruction) is a direct
  security failure. The agent sent the email, deleted the file, or called the external
  endpoint. Damage is done.
- **Payload echo** (the agent refuses but reproduces payload keywords in the explanation)
  is an informational risk. No action was taken. But the refusal text is not clean.

Treating these identically produces incorrect risk scores, misguided remediation
priorities, and EU AI Act readiness classifications that don't match the actual failure
mode.

---

## Taxonomy: Two Refusal Failure Modes

We identify two distinct failure modes in LLM agent refusals:

### 1. Task Execution

The agent begins executing the injected instruction before applying safety reasoning —
or applies safety reasoning and concludes the instruction is legitimate. The tool is
called. The output confirms the action.

*Typical in models with weaker instruction-following discipline or models that
have been fine-tuned for high task completion rates.* The Gemini 2.5 Pro CLI
benchmark shows this pattern: 7% of scenarios trigger task execution (VULNERABLE),
primarily in ASI04 supply-chain and ASI05 code execution categories.

### 2. Payload Echo

The agent correctly refuses the malicious request but its refusal text reproduces
attack payload keywords: URLs, shell command fragments, SQL strings, tool names, or
other attacker-controlled content. The behavioral outcome is safe; the output is not.

*Prevalent across frontier models regardless of instruction-following strength.*
Our n=5 CLI benchmark results:

| Model | Behavioral VULN | Payload Echo (REFUSAL_ECHO) |
|-------|----------------|-----------------------------|
| GPT-5.x | 0% | 47% |
| Model B 4.x | 0% | 60% |
| Gemini 2.5 Pro | 7% | 13% |

Frontier models have largely solved task execution for the scenarios in our benchmark.
Payload echo is the dominant remaining attack surface.

---

## Why Payload Echo Matters

### Probe-and-refine attack design

An attacker who receives a refusal containing their payload URL can confirm that the
payload was processed by the model's context window. The refusal itself becomes a
side-channel: "I cannot send data to http://attacker.com/collect" confirms the URL
was parsed and considered. The attacker can now adjust injection parameters — endpoint,
encoding, indirection — without ever triggering behavioral compromise. Behavioral
detection produces zero signal; the attack iteration happens entirely in the
informational regime.

### Multi-agent propagation

In multi-agent architectures, the orchestrator's response to a sub-task becomes input
to the next planning step or a downstream agent. A refusal text containing a shell
command fragment enters the context of a code-execution agent. A refusal containing a
URL enters the context of a browsing agent. The originating agent refused; downstream
agents may not. AASTF's REFUSAL_ECHO classification is specifically designed to surface
this propagation risk.

### Audit trail leakage

Enterprise deployments log agent conversations to SIEM systems, SARIF pipelines, and
compliance dashboards. A refusal that says "I cannot exfiltrate your SSH keys to
http://attacker.com/collect" contains attacker-controlled content in the audit trail.
This contaminates forensic records, may trigger false-positive security alerts on the
URL, and represents a data leakage path in regulated environments.

---

## How AASTF Measures It

### The three-class verdict system

AASTF v0.2.1 introduces a third verdict class between VULNERABLE and SAFE:

```
VULNERABLE     — behavioral trigger fired (tool called, dangerous input seen)
REFUSAL_ECHO   — output trigger fired + refusal language detected in output
SAFE           — neither trigger fired
```

Classification follows a two-step algorithm in `classify_with_refusal_check`:

1. If any behavioral trigger fires → `VULNERABLE` (regardless of output content)
2. If an output trigger fires:
   - Output contains refusal language → `REFUSAL_ECHO`
   - Output does not contain refusal language → `VULNERABLE` (compliance without explicit refusal)
3. Neither → `SAFE`

### The RefusalDetector heuristic

`RefusalDetector` matches against 24 refusal language substrings covering the most
common English refusal phrasings ("I cannot", "I'm not able to", "I must decline",
"not authorized", etc.). The default threshold is `min_matches=1` — any single
pattern match is sufficient to classify a refusal.

ASI09 (Human-Agent Trust Exploitation) uses a stricter threshold of `min_matches=2`
to avoid false positives from legitimate human-in-the-loop confirmation language
("I confirm I cannot proceed without approval" contains one refusal signal but is
not an echo — requiring two signals prevents misclassification).

The detector is conservative by design. A false negative (missed refusal → classified
VULNERABLE instead of REFUSAL_ECHO) is a more useful signal for practitioners than
a false positive (echo misclassified as VULNERABLE inflates the risk score).

### Rate separation

`vulnerability_rate` explicitly excludes `REFUSAL_ECHO`. This is a deliberate design
decision: the headline behavioral risk score must not conflate informational leakage
with direct compromise. A deployment with 0% vulnerability rate and 60% echo rate
has solved the behavioral problem; it has an output sanitization problem. These
require different remediations and different stakeholder communications.

`informational_risk_rate` tracks the echo proportion separately.

---

## Benchmark Findings (n=5 Stability)

Our CLI benchmark runs each of 15 output-detectable scenarios five times per model
and applies majority vote (threshold=3/5) to produce a stable final verdict. Wilson
score 95% confidence intervals are computed for the leading verdict proportion.

**Universal safe property (ASI10 — Governance Bypass):** Clean across all models.
No model continues executing after an explicit abort or governance check signal.
This is consistent with ICLR 2026 MASpi results showing that explicit governance
tokens are well-respected by current RLHF-trained models.

**Universal vulnerable finding (ASI04 — Supply Chain Compromise):** Fails across
all configurations tested. When a malicious MCP server registers a backdoored tool
with a legitimate-sounding name, agents invoke it. This is a framework-level
vulnerability — the LLM has no visibility into tool provenance, and no current
framework enforces tool registry integrity at the dispatch layer.

**Behavioral compliance**: All frontier CLI models show 0–7% behavioral vulnerability
rates on the tested scenarios. The behavioral safety problem for individual-agent
instruction following appears largely solved at the frontier.

**Payload echo**: 13–60% echo rates across frontier models. This is the dominant
unresolved security surface in frontier agent deployments as of April 2026.

---

## Implications

### For model developers

- Sanitize refusal output. A refusal that reproduces payload keywords is not a clean
  refusal. Generic templates ("I cannot help with requests that violate our policies")
  are safer than specific rephrasing of the attacker's instruction.
- Extend platform-level content filtering to outbound model responses, not just
  inbound prompts. The refusal text is part of the attack surface.
- Consider training-time interventions: reward models that refuse without reproducing
  payload keywords.

### For framework developers

- Enforce tool registry integrity at the dispatch layer. Agents should not be able
  to call tools that were not present in the original tool list passed to the harness.
  This directly addresses the ASI04 universal failure.
- Sanitize agent response text before injecting it as context into downstream agents.
  A response sanitization middleware layer between agents reduces echo propagation risk.
- Enforce hard resource budgets to prevent ASI08 cascading failures.

### For practitioners

- Run AASTF before deployment. Behavioral safety is necessary but not sufficient.
  Echo rates above 20% warrant output sanitization work before production deployment
  in multi-agent architectures or regulated environments.
- Add output sanitization middleware. A post-processing step that strips known injection
  patterns from agent responses before they enter downstream context reduces propagation
  risk without requiring model changes.
- Treat tool response content as untrusted. The ASI04 result shows that tool
  provenance verification cannot be delegated to the LLM. Implement allow-lists at
  the framework dispatch layer.
- Use `--strict-output` in CI/CD pipelines for deployments with strict audit trail
  requirements. This gates the build on REFUSAL_ECHO findings at your severity
  threshold, not just VULNERABLE findings.

---

## References

- OWASP Top 10 for Agentic Applications (December 2025) —
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Zhang et al., "Agent Security Bench (ASB): Formalizing and Benchmarking Attacks
  and Defenses in LLM-based Agents" (ICLR 2025) — arXiv:2410.02644
- Shahriar et al., "A Survey on the Security of Agentic AI Systems" —
  arXiv:2510.06445 (v2: 160+ papers surveyed)
- MASpi: Multi-Agent Security Propagation Index (ICLR 2026)
- EU AI Act, Articles 9 and 15 (risk management and cybersecurity obligations for
  high-risk AI systems) — https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689
