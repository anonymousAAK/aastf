# Competitive Feature Matrix: AI Agent Security Tools (May 2026)

## 1. Market Landscape Overview

The AI agent security market has undergone rapid consolidation AND expansion. Six tools
were acquired in the last 18 months, while multiple well-funded new entrants have
launched. Two critical new threats to AASTF's positioning have emerged:

1. **Microsoft Agent Governance Toolkit (AGT)** -- Released April 2026, MIT-licensed,
   claims 10/10 OWASP Agentic Top 10 coverage with 20+ framework adapters (including
   LangChain, CrewAI, Google ADK). This directly challenges AASTF's two key
   differentiators.

2. **Microsoft RAMPART** -- Released May 20, 2026, a pytest-native agent security
   testing framework built on PyRIT. CI-gatable, adapter-based, with statistical
   trial support. Directly competes with AASTF's testing-focused workflow.

3. **Onyx Security** -- Launched March 2026 with $40M funding, 70-person team, already
   securing 137K+ agents. Full control-plane: discovery, governance, runtime, ROI.

---

## 2. CRITICAL NEW COMPETITORS (Not in Previous Matrix)

### 2.1 Microsoft Agent Governance Toolkit (AGT) -- HIGHEST THREAT

| Attribute | Detail |
|---|---|
| **What it does** | Policy enforcement, zero-trust identity, execution sandboxing, reliability engineering for autonomous AI agents |
| **Released** | April 2, 2026 |
| **OWASP coverage** | **10/10 OWASP Agentic Top 10** (documented mapping in repo) |
| **License** | MIT |
| **Framework adapters** | **20+ adapters**: LangChain, CrewAI, Google ADK, Microsoft Agent Framework, plus TypeScript SDK (npm) and .NET SDK (NuGet) |
| **MCP scanning** | Yes (MCP Security Gateway) |
| **Runtime protection** | Yes (sub-millisecond, deterministic policy enforcement; 0.00% violation rate in red-team testing vs 26.67% for prompt-based safety) |
| **Identity/trust** | DID-based identity with behavioral trust scoring |
| **Supply chain** | Plugin signing with Ed25519, manifest verification |
| **Code execution** | Execution rings with resource limits |
| **Memory safety** | Cross-Model Verification Kernel (CMVK) with majority voting |
| **Inter-agent comms** | Agent Mesh for securing agent-to-agent communication |
| **Compliance** | Agent Compliance module for automated governance verification |
| **Architecture** | Monorepo with 7 independently installable packages |
| **Python version** | 3.10+ |
| **Why it matters** | **Eliminates both of AASTF's unique differentiators** (10/10 OWASP + framework adapters) while adding runtime governance, identity, and compliance that AASTF lacks |

### 2.2 Microsoft RAMPART (Risk Assessment and Measurement Platform for Agentic Red Teaming)

| Attribute | Detail |
|---|---|
| **What it does** | Pytest-native safety/security testing for AI agents; CI-gatable; built on PyRIT |
| **Released** | May 20, 2026 |
| **License** | Open source (Microsoft) |
| **Key innovation** | Tests written as standard pytest tests; adapter connects to agent; orchestrates interaction; returns pass/fail |
| **CI/CD** | Native -- tests gate CI pipelines like any integration test |
| **Statistical trials** | Supports "must be safe in at least X% of runs" policies (handles LLM non-determinism) |
| **Primary focus** | Cross-prompt injection attacks (most mature coverage) |
| **Framework integration** | Thin adapter model (connects to any agent) |
| **Attack strategies** | Inherits PyRIT's 6+ strategies: Crescendo, TAP, multi-turn, XPIA |
| **Datasets** | Inherits PyRIT's 53+ adversarial datasets |
| **Why it matters** | Developer-friendly testing (pytest!) with CI gating -- the exact workflow AASTF should own |

### 2.3 Onyx Security

| Attribute | Detail |
|---|---|
| **What it does** | AI control plane: discovery, monitoring, governance, orchestration, ROI measurement |
| **Launched** | March 2026 (18 months stealth) |
| **Funding** | $40M (Conviction + Cyberstarts) |
| **Team size** | ~70 employees |
| **Scale** | 137,000+ agents secured, 593,000+ employees, 10M+ sessions |
| **Key feature** | Guardian Agent -- supervisory AI that auto-identifies/remediates risks; blocks actions, requires human approval, or redirects agent behavior |
| **Compliance** | Policy templates aligned to MITRE, NIST, OWASP |
| **MCP support** | Yes (MCP deployment orchestration) |
| **ROI tracking** | Built-in adoption metrics and departmental attainment tracking |
| **Why it matters** | Enterprise-grade at launch; shows what funded competitors can build in 18 months of stealth |

### 2.4 Repello AI (Agent-Wiz + ARTEMIS)

| Attribute | Detail |
|---|---|
| **What it does** | Automated red teaming (ARTEMIS engine, 15M+ attack patterns), Agent-Wiz (open-source threat modeling CLI) |
| **Agent-Wiz frameworks** | LangGraph, AutoGen, CrewAI, Swarm, Pydantic AI |
| **OWASP coverage** | LLM Top 10, NIST AI RMF, MITRE ATLAS |
| **Threat modeling** | MAESTRO framework (12 agentic failure modes); STRIDE/PASTA/LINDDUN planned |
| **MCP testing** | Yes |
| **License** | Agent-Wiz: open source; ARTEMIS: proprietary |
| **Why it matters** | Agent-Wiz supports the SAME frameworks as AASTF (LangGraph, CrewAI, Pydantic AI) -- AASTF no longer unique in framework support |

### 2.5 Augustus (Praetorian)

| Attribute | Detail |
|---|---|
| **What it does** | Go-based LLM vulnerability scanner; 210+ attacks, 28 LLM provider integrations |
| **License** | Open source |
| **Language** | Go (single binary) |
| **Probes** | 190+ covering prompt injection, jailbreaks, adversarial attacks |
| **Why it matters** | Single-binary deployment is very DevOps-friendly; broad provider support |

### 2.6 FuzzyAI (CyberArk)

| Attribute | Detail |
|---|---|
| **What it does** | LLM fuzzing framework; 18 attack techniques |
| **License** | Apache 2.0 |
| **GitHub stars** | ~1,300 |
| **Targets** | 8 providers: OpenAI, Anthropic, Google, Azure, Bedrock, HuggingFace, Ollama, custom REST |
| **Techniques** | ArtPrompt, DAN jailbreaks, crescendo, genetic algorithm mutations, ASCII smuggling |

---

## 3. UPDATED EXISTING COMPETITOR PROFILES

### 3.1 Promptfoo (acquired by OpenAI, March 2026)

| Attribute | Detail |
|---|---|
| **What it does** | LLM red-teaming and evaluation; 50+ vulnerability types |
| **Acquisition** | OpenAI, ~$86M, March 2026 (pending closing) |
| **NEW: Coding agent evals** | Now covers OpenAI Codex SDK, Claude Agent SDK, OpenCode SDK |
| **NEW: Agent testing** | Multi-turn agentic workflows with OpenAI Agents SDK (tools, session history, handoffs, sandbox runtime) |
| **CI/CD** | GitHub Action, GitLab CI, Jenkins, CircleCI (still the best CI/CD story) |
| **Dynamic attacks** | ML-based dynamic attack generation (not static jailbreak lists) |
| **Adoption** | 25%+ of Fortune 500; 350,000 developer community |
| **License** | MIT (still open source post-acquisition) |
| **Risk** | May become OpenAI-centric; unclear long-term neutrality |

### 3.2 Invariant Labs / Snyk Agent Scan (acquired by Snyk, June 2025)

| Attribute | Detail |
|---|---|
| **What it does** | MCP/agent skill scanning, runtime guardrails, trace inspection |
| **NEW: Rebranded** | Now "Snyk Agent Scan" (v0.4.13, April 2026) |
| **NEW: 15+ risk categories** | Prompt injection, tool poisoning, tool shadowing, toxic flows, malware in NL, credential handling, hardcoded secrets |
| **NEW: Tool Pinning** | Detects MCP rug pulls -- silent changes to tool descriptions after installation -- by tracking tool hashes over time |
| **NEW: Operating modes** | Passive scan (one-time) + Active proxy (continuous runtime monitoring with guardrail enforcement) |
| **NEW: Hooks-based guardrails** | Snyk Studio replacing rules-based guardrails with deterministic async hooks |
| **Partnership** | Snyk + Vercel securing agent skill ecosystem |

### 3.3 Lakera / Check Point AI Defense Plane (acquired Sept 2025)

| Attribute | Detail |
|---|---|
| **What it does** | Lakera Guard (runtime firewall) + Check Point AI Defense Plane |
| **NEW: AI Defense Plane** | Launched March 23, 2026 -- unified AI security control plane |
| **Capabilities** | Discovery, governance, observability, runtime control, continuous validation |
| **Performance** | Adaptive protection <50ms, 100+ languages |
| **Built on** | ThreatCloud AI + Lakera + Cyata acquisitions |
| **NEW: Google Cloud integration** | Gemini Enterprise Agent Platform integration coming late June 2026 |

### 3.4 Garak (NVIDIA)

| Attribute | Detail |
|---|---|
| **Latest version** | v0.14.0 (February 2026) -- redesigned HTML reports, JSON config support |
| **Probes** | 120+ modules |
| **NEW: Agent breaker probe** | Tests tools available to target systems (experimental agent testing) |
| **Still lacking** | No framework adapters, no MCP scanning, no multi-agent testing |
| **NeMo Guardrails** | Separate NVIDIA product -- NIM microservices for agentic AI safety (content safety, topic control, jailbreak detection); integrates with LangChain, LangGraph, LlamaIndex; ~500ms latency overhead |

### 3.5 DeepTeam (Confident AI)

| Attribute | Detail |
|---|---|
| **Latest version** | v1.0.0 (stable release) |
| **GitHub stars** | ~1,277 (22 contributors) |
| **Vulnerabilities** | 50+ types |
| **Attack methods** | 20+ research-backed (single-turn + multi-turn) |
| **Guardrails** | 7 production-ready guardrails for binary classification |
| **Frameworks** | OWASP ASI 2026, NIST, MITRE, Aegis, BeaverTails |
| **Still lacking** | No native framework adapters, no MCP scanning, no CI/CD integration |

### 3.6 Microsoft PyRIT

| Attribute | Detail |
|---|---|
| **Latest version** | v2.0 (April 28, 2026) |
| **Attack strategies** | 6+ (Crescendo, TAP, TreeOfAttacks, multi-turn, XPIA) |
| **Converters** | 70+ prompt converters (Base64, ROT13, Leetspeak, Unicode, LLM-powered) |
| **Datasets** | 53+ (AIRT, HarmBench, AdvBench, XSTest) |
| **NEW: Spawned RAMPART** | PyRIT = researcher tool; RAMPART = developer CI tool (see above) |
| **NEW: Agent Governance Toolkit** | Separate project for runtime governance (see above) |
| **Ecosystem** | Microsoft now has THREE open-source agent security projects (PyRIT + RAMPART + AGT) |

### 3.7 Cisco DefenseClaw (launched March 27, 2026)

| Attribute | Detail |
|---|---|
| **What it does** | Secure agent framework: Skills Scanner, MCP Scanner, AI BoM, CodeGuard |
| **NEW: 5-minute install** | Scans agent skills, MCP servers, and AI-generated code before they run |
| **NEW: Drift detection** | Tracks skill state over time; detects skills that start exfiltrating data |
| **NEW: 2-second enforcement** | Block MCP servers without agent restart |
| **NEW: Splunk telemetry** | Built-in SIEM integration |
| **NEW: NVIDIA OpenShell** | DefenseClaw hooks directly into NVIDIA's OpenShell |
| **License** | Apache 2.0 (open source) |

### 3.8 HiddenLayer (updated March 23, 2026)

| Attribute | Detail |
|---|---|
| **NEW: Agentic Runtime Security** | Three new capabilities (March 2026) |
| **Runtime Visibility** | Reconstructs every session -- how agents interact with data, tools, other agents |
| **Threat Detection** | Search, filter, pivot across sessions, tools, execution paths |
| **Policy Enforcement** | Adaptive real-time policies: control access, redact data, block unsafe actions |
| **Scale** | 1 in 8 AI breaches linked to agentic systems (per their 2026 report) |
| **Funding** | $56M total; ~169 employees; independent |

### 3.9 Pillar Security (updated 2026)

| Attribute | Detail |
|---|---|
| **NEW: RedGraph** | Attack surface mapping: agents as nodes, relationships as edges (tools, MCP servers, datasets, SaaS apps, permissions) |
| **Discovery** | Maps every agent, tool, MCP server, data access, permissions, business use cases |
| **Partnership** | Wiz partnership for AI discovery to attack surface mapping |
| **Recognition** | Gartner Representative Vendor in "Market Guide for Guardian Agents" 2026 |
| **Funding** | $9M seed; ~31 employees |

### 3.10 Noma Security (updated 2026)

| Attribute | Detail |
|---|---|
| **Products** | Discovery/Posture (AI-SPM), Access Control, Red Teaming, Runtime Detection & Response (AI-DR) |
| **NEW: Cursor integration** | First provider to leverage Cursor's Agent Hooks for real-time AIDR |
| **NEW: AWS Security Hub** | Available in Extended plan (February 2026) |
| **NEW: Agent discovery** | Auto-discovers agents, toolsets, data access, MCP server connections |
| **NEW: Cascading risk** | Visualizes/analyzes agent connections to uncover cascading risk scenarios |
| **Recognition** | Rising in Cyber 2026 list |

### 3.11 Lasso Security

| Attribute | Detail |
|---|---|
| **Products** | AI Discovery, AISPM, Model Risk Management, Red Teaming, Runtime Protection |
| **Purple teaming** | Auto-updates policies from red team findings |
| **Enforcement** | Inline at proxy, API, or AI Gateway layer |
| **Pricing** | Custom enterprise (not published) |

### 3.12 Mindgard

| Attribute | Detail |
|---|---|
| **What it does** | DAST-AI: automated red teaming + continuous security testing for LLMs, agents, multimodal models |
| **NEW: Recon module (March 2026)** | Discovers AI guardrails, system prompts, tools, integrations, external services |
| **NEW: MCP/A2A discovery** | Identifies MCP/A2A servers, connected tools, shadow AI |
| **Compliance** | SOC 2 Type II certified, GDPR compliant |
| **CI/CD** | Native pipeline integration for continuous monitoring |
| **Attack alignment** | MITRE ATLAS, OWASP LLM Top 10 |
| **Recognition** | 2025 Cybersecurity Excellence Award for Best AI Security Solution |
| **Pricing** | Custom enterprise |

### 3.13 Palo Alto Prisma AIRS 3.0 (March 23, 2026)

| Attribute | Detail |
|---|---|
| **What it does** | Full agentic AI lifecycle: discovery, red teaming, runtime defense, governance |
| **Prevention** | 30+ prompt injection/jailbreak techniques, 1000+ sensitive data patterns |
| **Agent discovery** | Inventory agents, models, connections across cloud, SaaS, endpoints |
| **Identity** | CyberArk integration for Agent Identity Security (least-privilege) |
| **AI Gateway** | Agent artifact scanning, automated red teaming, runtime security |
| **Built on** | Protect AI acquisition ($500M) |

### 3.14 F5 AI Guardrails / AI Red Team (Jan 2026)

| Attribute | Detail |
|---|---|
| **What it does** | Runtime AI security from CalypsoAI acquisition ($180M) |
| **Red teaming** | 10,000+ new attack prompts/month; produces risk score |
| **NEW: Agentic Fingerprints** | Granular insight into every AI interaction with reasoning for accept/block |
| **Compliance** | GDPR/EU AI Act audit log support |
| **Agent protection** | Out-of-the-box and custom guardrails for agent connections |

---

## 4. ADJACENT ECOSYSTEM PLAYERS (Not Direct Competitors But Relevant)

| Player | Role | Why It Matters |
|---|---|---|
| **Wiz AI-APP** | Cloud AI-SPM: discovers models, agents, MCP servers across AWS/Azure/GCP | Partners with Pillar; sets expectation for cloud-native discovery |
| **NVIDIA NeMo Guardrails** | Runtime guardrails NIM microservices for agentic AI | Integrates with LangChain, LangGraph, LlamaIndex; GPU-accelerated |
| **Guardrails AI** | Open-source I/O validation (guardrails-ai/guardrails) | Hub ecosystem with community validators; tool guardrails for pre/post execution |
| **Holistic AI** | EU AI Act compliance automation platform | AI system classification, obligation tracking, compliance scoring |
| **Vanta** | GRC platform with EU AI Act module | Integrations, real-time automation, unified compliance dashboard |
| **Wiz + Pillar** | Partnership | AI discovery (Wiz) flows into attack surface mapping (Pillar RedGraph) |

---

## 5. UPDATED FEATURE COMPARISON MATRIX

### 5.1 Core Security Testing

| Feature | AASTF | MS AGT | RAMPART | Promptfoo | Snyk/Invariant | Lakera/CP | Garak | DeepTeam | PyRIT v2 | Cisco DC | HiddenLayer | Pillar | Noma | Onyx | Repello | Mindgard |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Pre-deployment testing | Yes | No* | **Yes** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | No | Yes | Yes |
| Runtime protection | No | **Yes** | No | No | **Yes** | **Yes** | No | Yes | No | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** |
| CI/CD native | No | No | **Yes (pytest)** | **Yes** | Via Snyk | API | No | No | No | IDE | Enterprise | Enterprise | Enterprise | Enterprise | No | **Yes** |
| SARIF output | **Yes** | No | No | **Yes** | Via Snyk | No | No | No | No | No | No | No | No | No | No | No |

*AGT is runtime governance, not pre-deployment testing

### 5.2 OWASP Agentic Top 10 Coverage

| ASI Category | AASTF | MS AGT | RAMPART | Promptfoo | DeepTeam | Cisco DC | Repello |
|---|---|---|---|---|---|---|---|
| ASI01: Goal Hijacking | Yes | **Yes** (intent classifier) | Yes (XPIA) | Yes | Yes | No | Yes |
| ASI02: Tool Misuse | Yes | **Yes** (capability sandbox + MCP gateway) | Partial | Yes | Yes | **Yes** | Yes |
| ASI03: Identity/Privilege | Yes | **Yes** (DID + behavioral trust) | No | Partial | Yes | No | Partial |
| ASI04: Supply Chain | Yes | **Yes** (Ed25519 plugin signing) | No | Yes | Yes | **Yes** | Yes |
| ASI05: Code Execution | Yes | **Yes** (execution rings) | No | Partial | Yes | **Yes** (CodeGuard) | Partial |
| ASI06: Context/Memory | Yes | **Yes** (CMVK majority voting) | No | Partial | Yes | No | Partial |
| ASI07: Inter-Agent Comms | Yes | **Yes** (Agent Mesh) | No | No | Yes | No | No |
| ASI08: Cascading Failures | Yes | **Yes** (Agent SRE) | No | No | Yes | No | No |
| ASI09: Trust Exploitation | Yes | **Yes** (behavioral trust scoring) | No | No | Yes | No | No |
| ASI10: Rogue Agents | Yes | **Yes** (Agent SRE) | No | No | Yes | No | No |
| **Total /10** | **10/10** | **10/10** | ~2/10 | ~4/10 | **10/10** | ~3/10 | ~5/10 |

### 5.3 Framework & Integration Support

| Feature | AASTF | MS AGT | RAMPART | Promptfoo | Repello Agent-Wiz | Snyk/Invariant | DeepTeam | Garak |
|---|---|---|---|---|---|---|---|---|
| Adapter: LangChain/LangGraph | **Yes** | **Yes** | Adapter model | No | **Yes** | No | No | No |
| Adapter: CrewAI | **Yes** | **Yes** | Adapter model | No | **Yes** | No | No | No |
| Adapter: OpenAI Agents | **Yes** | No | Adapter model | **Yes** | No | No | No | No |
| Adapter: Pydantic AI | **Yes** | No | No | No | **Yes** | No | No | No |
| Adapter: Google ADK | No | **Yes** | No | No | No | No | No | No |
| Adapter: AutoGen/AG2 | No | No | No | No | **Yes** | No | No | No |
| Adapter: MS Agent Framework | No | **Yes** | Yes | No | No | No | No | No |
| SDK: TypeScript/JS | No | **Yes** (npm) | No | **Yes** | No | No | No | No |
| SDK: .NET/C# | No | **Yes** (NuGet) | No | No | No | No | No | No |
| SDK: Go | No | No | No | No | No | No | No | No |
| MCP scanning | No | **Yes** | No | No | Yes | **Yes** | No | No |
| A2A protocol testing | No | No | No | No | No | No | No | No |

### 5.4 Compliance & Governance

| Feature | AASTF | MS AGT | Onyx | F5 | Pillar | Noma | HiddenLayer | Holistic AI |
|---|---|---|---|---|---|---|---|---|
| EU AI Act mapping | No | No | No | Partial (logs) | No | No | No | **Yes** |
| NIST AI RMF mapping | No | No | Templates | No | No | No | No | **Yes** |
| ISO 42001 mapping | No | No | No | No | No | No | No | No |
| GDPR/CCPA audit logs | No | No | Yes | **Yes** | **Yes** | **Yes** | Yes | **Yes** |
| MITRE ATLAS mapping | No | No | Templates | No | No | No | No | Partial |
| OWASP compliance docs | No | **Yes** | Templates | No | No | No | No | No |
| Agent identity governance | No | **Yes** (DID) | **Yes** | No | **Yes** | **Yes** | No | No |
| Policy templates | No | **Yes** | **Yes** | Yes | Yes | Yes | Yes | No |

### 5.5 Runtime & Operations

| Feature | AASTF | MS AGT | Cisco DC | HiddenLayer | Noma | Onyx | Lakera/CP |
|---|---|---|---|---|---|---|---|
| Agent discovery/inventory | No | No | AI BoM | **Yes** | **Yes** | **Yes** | **Yes** |
| Session replay/audit trail | No | Yes (Agent Mesh) | Splunk | **Yes** | **Yes** | **Yes** | Yes |
| Drift detection | No | Yes | **Yes** | **Yes** | Yes | Yes | No |
| Policy enforcement latency | N/A | **<0.1ms** | **2s** | Real-time | Real-time | Real-time | **<50ms** |
| Human-in-the-loop approval | No | Yes | No | No | No | **Yes** | No |
| SIEM integration | No | No | **Splunk** | Enterprise | AWS Hub | Enterprise | No |

---

## 6. PRICING LANDSCAPE

| Tool | Model | Free Tier | Paid Tier |
|---|---|---|---|
| **AASTF** | 100% free OSS | Yes (unlimited) | N/A |
| **MS AGT** | 100% free OSS | Yes (unlimited) | N/A |
| **RAMPART** | 100% free OSS | Yes (unlimited) | N/A |
| **Promptfoo** | OSS + Enterprise | Yes (unlimited OSS) | Custom enterprise |
| **Garak** | 100% free OSS | Yes (unlimited) | N/A |
| **DeepTeam** | OSS + SaaS | Yes (unlimited OSS) | Confident AI SaaS (custom) |
| **PyRIT** | 100% free OSS | Yes (unlimited) | N/A |
| **Cisco DefenseClaw** | OSS + Enterprise | Yes (unlimited OSS) | Cisco AI Defense (custom) |
| **Augustus** | 100% free OSS | Yes (unlimited) | N/A |
| **FuzzyAI** | 100% free OSS | Yes (unlimited) | N/A |
| **HiddenLayer** | Enterprise only | No | Custom (est. $100K+/yr) |
| **Pillar Security** | Enterprise only | No | Custom |
| **Noma Security** | Enterprise only | No | Custom |
| **Onyx Security** | Enterprise only | No | Custom |
| **Mindgard** | Enterprise only | No | Custom |
| **Lasso Security** | Enterprise only | No | Custom |
| **Repello AI** | OSS (Agent-Wiz) + Enterprise | Agent-Wiz free | ARTEMIS platform (custom) |
| **Lakera/Check Point** | Freemium + Enterprise | 10K req/mo | Custom |
| **F5 AI Guardrails** | Enterprise only | No | Custom |
| **Prisma AIRS 3.0** | Enterprise only | No | Custom |

---

## 7. FUNDING & ACQUISITION SUMMARY (Updated)

| Company | Total Funding | Acquisition | Acquirer | Price | Team Size | Status |
|---|---|---|---|---|---|---|
| Promptfoo | $23.6M | March 2026 | OpenAI | ~$86M | 8-11 | Pending close |
| Invariant Labs | $0 | June 2025 | Snyk | Undisclosed | ~10 | Snyk Labs |
| Lakera | $30-34M | Sept 2025 | Check Point | ~$300M | 50-91 | AI Defense Plane |
| Robust Intelligence | $44M | Aug 2024 | Cisco | ~$400M | ~70 | Cisco AI Defense |
| Protect AI | $129M | July 2025 | Palo Alto | ~$500M | ~110 | Prisma AIRS 3.0 |
| CalypsoAI | $43.2M | Q4 2025 | F5 | $180M | ~50 | F5 AI Guardrails |
| **Onyx Security** | **$40M** | Independent | -- | -- | **~70** | **Launched March 2026** |
| HiddenLayer | $56M | Independent | -- | -- | ~169 | Likely Series B |
| Pillar Security | $9M | Independent | -- | -- | ~31 | Growing |
| Confident AI | $2.7M | Independent | -- | -- | ~7 | YC-backed |
| **Mindgard** | Undisclosed | Independent | -- | -- | ~50 | SOC 2 Type II |
| **Noma Security** | Undisclosed | Independent | -- | -- | ~40 | Rising in Cyber 2026 |
| **Lasso Security** | Undisclosed | Independent | -- | -- | ~30 | AWS/Azure marketplaces |
| **Repello AI** | Undisclosed | Independent | -- | -- | ~15 | Growing |
| Garak | N/A | NVIDIA internal | -- | -- | NVIDIA team | Active |
| PyRIT | N/A | Microsoft internal | -- | -- | MS team | Active (v2.0) |
| **MS AGT** | N/A | Microsoft internal | -- | -- | MS team | **Active (April 2026)** |
| **RAMPART** | N/A | Microsoft internal | -- | -- | MS team | **Active (May 2026)** |
| **AASTF** | **$0** | Independent | -- | -- | **1** | OSS, v0.4.1 |

---

## 8. TABLE STAKES FEATURES (Must-Have for Credibility in 2026)

Based on what ALL serious competitors now offer, these are non-negotiable:

| Feature | Who Has It | AASTF Status |
|---|---|---|
| Prompt injection testing | Everyone | Yes |
| Jailbreak testing | Everyone | Yes |
| PII/data leakage detection | Everyone except pure scanners | Yes |
| Multi-turn attack support | 80% of tools | Yes |
| Python SDK/API | Everyone | Yes |
| Open source option | 60% of tools | Yes |
| CLI interface | 80% of tools | Yes |
| JSON/structured output | Everyone | Yes |
| OWASP LLM Top 10 alignment | 90% of tools | Yes |
| **CI/CD integration** | **70% of tools** | **NO -- GAP** |
| **MCP server scanning** | **50%+ of tools** | **NO -- GAP** |
| **Runtime guardrails** | **60%+ of tools** | **NO -- GAP** |
| **Agent discovery/inventory** | **50%+ of enterprise tools** | **NO -- GAP** |
| **Framework adapters** | **30%+ of tools (growing fast)** | **Yes (but no longer unique)** |

---

## 9. PREMIUM DIFFERENTIATORS (Paid Tier Features)

Features that distinguish enterprise paid tiers from free/OSS:

| Feature | Who Charges For It | Market Demand |
|---|---|---|
| Agent discovery across cloud/SaaS | Onyx, Noma, Prisma AIRS, Wiz | Very high |
| Session replay and forensics | HiddenLayer, Onyx, Noma | High |
| SIEM integration (Splunk, Sentinel) | Cisco DC, HiddenLayer, Noma | High |
| Compliance report generation | F5, Holistic AI, Onyx | High (EU AI Act deadline) |
| Policy template library | MS AGT (free), Onyx, Noma | Medium-high |
| Human-in-the-loop approval gates | Onyx | Medium |
| ROI/adoption dashboards | Onyx | Medium |
| Attack pattern updates (continuous) | Repello (15M+/month), F5 (10K/month) | Medium |
| Red team-as-a-service | Mindgard, Repello | Medium |
| Multi-cloud agent scanning | Wiz, Prisma AIRS | High |

---

## 10. GAPS NO COMPETITOR FILLS (Updated)

### 10.1 Still Uncontested Gaps

| Gap | Detail |
|---|---|
| **A2A protocol security testing** | Zero tools test Google A2A protocol security. Mindgard can *discover* A2A servers but cannot test them. |
| **EU AI Act automated evidence generation** | Holistic AI and Vanta do compliance tracking but no agent security tool maps *security test findings* to EU AI Act Articles automatically. |
| **ISO 42001 audit artifacts** | Zero tools produce ISO/IEC 42001-aligned audit evidence. |
| **Cross-framework migration testing** | No tool tests if security properties hold when agents move between frameworks. |
| **NIST AI RMF formal function mapping** | No tool maps to GOVERN/MAP/MEASURE/MANAGE functions with test evidence. |

### 10.2 Gaps That Were Filled Since Last Update

| Former Gap | Who Filled It | When |
|---|---|---|
| ~~Only AASTF has 10/10 OWASP ASI~~ | **Microsoft AGT** (10/10 with runtime enforcement) | April 2026 |
| ~~Only AASTF has native framework adapters~~ | **MS AGT** (20+ adapters), **Repello Agent-Wiz** (LangGraph, CrewAI, AutoGen, Pydantic AI) | 2026 |
| ~~No CI-native agent security testing~~ | **Microsoft RAMPART** (pytest-native, CI-gatable) | May 2026 |
| ~~No MCP drift detection~~ | **Cisco DefenseClaw** (skill state tracking), **Snyk Agent Scan** (tool pinning/hash tracking) | 2026 |
| ~~No agent identity governance~~ | **MS AGT** (DID-based), **Onyx** (Guardian Agent), **Prisma AIRS** (CyberArk integration) | 2026 |

---

## 11. AASTF COMPETITIVE POSITIONING (Revised)

### 11.1 What AASTF Still Uniquely Offers

1. **Combined ASI Top 10 testing (10/10) + SARIF output** -- MS AGT covers ASI 10/10 but is runtime governance (not testing); AASTF is the only *testing* tool with 10/10 coverage AND SARIF.
2. **MIT-licensed, zero-dependency testing** -- No cloud account, no API keys for scanning, no vendor lock-in.
3. **Smallest attack surface** -- Single-purpose testing tool vs. bloated platforms.

### 11.2 What AASTF Has LOST as Differentiators

| Former Differentiator | Status | Threat |
|---|---|---|
| Only tool with 10/10 OWASP ASI | **LOST** -- MS AGT claims 10/10 with enforcement | Critical |
| Only tool with native framework adapters | **LOST** -- MS AGT (20+), Repello Agent-Wiz (5+) | Critical |
| Open-source agent security testing | **DILUTED** -- MS AGT, RAMPART, DefenseClaw, Augustus, FuzzyAI all OSS | High |

### 11.3 Highest-Priority Features to Add (Revised & Re-Ranked)

| Priority | Feature | Rationale | Competition |
|---|---|---|---|
| **P0** | **CI/CD integration (GitHub Action + pytest)** | RAMPART now owns the "pytest + CI gate" story; Promptfoo owns GitHub Action. AASTF has zero CI/CD story. This is now table stakes. | RAMPART, Promptfoo |
| **P0** | **MCP server scanning** | 50%+ of tools now have this. It's table stakes, not a differentiator. Ship it to stop losing credibility. | Cisco DC, Snyk, Pillar, MS AGT |
| **P1** | **Runtime guardrails (lightweight)** | 60%+ of tools offer runtime protection. Even a thin guardrails layer would prevent "testing-only" dismissal. | DeepTeam, Invariant, Lakera, NeMo |
| **P1** | **A2A protocol testing** | Still zero competition. First-mover advantage remains. Google A2A has 150+ member orgs. | Nobody |
| **P1** | **TypeScript/JS SDK** | MS AGT has npm package; Promptfoo is TS-native. JS ecosystem is huge for agent developers. | MS AGT, Promptfoo |
| **P2** | **EU AI Act compliance report generation** | Aug 2026 deadline. Map AASTF test findings to specific EU AI Act articles. No security testing tool does this. | Holistic AI (governance only) |
| **P2** | **Multi-agent adversarial simulation** | Still underserved. Noma can visualize cascading risk but can't simulate it. | Nobody (adequately) |
| **P2** | **Statistical trial support** | RAMPART supports "safe in X% of runs". Critical for non-deterministic LLM testing. | RAMPART |
| **P3** | **Agent discovery** | Enterprise expectation but hard for a testing tool. Consider partnership. | Onyx, Noma, Wiz, Prisma AIRS |
| **P3** | **Google ADK adapter** | MS AGT has it; no one else does. Growing framework. | MS AGT |
| **P3** | **AutoGen/AG2 adapter** | Repello Agent-Wiz has it. Popular framework. | Repello Agent-Wiz |

### 11.4 Strategic Threats to Monitor

| Threat | Severity | Timeline |
|---|---|---|
| **Microsoft AGT ecosystem** (AGT + RAMPART + PyRIT) forming a complete stack | **Critical** | Now -- already shipped |
| **Promptfoo post-OpenAI** becoming the default testing tool for OpenAI customers | High | 2026 H2 |
| **Cisco DefenseClaw + NVIDIA OpenShell** partnership creating default agent security | High | 2026 H2 |
| **Onyx Security** raising Series A and expanding from governance to testing | Medium | 2027 |
| **Repello Agent-Wiz** expanding framework support and open-sourcing ARTEMIS | Medium | 2026-2027 |

---

## 12. NEW ENTRANTS WATCHLIST

| Company | What They Do | Funding | Why Watch |
|---|---|---|---|
| **Onyx Security** | AI control plane for agents | $40M seed | 70 people, Fortune 500 customers already |
| **Repello AI** | Red teaming + Agent-Wiz OSS | Undisclosed | Framework adapters matching AASTF |
| **Augustus (Praetorian)** | Go-based LLM vuln scanner | Praetorian-backed | 210+ attacks, single binary |
| **Xbow** | AI penetration testing | Sequoia-backed (~$1B valuation) | Continuous AI-driven pentesting |
| **Hex Security** | AI agents for continuous pentesting | Undisclosed | 24/7 automated vulnerability finding |
| **RunSybil** | AI pentesting | OpenAI/Meta alumni | Strong AI talent |
| **Cogent Security** | Agent-based network vuln scanning | $42M Series A | Bain Capital, Greylock |

---

*Last updated: May 21, 2026*
*Data sources: GitHub, Crunchbase, vendor websites, OWASP, press releases, Microsoft Security Blog,
Cisco Newsroom, Palo Alto Newsroom, Check Point Blog, HiddenLayer PR, Noma Security PR,
Pillar Security website, Repello AI GitHub, AppSec Santa, The Hacker News, VentureBeat,
SiliconANGLE, Help Net Security*
