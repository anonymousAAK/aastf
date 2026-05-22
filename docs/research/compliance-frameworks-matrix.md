# Comprehensive Compliance Frameworks Matrix for AASTF (May 2026)

This document catalogs every compliance framework, standard, and regulation relevant to an AI agent security testing tool in 2026. It provides actionable guidance on what AASTF must implement to support each framework.

---

## Table of Contents

1. [AI-Specific Security Standards (OWASP Family)](#1-ai-specific-security-standards-owasp-family)
2. [NIST AI Standards Ecosystem](#2-nist-ai-standards-ecosystem)
3. [ISO AI Standards](#3-iso-ai-standards)
4. [Adversarial AI Frameworks](#4-adversarial-ai-frameworks)
5. [EU Regulations](#5-eu-regulations)
6. [US Federal Regulations & Executive Orders](#6-us-federal-regulations--executive-orders)
7. [US State AI Laws](#7-us-state-ai-laws)
8. [International AI Regulations](#8-international-ai-regulations)
9. [General Security Standards (AI-Applicable)](#9-general-security-standards-ai-applicable)
10. [Industry-Specific Frameworks](#10-industry-specific-frameworks)
11. [Emerging & Voluntary Frameworks](#11-emerging--voluntary-frameworks)
12. [Compliance Evidence & Artifact Requirements](#12-compliance-evidence--artifact-requirements)
13. [Priority Implementation Roadmap](#13-priority-implementation-roadmap)

---

## 1. AI-Specific Security Standards (OWASP Family)

### 1.1 OWASP Top 10 for Agentic Applications (ASI Top 10) 2025

| Field | Detail |
|---|---|
| **Full Name** | OWASP Top 10 for Agentic Applications 2025/2026 |
| **Status** | Final (released December 2025) |
| **Relevance** | CRITICAL -- AASTF's primary framework; 10/10 coverage is our core differentiator |
| **Categories** | ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity/Privilege Abuse, ASI04 Supply Chain, ASI05 Code Execution, ASI06 Context/Memory Manipulation, ASI07 Inter-Agent Comms, ASI08 Cascading Failures, ASI09 Human Trust Exploitation, ASI10 Rogue Agents |
| **AASTF Status** | 10/10 coverage with dedicated evaluators per category |
| **What AASTF Needs** | Maintain; add compliance report output that explicitly maps each finding to ASI category |
| **Competitor Coverage** | DeepTeam: labels 10/10; Promptfoo: partial via plugins; all others: partial or none |
| **Priority** | P0 -- Already implemented, maintain leadership |

### 1.2 OWASP Top 10 for LLM Applications 2025 (v2.0)

| Field | Detail |
|---|---|
| **Full Name** | OWASP Top 10 for Large Language Model Applications 2025 |
| **Status** | Final (released late 2024) |
| **Relevance** | HIGH -- Foundational LLM security list; many enterprise RFPs reference it |
| **Categories** | LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data/Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector/Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption |
| **AASTF Status** | Substantial overlap with ASI coverage but no explicit LLM Top 10 mapping in reports |
| **What AASTF Needs** | Add cross-reference mapping from ASI scenarios to LLM Top 10 categories in report output; create LLM Top 10 compliance profile |
| **Competitor Coverage** | Promptfoo: full; DeepTeam: full; Garak: partial; PyRIT: partial |
| **Priority** | P1 -- Low effort (mapping only), high value for enterprise sales |

### 1.3 OWASP MCP Top 10 2025

| Field | Detail |
|---|---|
| **Full Name** | OWASP Top 10 for Model Context Protocol 2025 |
| **Status** | Beta (Phase 3 -- pilot testing; categories stable) |
| **Relevance** | HIGH -- MCP adoption is exploding; 9,400+ MCP servers |
| **Categories** | MCP01 Token Mismanagement & Secret Exposure, MCP02 Privilege Escalation via Scope Creep, MCP03 Tool Poisoning, MCP04 Supply Chain & Dependency Tampering, MCP05 Command Injection & Execution, MCP06 Intent Flow Subversion, MCP07 Insufficient Auth & Authz, MCP08 Lack of Audit & Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection & Over-Sharing |
| **AASTF Status** | Not covered |
| **What AASTF Needs** | Build MCP scanner module; create evaluators for each MCP01-MCP10 category; would make AASTF the first tool covering both ASI Top 10 AND MCP Top 10 |
| **Competitor Coverage** | Cisco MCP Scanner: partial; Invariant/Snyk mcp-scan: partial; Pillar: partial |
| **Priority** | P1 -- First-mover opportunity for combined ASI+MCP coverage |

---

## 2. NIST AI Standards Ecosystem

### 2.1 NIST AI Risk Management Framework (AI RMF 1.0)

| Field | Detail |
|---|---|
| **Full Name** | NIST AI 100-1: AI Risk Management Framework 1.0 |
| **Status** | Final (January 2023) |
| **Relevance** | CRITICAL -- De facto US standard; referenced in federal procurement, enterprise RFPs |
| **Structure** | Four core functions: GOVERN, MAP, MEASURE, MANAGE |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map each AASTF evaluator and scenario to AI RMF functions and subcategories. AASTF testing directly supports MEASURE and MANAGE functions. Generate AI RMF compliance artifacts showing which subcategories are addressed |
| **Competitor Coverage** | DeepTeam: labels only (no function mapping); Promptfoo: claims mapping (2026); all others: none |
| **Priority** | P1 -- High enterprise demand; required for US government sales |

### 2.2 NIST AI 600-1: Generative AI Profile

| Field | Detail |
|---|---|
| **Full Name** | NIST AI 600-1: AI RMF Generative AI Profile |
| **Status** | Final (July 2024) |
| **Relevance** | HIGH -- Extends AI RMF specifically for GenAI; 12 risk categories |
| **Key Risks** | CBRN info access, confabulation/hallucination, data privacy, environmental impact, human-AI interaction, info integrity, info security, IP, obscene content, toxicity/bias/homogeneity, value chain risks |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF scenarios to the 12 GenAI risk categories; generate profile-aligned reports |
| **Competitor Coverage** | No tool provides formal mapping |
| **Priority** | P2 -- Important for GenAI-focused customers |

### 2.3 NIST AI 100-2 E2025: Adversarial ML Taxonomy

| Field | Detail |
|---|---|
| **Full Name** | Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations |
| **Status** | Final (March 2025, updated from 2023 version) |
| **Relevance** | HIGH -- Authoritative taxonomy of AI attack types |
| **Structure** | ML method types, lifecycle stages of attack, attacker goals/objectives/capabilities/knowledge |
| **Key Threats** | Data poisoning, model inversion, prompt injection, model extraction, evasion attacks |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Tag each AASTF attack scenario with NIST 100-2 taxonomy references; helps customers show testing covers NIST-recognized threat categories |
| **Competitor Coverage** | No tool provides formal mapping |
| **Priority** | P2 -- Differentiator for research-oriented and government customers |

### 2.4 NIST SP 800-218A: Secure Software Development for AI

| Field | Detail |
|---|---|
| **Full Name** | Secure Software Development Practices for Generative AI and Dual-Use Foundation Models |
| **Status** | Final (2024) |
| **Relevance** | MEDIUM -- Extends SSDF to AI; relevant for customers building AI systems |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF testing to relevant SSDF practices (PS.1, PW.1, PW.6, RV.1); show how AASTF fits into secure AI SDLC |
| **Competitor Coverage** | None |
| **Priority** | P3 -- Niche but valuable for software-producer customers |

### 2.5 NIST AI 100-5: Agentic AI Systems (Forthcoming)

| Field | Detail |
|---|---|
| **Full Name** | NIST AI 100-5 (expected title: Agentic AI Systems) |
| **Status** | In development (announced February 2026 via CAISI initiative) |
| **Relevance** | CRITICAL (when published) -- Will be the authoritative US standard for agentic AI |
| **AASTF Status** | N/A (not yet published) |
| **What AASTF Needs** | Monitor closely; participate in public comment; prepare to be day-one compliant. NIST plans AI Agent Test Suite release in Q4 2026 |
| **Competitor Coverage** | None (not yet published) |
| **Priority** | P1 -- Watch and prepare; align early |

### 2.6 NIST COSAIS: AI Security Overlays for SP 800-53

| Field | Detail |
|---|---|
| **Full Name** | Controls Overlay for Securing AI Systems (first draft expected early 2026) |
| **Status** | In development |
| **Relevance** | HIGH -- Will map AI security controls to the 800-53 control catalog used by FedRAMP, FISMA |
| **AASTF Status** | N/A |
| **What AASTF Needs** | When released, map AASTF evaluators to the overlay controls; critical for government market |
| **Priority** | P2 -- Watch and prepare |

---

## 3. ISO AI Standards

### 3.1 ISO/IEC 42001:2023 -- AI Management System (AIMS)

| Field | Detail |
|---|---|
| **Full Name** | ISO/IEC 42001:2023 Information Technology -- Artificial Intelligence -- Management System |
| **Status** | Final (December 2023); certification available |
| **Relevance** | CRITICAL -- World's first AI management system standard; appearing in ~40% of EU enterprise AI vendor RFPs and ~25% in North America as of mid-2026 |
| **Structure** | Plan-Do-Check-Act; Annex A has 38 AI-specific controls across 9 objectives |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF testing outputs to Annex A control objectives (particularly A.6 Data for AI, A.7 AI System, A.8 AI System Lifecycle). Generate ISO 42001-aligned evidence packages showing security testing as part of AIMS implementation |
| **Competitor Coverage** | Zero tools produce ISO 42001-aligned audit artifacts |
| **Priority** | P1 -- Massive uncontested gap; high enterprise value |

### 3.2 ISO/IEC 42005:2025 -- AI Impact Assessment

| Field | Detail |
|---|---|
| **Full Name** | ISO/IEC 42005:2025 Information Technology -- AI System Impact Assessment |
| **Status** | Final (2025) |
| **Relevance** | MEDIUM -- Complements ISO 42001; guides AI impact assessments |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Include security impact findings in format compatible with 42005 impact assessment templates |
| **Competitor Coverage** | None |
| **Priority** | P3 -- Implement alongside ISO 42001 mapping |

### 3.3 ISO/IEC 27001:2022 -- Information Security Management

| Field | Detail |
|---|---|
| **Full Name** | ISO/IEC 27001:2022 Information Security Management Systems |
| **Status** | Final (enforced); widely adopted |
| **Relevance** | HIGH -- 93 Annex A controls; AI companies must map AI risks to existing controls |
| **Key AI-Relevant Controls** | 8.25 Secure Development (adapt to adversarial testing), 8.8 Technical Vulnerability Management, 8.16 Monitoring Activities, 5.7 Threat Intelligence |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF test results to relevant Annex A controls; particularly 8.25 (secure dev), 8.8 (vuln mgmt), 8.16 (monitoring) |
| **Competitor Coverage** | None provide AI-specific ISO 27001 mapping |
| **Priority** | P2 -- Most enterprises already have 27001; showing AASTF supports it removes adoption friction |

---

## 4. Adversarial AI Frameworks

### 4.1 MITRE ATLAS

| Field | Detail |
|---|---|
| **Full Name** | MITRE Adversarial Threat Landscape for AI Systems |
| **Status** | Final (monthly release cadence); v5.4.0 as of February 2026 |
| **Relevance** | CRITICAL -- 16 tactics, 84 techniques, 56 sub-techniques; the ATT&CK equivalent for AI |
| **Recent Updates** | January 2026 (v5.3.0): 3 new MCP case studies; February 2026 (v5.4.0): "Publish Poisoned AI Agent Tool" and "Escape to Host" techniques; Technique Maturity filter added |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Tag each AASTF scenario with ATLAS technique IDs (e.g., AML.T0043 Craft Adversarial Data, AML.T0051 LLM Prompt Injection). Include ATLAS technique references in SARIF output. SOC teams think in ATLAS/ATT&CK terms -- this is critical for enterprise adoption |
| **Competitor Coverage** | DeepTeam: labels; Promptfoo: partial; no tool provides technique-level mapping |
| **Priority** | P1 -- SOC teams require this; high differentiation value |

### 4.2 CSA AI Controls Matrix (AICM)

| Field | Detail |
|---|---|
| **Full Name** | Cloud Security Alliance AI Controls Matrix |
| **Status** | Final; maps to ISO 42001, ISO 27001, NIST AI RMF, BSI AIC4 |
| **Relevance** | HIGH -- Unified control framework; CSA STAR for AI Level 2 launched November 2025 combining ISO 42001 certification with CSA transparency |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF evaluators to AICM control domains; enables customers pursuing CSA STAR for AI certification to use AASTF as evidence |
| **Competitor Coverage** | None |
| **Priority** | P2 -- Growing adoption, especially for cloud-deployed AI |

---

## 5. EU Regulations

### 5.1 EU AI Act (Regulation 2024/1689)

| Field | Detail |
|---|---|
| **Full Name** | Regulation (EU) 2024/1689 -- Artificial Intelligence Act |
| **Status** | ENFORCED (phased) |
| **Enforcement Timeline** | Feb 2, 2025: Prohibited practices + definitions + AI literacy. Aug 2, 2025: GPAI model rules + governance. **Aug 2, 2026: Transparency obligations (Article 50) + innovation measures.** **Dec 2, 2027: High-risk AI (biometrics, critical infra, education, employment, migration) -- DELAYED from Aug 2026 by Digital Omnibus VII (agreed May 7, 2026).** Aug 2, 2028: High-risk AI in regulated products (lifts, toys, medical devices). |
| **Relevance** | CRITICAL -- First comprehensive AI law globally; extraterritorial scope |
| **Key Requirements for High-Risk AI** | Conformity assessment, risk management system (Art 9), data governance (Art 10), technical documentation (Art 11), record-keeping (Art 12), transparency (Art 13), human oversight (Art 14), accuracy/robustness/cybersecurity (Art 15) |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | (1) Map test results to Art 9 risk management obligations, (2) Generate Art 15 accuracy/robustness/cybersecurity evidence, (3) Produce Art 11 technical documentation artifacts, (4) EU AI Act compliance report template showing which articles are addressed by testing. This is the single biggest compliance automation opportunity -- zero competitors do this |
| **Competitor Coverage** | Pillar: GDPR/CCPA only; no tool maps to EU AI Act articles |
| **Priority** | P0 -- Urgent; Art 50 transparency obligations enforce Aug 2026; high-risk Dec 2027 creates massive demand starting now |

### 5.2 GDPR -- AI Provisions (Article 22)

| Field | Detail |
|---|---|
| **Full Name** | General Data Protection Regulation -- Article 22 (Automated Decision-Making) |
| **Status** | ENFORCED (since May 2018) |
| **Relevance** | HIGH -- Automated decision-making rights; cumulative with EU AI Act obligations; highest penalty tier (up to 4% global turnover or EUR 20M) |
| **Key Requirements** | Right not to be subject to solely automated decisions with legal effects; right to human intervention; right to contest; DPIA required |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Test for scenarios where AI agents make consequential decisions without human oversight; report whether agent architecture supports Art 22 compliance (human-in-the-loop, contestability) |
| **Competitor Coverage** | Pillar: GDPR audit logs |
| **Priority** | P2 -- Implement alongside EU AI Act mapping |

### 5.3 DORA -- Digital Operational Resilience Act

| Field | Detail |
|---|---|
| **Full Name** | Regulation (EU) 2022/2554 -- Digital Operational Resilience Act |
| **Status** | ENFORCED (January 17, 2025) |
| **Relevance** | HIGH for financial sector -- AI systems must be embedded into DORA ICT risk management; BaFin guidance (January 2026) confirms AI/LLM systems are subject to DORA testing requirements |
| **Key Requirement** | Art 9(10) AI Act explicitly permits integration of AI risk management into DORA ICT procedures; AI agents in financial services must undergo threat-led penetration testing (TLPT) |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Generate DORA-compliant ICT risk assessment evidence for AI agent systems; map to TLPT requirements; tag financial-services-specific scenarios |
| **Competitor Coverage** | None |
| **Priority** | P2 -- High value for FinTech ICP |

### 5.4 NIS2 Directive

| Field | Detail |
|---|---|
| **Full Name** | Directive (EU) 2022/2555 -- Network and Information Systems Directive 2 |
| **Status** | ENFORCED (transposition closing 2025-2026; active enforcement beginning 2026) |
| **Relevance** | MEDIUM-HIGH -- AI agents processing data qualify as information systems; must be included in risk assessments; Article 21 mandates 10 cybersecurity measures |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF testing to NIS2 Article 21 risk management measures (supply chain security, vulnerability handling, incident management) |
| **Competitor Coverage** | None |
| **Priority** | P3 -- Implement alongside EU AI Act work |

---

## 6. US Federal Regulations & Executive Orders

### 6.1 Executive Order on AI (Current Administration)

| Field | Detail |
|---|---|
| **Full Name** | EO "Ensuring a National Policy Framework for Artificial Intelligence" (December 11, 2025) |
| **Status** | ENFORCED -- Replaced Biden-era EO 14110 (revoked January 20, 2025) |
| **Relevance** | MEDIUM -- Deregulatory; proposes preempting inconsistent state AI laws; focuses on removing barriers rather than mandating safeguards |
| **AASTF Status** | N/A |
| **What AASTF Needs** | Monitor for implementing guidance; OMB procurement updates required agencies to update by March 2026 |
| **Priority** | P3 -- Watch only |

### 6.2 OMB AI Procurement Guidance (M-24-10, M-24-18 revisions)

| Field | Detail |
|---|---|
| **Full Name** | OMB Memoranda on Federal Government AI Acquisition and Governance |
| **Status** | Being revised per current EO; March 2026 deadline for agency procurement policy updates |
| **Relevance** | HIGH for government sales -- Federal agencies buying AI tools will reference updated OMB guidance |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Ensure AASTF can generate artifacts that satisfy federal AI procurement evaluation criteria |
| **Priority** | P2 -- Important for government market |

---

## 7. US State AI Laws

### 7.1 Colorado AI Act (SB 24-205)

| Field | Detail |
|---|---|
| **Full Name** | Colorado Consumer Protections for Artificial Intelligence |
| **Status** | Enacted; effective June 30, 2026 BUT enforcement frozen pending AG rulemaking; replacement framework may narrow scope and push to January 2027 |
| **Relevance** | HIGH -- First comprehensive US state AI law; model for other states |
| **Key Requirements** | Reasonable care to prevent algorithmic discrimination; impact assessments; annual reviews; consumer disclosures; 60-day cure period |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Test for algorithmic discrimination scenarios in AI agents; generate impact assessment evidence; support deployer annual review requirements |
| **Priority** | P2 -- Watch legislative changes; prepare mapping |

### 7.2 California AI Laws (Multiple)

| Field | Detail |
|---|---|
| **Full Name** | SB 942 (AI Transparency Act), AB 2013 (GAI Training Data Transparency) |
| **Status** | SB 942 effective January 1, 2026; AB 2013 effective January 1, 2026; SB 942 full enforcement August 2, 2026 |
| **Relevance** | HIGH -- California sets national trends; transparency and watermarking requirements |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Test whether AI agents properly disclose AI-generated content; verify transparency requirements |
| **Priority** | P3 |

### 7.3 Illinois AI Amendment (HB 3773)

| Field | Detail |
|---|---|
| **Full Name** | Illinois Amendment to Human Rights Act |
| **Status** | Enacted (August 2024); effective January 1, 2026 |
| **Relevance** | MEDIUM -- Employment AI discrimination; civil rights violation for non-compliant AI hiring tools |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Employment-focused bias testing scenarios |
| **Priority** | P3 |

### 7.4 Texas TRAIGA (HB 149)

| Field | Detail |
|---|---|
| **Full Name** | Texas Responsible AI Governance Act |
| **Status** | Enacted (June 2025) |
| **Relevance** | MEDIUM -- Prohibits restricted AI purposes; applies extraterritorially to Texas users |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Test for restricted-purpose violations (self-harm encouragement, discrimination, CSAM) |
| **Priority** | P3 |

### 7.5 Connecticut SB 5 (AIRT Act)

| Field | Detail |
|---|---|
| **Full Name** | Connecticut AI Risk & Transparency Act |
| **Status** | Added May 9, 2026 |
| **Relevance** | MEDIUM -- Unique definitions differing from CA and NY; emerging model |
| **Priority** | P3 -- Watch |

### 7.6 Utah SB 149

| Field | Detail |
|---|---|
| **Full Name** | Utah Artificial Intelligence Policy Act |
| **Status** | Enacted; effective May 1, 2024 |
| **Relevance** | LOW-MEDIUM -- Narrow scope: disclosure requirements in healthcare, legal, financial |
| **Priority** | P4 |

### 7.7 US State Law Summary

Over 70 AI-related laws passed in 27+ states. AASTF should build a generic "US State Compliance" profile covering the common threads: algorithmic discrimination testing, transparency/disclosure verification, impact assessment evidence generation.

---

## 8. International AI Regulations

### 8.1 South Korea AI Basic Act

| Field | Detail |
|---|---|
| **Full Name** | South Korea Basic Act on AI |
| **Status** | ENFORCED (January 22, 2026) -- Second comprehensive AI law globally after EU |
| **Relevance** | HIGH -- Extraterritorial; transparency, risk assessment, human oversight, documentation requirements |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map to transparency and risk assessment requirements; support Korean market customers |
| **Priority** | P2 -- Enforced law with teeth |

### 8.2 China AI Governance Framework

| Field | Detail |
|---|---|
| **Full Name** | National AI Governance Code (2026 consolidation); Generative AI Measures (Aug 2023); Algorithm Registration Requirements |
| **Status** | ENFORCED (multiple regulations); 2026 consolidation introducing mandatory algorithm registration for high-impact systems |
| **Relevance** | MEDIUM -- Relevant for customers deploying AI in China; "Trusted Algorithm Certification" creates testing demand |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Monitor; low priority unless targeting Chinese market |
| **Priority** | P4 |

### 8.3 UK AI Framework

| Field | Detail |
|---|---|
| **Full Name** | UK Pro-Innovation AI Regulation Framework + AI Safety/Security Institute |
| **Status** | Non-statutory; five principles (safety, transparency, fairness, accountability, contestability); no comprehensive AI Bill yet (possible introduction 2026) |
| **Relevance** | MEDIUM -- Sector regulators applying principles; DSIT consulting on statutory AI Safety Institute |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map to five principles; lightweight -- mostly covered by existing testing |
| **Priority** | P3 |

### 8.4 Canada (Post-AIDA)

| Field | Detail |
|---|---|
| **Full Name** | AIDA died January 2025 (Bill C-27 prorogation); no federal AI legislation |
| **Status** | No binding federal AI law; provinces advancing (Ontario Bill 194); privacy-focused approach |
| **Relevance** | LOW -- No binding obligations currently |
| **AASTF Status** | N/A |
| **What AASTF Needs** | Monitor provincial developments |
| **Priority** | P4 |

### 8.5 Japan AI Promotion Act

| Field | Detail |
|---|---|
| **Full Name** | AI Promotion Act (approved May 2025) |
| **Status** | Enacted; principles-based, no penalties |
| **Relevance** | LOW-MEDIUM -- Innovation-first; light-touch |
| **Priority** | P4 |

### 8.6 Brazil AI Bill (No. 2338)

| Field | Detail |
|---|---|
| **Full Name** | Bill No. 2338 -- Comprehensive AI Framework |
| **Status** | Passed Senate December 2024; awaiting final approval |
| **Relevance** | MEDIUM -- Closely mirrors EU AI Act risk-based approach; strict liability |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | If enacted, leverage EU AI Act mapping (similar structure) |
| **Priority** | P3 -- Watch |

### 8.7 Singapore Agentic AI Governance Framework

| Field | Detail |
|---|---|
| **Full Name** | IMDA Model AI Governance Framework for Agentic AI (2026) + AI Verify Foundation |
| **Status** | Published 2026; voluntary but influential in ASEAN |
| **Relevance** | HIGH for agentic AI -- First-of-its-kind framework specifically for agentic AI; covers risk bounding, human accountability, agent power limits |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF testing to the four dimensions: risk bounding, human checkpoints, agent power limits, accountability. AI Verify toolkit integration possible |
| **Competitor Coverage** | None |
| **Priority** | P2 -- Directly addresses agentic AI; aligns perfectly with AASTF's focus |

---

## 9. General Security Standards (AI-Applicable)

### 9.1 SOC 2 (AICPA Trust Services Criteria)

| Field | Detail |
|---|---|
| **Full Name** | System and Organization Controls 2 |
| **Status** | ENFORCED; de facto standard for SaaS/cloud; 2026 auditors pressing on AI-specific evidence |
| **Relevance** | CRITICAL for SaaS -- AI companies need SOC 2; auditors now expect model versioning, inference logging, drift detection, supply chain evidence mapped to CC6/CC7/CC8 |
| **AI-Specific 2026 Expectations** | Zero-trust as default, MFA on every privileged surface, immutable audit logs, continuous monitoring, explicit AI controls |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF test outputs to TSC controls (CC6 Logical & Physical Access, CC7 System Operations, CC8 Change Management); generate SOC 2-ready evidence artifacts |
| **Competitor Coverage** | None provide AI-specific SOC 2 mapping |
| **Priority** | P1 -- Required for enterprise customers |

### 9.2 PCI DSS 4.0.1

| Field | Detail |
|---|---|
| **Full Name** | Payment Card Industry Data Security Standard v4.0.1 |
| **Status** | ENFORCED (March 31, 2025 -- all requirements mandatory, no exemptions for AI) |
| **Relevance** | HIGH for FinTech -- AI processing cardholder data must comply; Req 3 (encryption), Req 6 (secure dev), Req 7 (access control for training data), Req 10 (logging AI queries) |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Tag findings related to data exposure with PCI relevance; test AI agent access to cardholder data environments |
| **Priority** | P2 -- FinTech ICP |

### 9.3 HIPAA Security Rule (2026 Update)

| Field | Detail |
|---|---|
| **Full Name** | Health Insurance Portability and Accountability Act -- Security Rule (proposed 2026 overhaul) |
| **Status** | Proposed rule expected finalized May 2026; most substantial update since original rule; effective July/August 2026 with 180-day compliance window |
| **Relevance** | HIGH for healthcare -- ePHI in AI training data, prediction models, and algorithm outputs is protected; mandatory encryption, MFA, 72-hour incident reporting, annual pen testing |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Test for ePHI exposure in AI agent workflows; generate HIPAA-aligned security assessment evidence |
| **Priority** | P2 -- HealthTech ICP |

---

## 10. Industry-Specific Frameworks

### 10.1 HITRUST AI Security Assessment

| Field | Detail |
|---|---|
| **Full Name** | HITRUST CSF AI Security Assessment (ai1 designation) |
| **Status** | Available; optional add-on to HITRUST e1/i1/r2 assessments |
| **Relevance** | HIGH for healthcare -- Up to 44 AI-specific security requirements; maps to HITRUST CSF + ISO 42001 |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AASTF evaluators to HITRUST AI security requirements; generate ai1-compatible evidence |
| **Competitor Coverage** | None |
| **Priority** | P2 -- HealthTech ICP; pairs with HIPAA mapping |

### 10.2 FedRAMP (+ AI Prioritization)

| Field | Detail |
|---|---|
| **Full Name** | Federal Risk and Authorization Management Program + FedRAMP 20x |
| **Status** | ENFORCED; FedRAMP 20x target Q3 2026; AI cloud services being prioritized for authorization |
| **Relevance** | HIGH for government -- AI tools must meet NIST 800-53 Rev 5 controls + AI RMF alignment; FedRAMP 20x compresses authorization from 18 months to weeks |
| **Requirements** | Model provenance, training data lineage, automated decision-making transparency |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Ensure AASTF outputs map to 800-53 controls relevant to AI; support customers pursuing FedRAMP authorization for AI tools |
| **Priority** | P2 -- Government market |

### 10.3 CMMC 2.0

| Field | Detail |
|---|---|
| **Full Name** | Cybersecurity Maturity Model Certification 2.0 |
| **Status** | ENFORCED (Phase 1 began November 2025; Phase 2 begins November 2026) |
| **Relevance** | MEDIUM -- Defense contractors using AI must comply; based on NIST 800-171/800-172; no AI-specific controls yet |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Map AI security testing to 800-171 controls where applicable; primarily through 800-53 mapping |
| **Priority** | P3 -- Defense vertical |

---

## 11. Emerging & Voluntary Frameworks

### 11.1 OECD AI Principles (2024 Update)

| Field | Detail |
|---|---|
| **Full Name** | OECD Recommendation on Artificial Intelligence (2019, updated May 2024) |
| **Status** | Adopted by 46 countries; non-binding but widely referenced in legislation |
| **Relevance** | MEDIUM -- Five principles (inclusive growth, human-centered values, transparency, robustness/security, accountability) + five policy recommendations |
| **AASTF Status** | No mapping |
| **What AASTF Needs** | Reference OECD principles in documentation; lightweight mapping in compliance reports |
| **Priority** | P3 |

### 11.2 IEEE P2863 -- AI Organizational Governance

| Field | Detail |
|---|---|
| **Full Name** | IEEE P2863: Recommended Practice for Organizational Governance of AI |
| **Status** | Updated January 2026; recommended practice (not mandatory) |
| **Relevance** | LOW-MEDIUM -- Governance criteria: safety, transparency, accountability, bias minimization |
| **Priority** | P4 |

### 11.3 IEEE 3119-2025 -- AI Procurement

| Field | Detail |
|---|---|
| **Full Name** | IEEE 3119: Standard for Procurement of AI and Automated Decision Systems |
| **Status** | Final (2025); used by government procurement teams |
| **Relevance** | MEDIUM -- Government entities use this to evaluate AI tools; having AASTF aligned helps customers pass procurement reviews |
| **Priority** | P3 |

### 11.4 Singapore AI Verify Toolkit

| Field | Detail |
|---|---|
| **Full Name** | AI Verify -- Open-source AI governance testing toolkit |
| **Status** | Active (90+ member organizations); Global Model Evaluation Toolkit for LLMs |
| **Relevance** | MEDIUM -- Integration opportunity; AI Assurance Framework (2026 planned) will unify testing criteria |
| **Priority** | P3 |

### 11.5 BSI AIC4 (Germany)

| Field | Detail |
|---|---|
| **Full Name** | BSI AI Cloud Services Compliance Criteria Catalogue |
| **Status** | Published; used by German federal agencies |
| **Relevance** | MEDIUM -- Maps to ISO 42001 and CSA AICM |
| **Priority** | P4 |

---

## 12. Compliance Evidence & Artifact Requirements

### What Auditors Expect from AI Security Testing in 2026

Based on research across SOC 2, ISO 42001, EU AI Act, and HIPAA audit expectations, here are the evidence artifacts AASTF must generate:

#### 12.1 Technical Artifacts

| Artifact | Description | Frameworks Requiring It |
|---|---|---|
| **Test Execution Report** | Timestamped record of all test scenarios executed, inputs, outputs, pass/fail | All frameworks |
| **Vulnerability Findings Report** | Categorized findings with severity, description, remediation | All frameworks |
| **SARIF Output** | Machine-readable standardized vulnerability format | SOC 2, CI/CD integration, ISO 27001 |
| **Model Version Tracking** | Which model version was tested, when, by whom | SOC 2, EU AI Act Art 11, ISO 42001 A.7 |
| **Attack Coverage Matrix** | Which attack types were tested, mapped to framework categories | MITRE ATLAS, NIST 100-2, OWASP |
| **Prompt/Response Audit Log** | Append-only, tamper-evident log of all test interactions | SOC 2, HIPAA, GDPR, EU AI Act Art 12 |

#### 12.2 Compliance Mapping Artifacts

| Artifact | Description | Frameworks Requiring It |
|---|---|---|
| **Framework Compliance Report** | Maps each finding to specific framework control/article/category | EU AI Act, NIST AI RMF, ISO 42001, SOC 2 |
| **Risk Assessment Evidence** | Shows risks identified, tested, and their severity | EU AI Act Art 9, NIST AI RMF MEASURE, ISO 42001, Colorado SB 205 |
| **Robustness/Security Evidence** | Demonstrates AI system testing for accuracy, robustness, cybersecurity | EU AI Act Art 15, NIST AI 600-1 |
| **Human Oversight Verification** | Tests whether human-in-the-loop mechanisms function correctly | EU AI Act Art 14, GDPR Art 22, Singapore Agentic Framework |
| **Bias/Discrimination Testing Report** | Algorithmic fairness assessment results | Colorado SB 205, Illinois HB 3773, EU AI Act |
| **Supply Chain Security Report** | Third-party component, MCP server, and dependency analysis | OWASP ASI04, MCP04, NIST SP 800-218A |

#### 12.3 Governance & Process Artifacts

| Artifact | Description | Frameworks Requiring It |
|---|---|---|
| **Test Schedule/Cadence Evidence** | Proof of regular, recurring testing | SOC 2, HIPAA (annual pen test), ISO 42001 |
| **Remediation Tracking** | Evidence that findings were addressed with timelines | All frameworks |
| **Trend Analysis** | Security posture changes over time | SOC 2 (continuous monitoring), ISO 27001 |
| **Executive Summary** | Non-technical compliance status for leadership | ISO 42001, SOC 2, EU AI Act |

### 12.4 Evidence Collection Features AASTF Needs

1. **Structured JSON/SARIF output** with framework tags on every finding (already have SARIF)
2. **Compliance report generator** accepting a profile parameter (e.g., `--compliance eu-ai-act`, `--compliance nist-ai-rmf`, `--compliance iso-42001`)
3. **Cross-reference engine** that maps each evaluator to multiple frameworks simultaneously
4. **Tamper-evident audit log** with timestamps, model versions, and hash chains
5. **Evidence package exporter** bundling all artifacts for a specific framework audit
6. **Trend tracking** over multiple test runs (partially implemented via `trend_tracker.py`)
7. **Executive dashboard/summary** with pass/fail per framework control

---

## 13. Priority Implementation Roadmap

### Tier 1: P0-P1 (Implement in v0.5-v0.6)

| Framework | Action | Effort | Impact |
|---|---|---|---|
| **OWASP ASI Top 10** | Maintain 10/10; add explicit mapping in reports | Low | Defend core differentiator |
| **EU AI Act** | Art 9/11/12/14/15 compliance report template | Medium | Massive uncontested gap; Aug 2026 deadline |
| **NIST AI RMF 1.0** | Map evaluators to GOVERN/MAP/MEASURE/MANAGE | Medium | Required for US enterprise/government |
| **ISO 42001** | Map to Annex A controls A.6/A.7/A.8 | Medium | 40% of EU RFPs ask for it |
| **MITRE ATLAS** | Tag scenarios with ATLAS technique IDs | Medium | SOC team adoption |
| **OWASP LLM Top 10** | Cross-reference mapping from ASI scenarios | Low | Enterprise checklist item |
| **SOC 2** | Map outputs to CC6/CC7/CC8 controls | Medium | Enterprise table stakes |
| **OWASP MCP Top 10** | Build MCP scanner module | High | First combined ASI+MCP tool |
| **Compliance Report Engine** | Build `--compliance <profile>` CLI option | High | Enables ALL compliance mappings |

### Tier 2: P2 (Implement in v0.7-v0.8)

| Framework | Action | Effort |
|---|---|---|
| **NIST AI 600-1** | Map to 12 GenAI risk categories | Low |
| **NIST AI 100-2** | Tag scenarios with taxonomy references | Low |
| **ISO 27001** | Map to Annex A AI-relevant controls | Low |
| **DORA** | Financial sector compliance profile | Medium |
| **HIPAA** | Healthcare compliance profile with ePHI scenarios | Medium |
| **PCI DSS 4.0** | FinTech compliance profile | Medium |
| **HITRUST AI** | Map to 44 AI security requirements | Medium |
| **FedRAMP** | Map to 800-53 AI-relevant controls | Medium |
| **South Korea AI Basic Act** | Compliance profile | Low |
| **Singapore Agentic AI Framework** | Map to four governance dimensions | Low |
| **CSA AICM** | Map to AI Controls Matrix domains | Medium |
| **Colorado SB 205** | Algorithmic discrimination testing profile | Medium |
| **GDPR Art 22** | Human oversight verification scenarios | Low |
| **OMB AI Procurement** | Federal procurement evidence artifacts | Low |

### Tier 3: P3 (Implement in v0.9-v1.0)

| Framework | Action |
|---|---|
| **NIST SP 800-218A** | SSDF mapping for AI dev lifecycle |
| **NIS2** | Article 21 risk management mapping |
| **ISO 42005** | Impact assessment template integration |
| **UK AI Framework** | Five principles mapping |
| **Brazil AI Bill** | Leverage EU AI Act mapping if enacted |
| **California AI Laws** | Transparency testing scenarios |
| **Illinois HB 3773** | Employment bias testing profile |
| **Texas TRAIGA** | Restricted purpose testing |
| **Connecticut SB 5** | Monitor and map |
| **OECD AI Principles** | Reference in documentation |
| **IEEE 3119** | Procurement alignment evidence |
| **Singapore AI Verify** | Toolkit integration |
| **CMMC 2.0** | Defense sector profile |

### Tier 4: P4 (Monitor/Defer)

| Framework | Action |
|---|---|
| **NIST AI 100-5** | Prepare for day-one compliance when published (Q4 2026) |
| **NIST COSAIS** | Prepare for 800-53 overlay when draft released |
| **Canada provincial AI laws** | Monitor |
| **Japan AI Promotion Act** | Low priority |
| **China AI Governance** | Only if targeting Chinese market |
| **IEEE P2863** | Reference only |
| **BSI AIC4** | Reference only |
| **Utah SB 149** | Narrow scope, low priority |

---

## Summary: Competitive Compliance Landscape

| Framework | AASTF | Promptfoo | DeepTeam | Garak | PyRIT | Pillar | HiddenLayer |
|---|---|---|---|---|---|---|---|
| OWASP ASI Top 10 | **10/10** | Partial | Labels | No | No | No | No |
| OWASP LLM Top 10 | Implicit | **Yes** | **Yes** | Partial | Partial | Partial | No |
| OWASP MCP Top 10 | No | No | No | No | No | Partial | No |
| NIST AI RMF | No | Claims | Labels | No | No | No | No |
| NIST AI 600-1 | No | No | No | No | No | No | No |
| NIST 100-2 | No | No | No | No | No | No | No |
| MITRE ATLAS | No | Partial | Labels | No | No | No | No |
| ISO 42001 | No | No | No | No | No | No | No |
| EU AI Act | No | No | No | No | No | No | No |
| SOC 2 | No | No | No | No | No | No | No |
| GDPR/CCPA | No | No | No | No | No | **Yes** | No |
| HIPAA | No | No | No | No | No | No | No |
| PCI DSS 4.0 | No | No | No | No | No | No | No |
| DORA | No | No | No | No | No | No | No |
| HITRUST AI | No | No | No | No | No | No | No |
| FedRAMP | No | No | No | No | No | No | No |

**Key insight:** The compliance mapping space is almost entirely greenfield. No AI security testing tool provides substantive, audit-ready compliance mapping to any major framework. The first tool to build a compliance report engine with multi-framework mapping will own this market.

---

## Total Framework Count

| Category | Count |
|---|---|
| AI-Specific Security Standards (OWASP) | 3 |
| NIST AI Standards | 6 |
| ISO AI Standards | 3 |
| Adversarial AI Frameworks | 2 |
| EU Regulations | 4 |
| US Federal | 2 |
| US State Laws | 6+ (70+ total across 27 states) |
| International Regulations | 7 |
| General Security Standards | 3 |
| Industry-Specific | 3 |
| Emerging/Voluntary | 5 |
| **Total distinct frameworks** | **44+** |

---

*Last updated: May 21, 2026*
*Research sources: OWASP, NIST, ISO, European Commission, state legislatures, MITRE, CSA, HITRUST, FedRAMP, IEEE, OECD, IMDA Singapore, and vendor documentation*
