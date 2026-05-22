# AASTF Go-to-Market: The Realistic Path from $0 to ARR in 6 Months
## Founder-Ready Strategy Document — Drafted May 21, 2026 for Operation Window June 10 – December 10, 2026

---

## TL;DR

- **$1M ARR in 6 months is a ~10–15% probability outcome for AASTF. The honest base case is $250K–$500K booked ARR by Dec 10, 2026.** Comparable AI-security OSS startups Lakera reached only $5.7M ARR four years after founding (per getlatka.com, September 2025); Promptfoo took roughly 18 months from commercial launch (July 2024 a16z $5M seed) to Series A scale (July 2025, $18.4M led by Insight Partners) and was acquired by OpenAI in March 2026 with ~25% Fortune 500 penetration and 350,000+ developers. The only credible OSS-led path to $1M in 12 months in adjacent categories is BrowserStack (1,000 paying customers and $1M revenue in year one, per founder retellings cited at buildd.co and valueforstartups.in), and that was a horizontal dev-tool category, not a niche security tool fighting acquired incumbents.
- **The ICP is not "enterprises that buy AI security." It is two narrow wedges: (1) AI-native Series A/B startups deploying agents to production (ACV $5–15K self-serve), and (2) EU-headquartered mid-market FinTech/HealthTech/InsurTech facing the August 2, 2026 EU AI Act high-risk obligations deadline (ACV $25–60K, compliance-triggered).** A third "swing" wedge is Indian IT services and GCCs ($10–40K) for white-label resale into their client engagements. Stop chasing F500 CISOs direct — Promptfoo (a16z + Insight + Fortune-500 logos + OpenAI brand) just took that lane, and AASTF cannot win it from India with three people in six months.
- **The 26-week plan: by Week 4 land 3 paid design partners at $5K each, by Week 12 close first $25K EU AI Act compliance pilot, by Week 18 have AWS Marketplace + partner pipeline live, by Week 26 book $400K–$500K ARR with a Q1 2027 expansion path to $1M. Kill-switch checkpoints at Week 8 (≥$15K booked or pivot), Week 16 (≥$100K booked or narrow ICP to EU-only), and Week 22 (≥$300K booked or extend timeline by one quarter).** The single most important early-action item: ship a free, hosted "EU AI Act Agent Risk Assessment" lead magnet by Week 1 and drive it through tl;dr sec sponsorship + founder-led LinkedIn content, not cold email to CISOs (where 2026 cold-email reply rates have collapsed to 3.43% industry-wide per the Instantly 2026 benchmark report, and well under 1% for unknown vendors emailing security buyers per Security Boulevard analysis).

---

## Key Findings

### 1. The market reality, in three sentences
The agentic-AI-security category is being rapidly consolidated by incumbents. In the 18 months before Dec 10, 2026: **Snyk acquired Invariant Labs (June 24, 2025)**, **Cato Networks acquired Aim Security (Calcalist reported $300–350M, September 2025)**, **Check Point acquired Lakera (September 16, 2025)**, **Palo Alto announced "Frontier AI Defense" with Accenture, Deloitte, IBM, NTT DATA, PwC partners (May 2026)**, **Microsoft launched Agent 365 + the open-source Agent Governance Toolkit (April 2, 2026, MIT-licensed, covering all 10 OWASP ASI risks with sub-millisecond enforcement, integrations across LangChain, CrewAI, ADK, OpenAI Agents SDK, AutoGen, Haystack, LangGraph, PydanticAI, Dify, LlamaIndex) plus Microsoft 365 E7 at $99/user/month (May 1, 2026)**, **ServiceNow launched Autonomous Security & Risk at Knowledge 2026 (May 5, 2026; their security/risk business crossed $1B ACV in the prior year)**, and **OpenAI acquired Promptfoo on March 9, 2026** (Promptfoo at acquisition: ~25% F500 penetration, 350,000+ developers, 23 employees, $85.5M post-money July 2025 valuation per PitchBook). The implications: (a) the F500 buyer now has 3–5 incumbent options bundled with their existing security stack, (b) the OSS-only/free competition just got harder because Microsoft AGT is free and ships with 9,500+ tests, and (c) the M&A premium for agentic-AI-security startups is real but is going to teams with patents, IP, or named-enterprise traction — not to 6-month-old tools.

### 2. What is actually buying AI agent security in mid-2026
- **EU AI Act compliance**: August 2, 2026 is the binding deadline for high-risk AI systems (Annex III: biometrics, critical infrastructure, employment, credit, insurance, law enforcement, migration). The Omnibus VII provisional agreement (Council/Parliament, May 13, 2026) may delay parts pending trilogue, but legal teams are advising clients to "assume August 2026 binds, prepare accordingly" (netguardia.com regulatory analysis). This is AASTF's single largest near-term catalyst — every EU-headquartered company with an Annex III AI system needs documented adversarial testing and risk assessment in the next 2.5 months.
- **Visible incidents driving emergency budget**: EchoLeak (CVE-2025-32711, CVSS 9.3, disclosed June 11, 2025 by Aim Labs) was the first widely-publicized zero-click prompt injection against a production LLM (Microsoft 365 Copilot). The GTG-1002 Chinese state-sponsored Claude Code hijacking (disclosed by Anthropic November 13, 2025) was the first publicly-documented AI-orchestrated cyberattack with ~30 targets and Claude executing 80–90% of operations autonomously. Per Thycotic's (now Delinea) CISO Decisions survey of 908 senior IT security decision-makers conducted by Sapio Research in August 2020, "More than three quarters (77%) of respondents have received Boardroom investment for new security projects either in response to a cyber incident in their organization (49%) or through fear of audit failure (28%)" — meaning AASTF's content marketing must lead with these named CVEs and incidents in every demo and ABM touch.
- **Open vs. closed competition**: DeepTeam (Confident AI, YC W25, $2.2M seed March 2025, 12,600 GitHub stars, 3M monthly downloads, named enterprise customers Microsoft, AstraZeneca, AXA, BCG, team of 7 per startupintros.com) is AASTF's closest direct OSS analog and is already 12 months ahead on commercial conversion. Garak (NVIDIA), PyRIT (Microsoft), and now Microsoft Agent Governance Toolkit are all free and well-resourced. **Pure OSS-with-paid-support will not get to $1M ARR in 6 months in this market.** A managed cloud + compliance reporting wedge is the only viable monetization.

### 3. Founder-fit honest assessment
Adarsh is an IIM Raipur PGP 2026 student with a marketing role at a solar EPC — there is **no security-engineer signal** and **no US/EU enterprise relationship base**. The two co-founders are explicitly marketing/BD. This is a marketing-led team selling a deeply technical security tool, which inverts the usual OSS security playbook (technical founder + marketing hire). The path to $1M requires either (a) recruiting/contracting a credentialed security engineer to be the technical face (someone with a Black Hat/DEF CON history, OWASP GenAI Security Project committee role, or a published CVE) before Week 6, OR (b) accepting that the tool sells itself via product-led adoption and the founders' role is purely demand generation + compliance packaging. The Indian-founders-selling-US-security path has worked (Druva, Postman, BrowserStack, Freshworks) but always with a hands-on technical CEO. Adarsh is closer to the Aakrit Vaish/Haptik or Girish Mathrubootham/Freshworks model than the Abhinav Asthana/Postman model.

---

## Details

### Section A — ICP Prioritization: Who Actually Buys in 2026

Ranked by realistic close probability in a 6-month window:

#### **Tier 1 (highest conversion, lowest ACV): AI-native Series A/B startups deploying agents to production**
- **ACV**: $5,000–$15,000/year (Promptfoo's Team-tier analog: probe-based metering, free OSS funnel; per sacra.com: "A probe is one request against the target system during red team testing, and the free tier includes 10,000 probes per month")
- **Sales cycle**: 14–30 days, often founder-to-founder
- **Decision-maker**: CTO or Head of Eng directly; sometimes a single staff AI engineer
- **Trigger**: First production deployment + a customer / VC asking "how is this safe?"
- **Pain level (1–10)**: 7 — high curiosity, low willingness to pay six figures
- **Named accounts (representative)**: From YC W26 alone the highest-relevance targets are agent-infrastructure plays: **Daytona** (running 100+ YC startups' agents per @daytonaio Feb 17 2026), **E2B** (sandboxed code execution, ~10% of W26), **Cascade** and **Clam** (W26 security/identity for agents), **Agentic Fabriq** (W26 identity for agents), **Veriad** (W26 AI compliance officers), **Pollinate** (W26 supply-chain agents), **Hex Security** (W26 autonomous probing — note: direct competitor, do not pitch), **General Legal** (W26 AI-native law firm), **Jinba** (W26 chat-driven workflows). YC S25 / W26 directory has ~850 AI companies; the realistic top-of-funnel is ~150 names. Add agentic-infra leaders outside YC: **LangChain, LlamaIndex, CrewAI, AutoGen (Microsoft), Semantic Kernel, Letta, Pydantic AI, Haystack (deepset), n8n, Gumloop, Lindy, Dust, StackAI** — many of these are partner-channel rather than direct-customer plays.
- **Tactic**: Founder-led DM via X/LinkedIn. Free-tier upgrade nudge based on probe usage. Target 60 paying logos at $7K average = $420K.

#### **Tier 2 (best $/effort ratio): EU mid-market FinTech / HealthTech / InsurTech with Aug 2, 2026 high-risk AI Act exposure**
- **ACV**: $25,000–$60,000/year (compliance-as-a-service framing) plus $15K–$40K one-time "EU AI Act Agent Audit" engagement
- **Sales cycle**: 30–60 days when paired with the deadline
- **Decision-maker**: Head of AI Governance / DPO / CISO; in regulated finance the Chief Risk Officer signs
- **Trigger**: Aug 2, 2026 high-risk obligations enforcement; even with Omnibus VII partial delay (provisional agreement May 13, 2026), conformity assessment documentation, post-market monitoring, and human-oversight evidence are still expected by August. Fines up to €15M or 3% of global turnover for high-risk non-compliance per Regulation (EU) 2024/1689.
- **Pain level**: 9 — board-level reportable obligation
- **Named target sectors and representative companies**: Insurance/credit-scoring (Annex III): **Allianz, AXA, Generali, Zurich, Aviva, Klarna, Wise, N26, Revolut, Monzo, Trade Republic, Scalable Capital, Mambu, Solaris** (regulated finance/fintech); healthcare AI (Annex III medical devices via Aug 2027 but conformity prep starts now): **Doctolib, Kry/Livi, Babylon Health, BenevolentAI, Owkin, DeepMind Health spinouts**; HR/employment AI (Annex III): **HireVue, Personio, SAP SuccessFactors EU customers, Workday EU customers**; education/credit-scoring: **Klarna, Younited Credit, Auxmoney, Bunq**. Note: AXA is already a named Confident AI customer, which is signal but also competitive friction.
- **Tactic**: Targeted ABM with named compliance personas (DPO + Head of AI Governance), gated by the "EU AI Act Agent Risk Assessment" lead magnet (auto-generated PDF mapping ASI01–ASI10 to Articles 9–15 of the AI Act). Target 8–12 logos at $35K average = $280K–$420K.

#### **Tier 3 (swing wedge): Indian IT services + Global Capability Centers, white-label resale**
- **ACV**: $10,000–$40,000/year per integrator (license to embed AASTF in client deliverables); upside via revenue-share on each client engagement
- **Sales cycle**: 45–90 days; faster if you bring named buyer/use case
- **Decision-maker**: Practice Head / Partner — AI Risk / Responsible AI at TCS, Infosys, Wipro, HCLTech, Tech Mahindra, LTIMindtree, Persistent, Mphasis, Coforge; at Big-4 India, Partner — AI Risk Advisory
- **Trigger**: Their clients (especially US/EU enterprises) demanding documented AI agent security testing; Indian Big-4 engagements run ₹50 lakhs to ₹10+ crores per project (per India consulting market reporting); embedding AASTF saves them building internal red-team tools
- **Pain level**: 6 — currently buying point tools and consulting hours; not yet a screaming need
- **Named targets**: **TCS** (Responsible AI practice + ignio platform), **Infosys** (Topaz, Aster, AI3S security suite), **Wipro** (ai360), **HCLTech** (AI Force), **Tech Mahindra** (amplifAI), **LTIMindtree** (Canvas.ai), **Mphasis** (NEXT Labs), **Persistent**, **Coforge**. Big-4: **Deloitte India Trustworthy AI**, **EY India Responsible AI** (EY.ai Agentic Platform powered by NVIDIA, 150 AI agents supporting 80,000 tax professionals), **KPMG India AI Audit** (using Google Agentspace), **PwC India AI Risk** (PwC + Google Cloud announced agentic SOC partnership; PwC's "Agent OS" platform). GCCs: **JPMorgan Mumbai/Bengaluru, Goldman Sachs Bengaluru, Bank of America Hyderabad, Deutsche Bank Pune, Citi Pune** (Citi posted a Senior AI Security Engineer role in Budapest March 2026 — they are hiring globally), **Wells Fargo Hyderabad, Walmart Global Tech Bengaluru, Target India, Lowe's India, Optum, UnitedHealth, Mastercard Pune, Visa Bengaluru**.
- **Tactic**: Direct partner-channel sales with rev-share. Adarsh's IIM Raipur network + India presence is a structural advantage here. Target 3–5 partner logos at $25K average = $75K–$125K, with embedded usage upside.

#### **Tier 4 (avoid for now): F500 / US Enterprise direct**
- **ACV**: $75K–$250K
- **Sales cycle**: 6–9 months
- **Why deprioritize**: Promptfoo + Lakera/Check Point + Aim/Cato + Microsoft AGT + ServiceNow Autonomous Security & Risk + Palo Alto Frontier AI Defense own this lane. A three-person India-based team with 6 months and no enterprise references will lose 9 out of 10 of these deals. Pursue only if a Tier 2 or 3 customer pulls AASTF into a parent F500.

#### **Tier 5 (long sales cycle, save for 2027): US/EU government/defense, Indian government**
- US DoD, CISA, GSA, EU institutions — RFPs are 12–18 months. Indian DRDO/NCIIPC/CERT-In — possible Tier 3 partner pull. Not a 6-month revenue source.

#### **Tier 6 (free-tier funnel, not a revenue source in 6 months): Indian consumer-tech**
- Razorpay, Zomato, Swiggy, Flipkart, PhonePe, CRED, Meesho, Freshworks, Zoho — most are deploying agents but security budgets are smaller and slower than US peers. Use them as case studies/community, not revenue. **HDFC Bank** (per Analytics Vidhya's August 2025 case study: targeting 80% of customer interactions to involve AI by 2025, GenAI Academy training 35,000 staff, reinforcement-learning agents triaging cybersecurity alerts, CISO Sameer Ratolikar describing an "AI-first enterprise within the next two years") and **ICICI Bank** (iPal chatbot, ML-based fraud detection across private banking) are real but procurement runs 6–12 months and they prefer Indian vendors with on-prem deployment + RBI FREE-AI framework alignment (RBI FREE-AI released August 13, 2025, 26 recommendations).

---

### Section B — The Math of $1M ARR

Three scenarios with explicit math:

#### **Aggressive ($1M ARR by Dec 10, 2026): ~10–15% probability**
| Segment | Logos | ACV | Subtotal |
|---|---|---|---|
| Tier 1 (PLG self-serve startups) | 60 | $7,000 | $420,000 |
| Tier 2 (EU AI Act mid-market) | 10 | $40,000 | $400,000 |
| Tier 3 (India SI/GCC partners) | 4 | $30,000 | $120,000 |
| Tier 4 (one F500 design-partner halo) | 1 | $75,000 | $75,000 |
| **Total** | **75 logos** | | **$1,015,000** |

What would need to be true: (a) AASTF wins the EU AI Act compliance positioning before any of Promptfoo/OpenAI, Lakera/Check Point, Aim/Cato bundles compliance reporting (Q3 2026 is the contested quarter); (b) at least one viral incident response or research disclosure published by AASTF lands in Black Hat USA Arsenal or DEF CON AI Village (August 2026); (c) one Big-4 India partner signs and pulls $200K+ of usage; (d) PLG conversion holds at the upper end of the open-source SaaS range (need ~1.5%) on a base of 4,000+ active GitHub installs.

#### **Realistic ($500K ARR by Dec 10, 2026): ~50% probability**
| Segment | Logos | ACV | Subtotal |
|---|---|---|---|
| Tier 1 (PLG startups) | 30 | $6,000 | $180,000 |
| Tier 2 (EU AI Act) | 6 | $35,000 | $210,000 |
| Tier 3 (India SI/GCC partners) | 3 | $25,000 | $75,000 |
| Tier 4 / F500 | 0 | — | $0 |
| Tier 2 one-time audit engagements | 5 | $8,000 | $40,000 |
| **Total** | **44 logos + 5 services** | | **$505,000** |

#### **Conservative ($250K ARR by Dec 10, 2026): ~75% probability**
| Segment | Logos | ACV | Subtotal |
|---|---|---|---|
| Tier 1 (design partners) | 15 | $5,000 | $75,000 |
| Tier 2 (EU AI Act) | 3 | $30,000 | $90,000 |
| Tier 3 (India partners) | 2 | $20,000 | $40,000 |
| Tier 2 audit engagements | 6 | $8,000 | $48,000 |
| **Total** | **26 logos** | | **$253,000** |

**Pipeline coverage**: For new security tools, 4–6× coverage is realistic. To book $500K closed-won at a 20% close rate, AASTF needs $2.5M of qualified pipeline by Week 18. To book $1M, $5M of pipeline by Week 18. At a 5% lead-to-qualified rate, that's 1,000–2,000 raw leads. **This is the binding constraint, not product capability.**

**OSS-to-paid conversion benchmark**: For open-source SaaS companies the benchmark is 0.5–3%, per OpenView Partners' analysis of companies including Elastic, MongoDB, and HashiCorp (cited in getmonetizely.com): "open source SaaS companies typically see lower conversion rates, often between 0.5-3%… successful open source companies like Elastic, MongoDB, and HashiCorp operate with conversion rates on the lower end of this spectrum." Confident AI (DeepTeam) is the most relevant comp: 12,600 GitHub stars and 3M monthly downloads converted to a paid base that includes Microsoft, AstraZeneca, AXA, BCG. Promptfoo's paid:free ratio at acquisition: ~30 F500 enterprise customers ÷ 350,000 developers ≈ 0.01% conversion on individual developers, but very high ACV. **AASTF should plan for 1% conversion of paid-tier-eligible users (i.e., companies, not individual devs).**

---

### Section C — Channel-by-Channel ROI Estimates

| Channel | Realistic 6-month yield | Cost / effort | Verdict |
|---|---|---|---|
| **Founder-led LinkedIn DMs to AI startup CTOs** | 15–25 paying Tier 1 logos at $5–10K | High founder time; ~30 DMs/day per BD co-founder, ~3% reply rate, 20% reply-to-call, 30% call-to-paid | **Do this from Week 1.** Adarsh's IIM network helps less in this lane than US-college networks would; lean on the two BD co-founders here. |
| **Cold email to CISOs / Heads of AI Security** | 1–3 logos at best | 2026 industry average cold-email reply rate has dropped to 3.43% (Instantly 2026 benchmark report); CISO-specific is well under 1% per Security Boulevard analysis ("Cold email converts to deals at just 0.2% — you need 500 emails for one customer"). Lakera's own 2025 GenAI Security Readiness Report shows only 4% of orgs rate their GenAI security confidence at the highest level — the buyer is interested but inundated. | **Skip until you have intent signals.** Generic cold email to security buyers is dead in 2026. |
| **ABM with intent signals (LinkedIn + Apollo + Clay) targeting EU AI Act-named accounts** | 6–10 Tier 2 logos at $30–50K | 50 named accounts, 5+ stakeholders per account, multi-channel sequence over 6–8 weeks, timeline-based hook (which delivers 2.3× higher reply rates and 3.4× higher meeting rates, per The Digital Bloom's "Cold Outbound Reply-Rate 2025 Benchmarks: Hook × ICP × Industry Analysis" by Vlad Kuriatnyk, November 10, 2025: "Timeline hooks drive 2.3x higher reply rates and 3.4x higher meeting rates compared to problem-based hooks") | **Highest-leverage paid channel.** Build this for EU AI Act wedge. |
| **OWASP community + Global AppSec USA SF (Nov 2–6, 2026, 25th anniversary, Hyatt Regency San Francisco, "connect with over 800 hundred security experts" per OWASP Foundation glueup.com page)** | 1 keynote/talk drives 3–6 enterprise conversations, 1–2 paid closes; Project Demo Room booth drives ~50 qualified leads | $2,500+ ticket + travel + booth/sponsorship; CFP closed for 2026 conference — pivot to OWASP Project Showcase + a US chapter talk in SF/NYC | **High ROI if you secure a slot.** Apply for OWASP AppSec Days India 2026 Virtual + a US chapter (e.g., OWASP Bay Area, OWASP DC) immediately. |
| **Black Hat USA Aug 1–6, 2026 Mandalay Bay + DEF CON AI Village + BSidesLV** | Arsenal demo slot drives ~100 qualified leads; DEF CON AI Village credibility is the highest in the market | Briefings pass starts ~$2,500; Arsenal acceptance is competitive. Vegas week is the highest-density technical week of the year, per Infosec Conferences. | **Critical for credibility.** Submit Arsenal CFP for AASTF demo if window is open (typically early May, may have closed — pivot to Tool Demo Room or sponsor reception). |
| **Indian conferences: c0c0n Kochi (Oct 6–13, 2026, Grand Hyatt Bolgatty) + Nullcon Goa (Feb 28 – Mar 1, 2027, BITS Pilani Goa, expected 3,000+ attendees) + DSCI Annual Information Security Summit** | 5–10 Tier 3 partner conversations; potentially 1–2 closed in 2026 (Nullcon falls outside the window but Day Zero CISO forum is the right audience) | Low cost, Adarsh can attend in person | **Strong fit for India-partner motion.** |
| **AWS Marketplace listing + Azure Marketplace** | First close typically 4–8 weeks after listing for free-tier; first $100K+ closed deal 6–12 months out | Listing setup 4–8 weeks (per AWS docs and Labra/Clazar analyses); AWS fees 1.5–3% for SaaS; ISV Accelerate program requires "Minimum 5 launched opportunities (ACE or AWS Marketplace Private Offers) in past 12 months… Minimum 15 qualified opportunities in ACE in past 12 months" (aws.amazon.com/partners/programs/isv-accelerate) — co-sell at scale is a 2027 lever, not a 2026 one | **List by Week 6 but don't depend on it for 2026 revenue.** Use for procurement-ease, not lead-gen. |
| **AI consultancy / Big-4 / Snyk partner deals** | 2–4 partner logos in 6 months; first deal 60–90 days from MSA | Slow start, big upside in 2027. Snyk, post-Invariant Labs (June 24, 2025), is now an AppSec-AI competitor more than a partner. Cato, Check Point, Palo Alto are competitors. **The realistic partners are: regional MSSPs (Optiv, Trustwave, NCC Group, eSentire), Indian SIs (Section A Tier 3 list), and EU-focused AI risk boutiques (e.g., Holistic AI, Credo AI, Trustible).** | **Time investment now pays in Q1 2027.** Get partner MSAs signed by Week 12. |
| **Content marketing + SEO** | Realistic SEO traction takes 6–9 months; expect minimal organic in 2026 | High writing cost | **Publish for credibility, not lead-gen.** Cadence: 2 long-form posts/month + 5 LinkedIn posts/week + 3 X threads/week per founder. |
| **Newsletter sponsorships** | tl;dr sec (Clint Gibler, 90,000+ subscribers per tldrsec.com/subscribe: "90,000+ security professionals getting the best tools, blog posts, talks, and resources right in their inbox for free every Thursday") is the single best-targeted property in the space; Risky Business (Patrick Gray, "more than 25,000 information security professionals all over the world… 50% of our audience is based in the USA" per risky.biz/sponsorship) drives credibility but is interview-style not display; Return on Security / Security Funded (Mike Privette) is good for fundraising signals; TLDR (general tech, "$3000 per issue with a 3 issue minimum… 7M+ subscribers" per messaged.com/tldr) is too broad to be efficient | **Sponsor tl;dr sec twice (Week 4 + Week 16) and Risky Biz Soap Box once (Week 12) — expect ~$15K–$30K in spend driving 80–120 qualified inbound conversations** | **High-ROI for AASTF's exact buyer.** |
| **"Build in public" on X + LinkedIn** | Founder follower-to-customer conversion benchmarks for B2B security: <0.05% but compounds | Free, requires founder time | **Adarsh should post 5×/week minimum.** Frame: India-based founder, OWASP ASI 2026 framework, EU AI Act countdown clock. |
| **YC W26/S26 founder outreach via WhatsApp/Slack** | Could yield 5–15 Tier 1 logos at $5K | Founder-to-founder DMs, free | **Run a 3-week sprint Week 1–3.** |

---

### Section D — Pricing Strategy

The fastest-revenue pricing structure for AASTF in 6 months:

1. **Free Community tier (OSS)**: aastf PyPI package, GitHub Action, MCP Top 10 scanner, basic ASI Top 10 detectors. Cap at 10,000 probes/month (mirror Promptfoo's metering, which OpenAI inherited). **Goal: 5,000+ installs by Week 26 as the funnel.**
2. **Starter / Team tier ($499/month or $4,990/year, 1–5 seats)**: web dashboard, CI/CD hooks, AutoGen/Semantic Kernel/CrewAI/LangChain adapters, hosted result storage 90 days, email support. **This is the Tier 1 PLG wedge.** Annual prepay 17% discount.
3. **Compliance tier ($25,000–$50,000/year)**: EU AI Act + NIST AI RMF + ISO 42001 mapped report engine, SSO/SAML, RBAC, audit trail, signed PDF attestations for auditors, MSA + SOC 2 Type 1 commitment. **This is the Tier 2 wedge — price it at $35K base + $5K per Annex III system.**
4. **One-time "EU AI Act Agent Audit" engagement ($8,000–$15,000)**: 2-week consulting engagement using AASTF tooling, deliverable is a board-ready conformity assessment package. Adarsh's BD co-founders lead delivery. **This is the fastest cash — average sale Week 6–12.**
5. **Partner / OEM tier ($25,000–$75,000/year base + revenue share)**: Indian SI / Big-4 white-label. **This is Tier 3.**

**Avoid**: Pure self-serve $29/seat (no path to $1M from $29/month seats in 6 months with this team size); pure $100K+ enterprise custom (sales cycle is too long for the window).

**Anchor pricing publicly on the site** — opacity hurts you at this stage. Promptfoo, Lakera, HiddenLayer all hide pricing because they have brand. AASTF doesn't, so transparency wins the first call.

---

### Section E — The 26-Week GTM Calendar (June 10 – December 10, 2026)

#### **Phase 1: Foundation (Weeks 1–4, June 10 – July 8)**
- **Week 1 (Jun 10–16)**: Ship the "EU AI Act Agent Risk Assessment" lead magnet (free hosted tool that runs AASTF's ASI01–ASI10 detectors against a public agent endpoint and emails a 12-page PDF with EU AI Act Article 9/14/15 mappings). Stand up Stripe + self-serve checkout for Starter tier. Publish v1.0.0 PyPI release post on HN, Reddit r/MachineLearning, r/netsec, X. Apply to OWASP AppSec Days India 2026 Virtual + a US chapter. Founders publish 1 post/day on LinkedIn each.
- **Week 2 (Jun 17–23)**: Open-source MCP Top 10 scanner with a Microsoft AGT comparison blog post ("AGT covers runtime; AASTF covers pre-deployment testing — here's the complementary playbook"). Reach out to 50 YC W26/S26 AI agent founders. Apply for AWS Marketplace seller registration (4–8 week timeline). Submit Black Hat Arsenal application if window is still open; otherwise reserve a sponsor lounge meeting block.
- **Week 3 (Jun 24–30)**: Publish a deep-dive technical breakdown of the GTG-1002 Claude hijacking + EchoLeak chain — "What AASTF would have caught" — and pitch tl;dr sec, Risky Business, Security Boulevard, The Stack as guest content. Begin ABM list-build for 50 EU AI Act-named accounts (Allianz, AXA, Klarna, Wise, N26, Revolut, Trade Republic, Solaris, Doctolib, Kry, Personio, Mambu, Younited Credit, Auxmoney, Bunq, etc.).
- **Week 4 (Jul 1–8)**: **Milestone — 3 paid design partners at $5K each ($15K cumulative ARR)**. These should be YC W26/S26 startups already in your network or via the public launch. Run a sponsored tl;dr sec slot Week 4 issue.

**Kill-switch checkpoint Week 8**: If <$15K booked or <3 paying logos, diagnose: is it product (free tier too restrictive?), positioning (lead magnet not landing?), or distribution (founder-led DMs not converting?). If positioning, swap the EU AI Act angle for a pure "OWASP ASI 2026 testing" angle. If distribution, double down on Indian partner channel.

#### **Phase 2: EU AI Act + Vegas (Weeks 5–10, July 9 – August 19)**
- **Week 5 (Jul 9–15)**: Launch ABM sequence to the 50 EU AI Act accounts. Sequence: Day 1 personalized LinkedIn connection; Day 3 timeline-hook email ("Your firm has 25 working days to August 2"); Day 7 case study; Day 12 free risk assessment offer; Day 18 follow-up + AASTF founder calendar link. Hire one part-time SDR in India (~$1.5K/month) to run this sequence — Indian SDR cost is roughly 1/4 of US SDR cost.
- **Week 6 (Jul 16–22)**: AWS Marketplace listing goes live (or close to it). Launch a "30 days to EU AI Act" content drumbeat: 2 blog posts per week through Aug 2. Pitch India-specific Big-4 partner intros (Adarsh's IIM Raipur network here).
- **Week 7 (Jul 23–29)**: First "EU AI Act Agent Audit" $8K engagement closed via inbound from the lead magnet.
- **Week 8 (Jul 30 – Aug 5)**: Black Hat USA Week (Aug 1–6, Mandalay Bay Convention Center). One co-founder physically in Las Vegas. Goals: 50 in-person meetings, 1 demo per day in the Business Hall (Tue–Thu), attend Arsenal demos as audience for relationship-building. DEF CON immediately following Black Hat at Las Vegas Convention Center, AI Village booth visits. Target: 80 qualified conversations across Vegas week.
- **Week 9 (Aug 6–12)**: Vegas debrief; convert 15 of 80 Vegas conversations into demo bookings. **EU AI Act high-risk obligations enter force Aug 2 — publish the "AASTF EU AI Act Compliance Pack 2.0" and run a webinar.** Target 200 webinar attendees.
- **Week 10 (Aug 13–19)**: Close 2–3 Tier 2 logos from Vegas + webinar pipeline. **Milestone — $75K cumulative ARR.**

#### **Phase 3: India + Partner Channel (Weeks 11–16, August 20 – October 1)**
- **Week 11 (Aug 20–26)**: Open Tier 3 motion. Adarsh in India presents at OWASP local chapters (Mumbai, Bengaluru, Delhi) and meets in-person with TCS Responsible AI Practice, Infosys AI3S, Wipro ai360, LTIMindtree Canvas.ai practice leads. Pitch a partner program with 25% revenue share on year-one ACV.
- **Week 12 (Aug 27 – Sep 2)**: **Milestone — first $25K Tier 2 enterprise pilot closed.** Sponsor Risky Biz Soap Box (rate by direct enquiry — risky.biz does not publish rates). Publish "State of Agentic AI Security Q3 2026" — original survey of 200+ practitioners, modeled on Lakera's annual GenAI Security Readiness Report (which drove most of their late-stage narrative).
- **Week 13 (Sep 3–9)**: Sign first Indian SI partner MSA at $25K base. Start joint go-to-market with that partner's existing F500 client base.
- **Week 14 (Sep 10–16)**: SOC 2 Type 1 audit kickoff with a fast vendor (e.g., Vanta, Drata-managed) — required for any Tier 2 enterprise close. Budget: $8–15K + 4-week timeline.
- **Week 15 (Sep 17–23)**: Sponsor tl;dr sec second slot. Apply to speak at AWS re:Invent 2026 (Dec 1–5, Vegas) — agenda is set early, so target the AWS Marketplace sponsor lounge or a partner-co-hosted session.
- **Week 16 (Sep 24 – Oct 1)**: **Kill-switch checkpoint — if <$100K booked, narrow ICP to EU-only and extend timeline.**

#### **Phase 4: India in-Person + Compliance Push (Weeks 17–22, October 2 – November 12)**
- **Week 17–18 (Oct 2–15)**: c0c0n Kochi (Oct 6–13, 2026, Grand Hyatt Bolgatty). Adarsh delivers a talk on OWASP ASI 2026 testing in production. Run a CXO breakfast for Indian GCC CISOs. Target: 5 Tier 3 partner conversations + 2 GCC pilot signups.
- **Week 19 (Oct 16–22)**: Black Hat Middle East & Africa Dec 1–3, 2026 Riyadh — apply for sponsor slot or panel. Begin closing Q4 EU AI Act renewals/expansions (orgs that bought audit engagements in Jul–Sep now upgrade to annual Compliance tier).
- **Week 20 (Oct 23–29)**: **Milestone — $200K cumulative ARR booked.** Hire first US-based AE on commission-only or low-base ($60K base + 10% commission) to handle inbound demos Adarsh and BD co-founders can't run from IST.
- **Week 21 (Oct 30 – Nov 5)**: Pre-OWASP Global AppSec push. Publish a Mindgard-style benchmark study: "How AASTF vs DeepTeam vs Garak vs PyRIT vs Microsoft AGT detect the OWASP ASI 2026 Top 10." Send to OWASP project leads and tl;dr sec for editorial mention.
- **Week 22 (Nov 6–12)**: OWASP Global AppSec USA San Francisco (training Nov 2–4, conference Nov 5–6, Hyatt Regency SF, 800+ attendees, OWASP Projects Demo Room). One co-founder on the ground. Goal: 40 qualified conversations. Apply ahead to the OWASP Projects Demo Room (free for OWASP project leads — register AASTF as an OWASP-affiliated project if not already). **Kill-switch checkpoint — if <$300K booked, extend timeline to Q1 2027.**

#### **Phase 5: Close & Renewal Sprint (Weeks 23–26, November 13 – December 10)**
- **Week 23 (Nov 13–19)**: Convert post-OWASP pipeline. Close 3–5 Tier 1 + Tier 2 deals.
- **Week 24 (Nov 20–26)**: Begin renewal conversations with all Tier 1 design partners from Week 4 — upgrade $5K monthly trials to $7–10K annual. AWS re:Invent Dec 1–5 Vegas — booth or partner-pavilion presence.
- **Week 25 (Nov 27 – Dec 3)**: AWS re:Invent + year-end procurement push. Many F500 buyers have "use it or lose it" Q4 security budget — pitch Compliance tier with implementation-by-Jan-1.
- **Week 26 (Dec 4–10)**: **Final close push.** Target: $400K–$500K cumulative ARR booked.

---

### Section F — Founder-Fit & India-Specific Calculus

#### **Incorporation recommendation**
- For US/EU enterprise sales: **Delaware C-corp by Week 4**. Indian Pvt Ltd creates procurement friction at every F500 / EU mid-market deal. The fastest setup is a Delaware C-corp + India Pvt Ltd subsidiary (the "Flip" structure used by Postman, BrowserStack, Freshworks, Druva — all of whom incorporated US-side before scaling). Use Stripe Atlas or Clerky ($500–$2,000 setup + ~$500/year compliance).
- AWS Marketplace requires a seller-of-record entity in an eligible jurisdiction; India is on the eligible list but a US bank account is required for paid products. Delaware solves both.
- For India-only Tier 3 partner sales: Pvt Ltd is fine and may be preferred by Indian SIs for GST/INR billing.

#### **Time-zone playbook**
- Adarsh in India + BD co-founders' geographies determine coverage. If both BD co-founders are also in India, this is a weakness for US enterprise sales (live demos only in early-AM US hours). Mitigations: (a) hire a US-based contract AE by Week 20; (b) use Loom-recorded async demos + scheduled Calendly slots in US 9am–11am ET = 6:30–8:30 PM IST; (c) use Vegas (Aug) and SF OWASP (Nov) trips to compress F2F selling.

#### **Cost advantage**
- Indian BD/SDR costs ~$18–24K/year fully loaded vs $80–120K in US. AASTF can run 3 SDRs in Bengaluru/Pune for the cost of 1 US SDR. **This is a real moat for the partner-channel and EU mid-market segments where buyers are timezone-tolerant.**

#### **India-to-US OSS-led security SaaS analogs**
- **BrowserStack** (Ritesh Arora, Nakul Aggarwal): bootstrapped, "Within 6 months: 1,000 paying customers. Within 1 year: $1M in revenue. All with a team of two, working from a coffee shop… By 2018, revenue exceeds $50M with $40M in profits" (per valueforstartups.in BrowserStack investor report). First VC round in 2018. This is the most aspirational comp — but they had no entrenched competitors.
- **Postman** (Abhinav Asthana, Ankit Sobti, Abhijit Kane): Chrome extension 2012, incorporated 2014, $1M Nexus seed May 2015, $8.4M revenue by 2018. Roughly 12–18 months from paid launch to $1M ARR.
- **Druva** (Jaspreet Singh): backup/security, founded 2008 in Pune, took years to $1M ARR but eventually IPO'd 2024.
- **Freshworks** (Girish Mathrubootham): horizontal SaaS, took ~3 years to material ARR but founded a different playbook.
- **Repello AI**: relevant direct comparable — Indian AI security startup founded 2024, $1.225M seed (Venture Highway/General Catalyst, pi Ventures), customers Groww and PhysicsWallah. Early days, but proves Indian AI-security startups can sign Indian consumer-tech logos.

The honest lesson: **Indian-founded OSS-led security SaaS reaching $1M ARR in 6 months from a cold start has no proven precedent.** BrowserStack hit $1M in 12 months but wasn't security and had no entrenched competition. AASTF needs to compress that timeline by 2× in a category with 5+ acquired/well-funded competitors. The plan is achievable for $500K, ambitious for $1M.

---

### Section G — Risk Factors & Kill-Switches

| Failure mode | What it means | Action |
|---|---|---|
| **$0 ARR by end of Month 2 (Aug 10)** | Either the lead magnet isn't converting, or product positioning is wrong | Run user interviews with 20 lapsed trials. If positioning, swap to "OWASP ASI 2026 testing" pure technical angle. If product, accelerate a managed-hosted-SaaS launch ahead of v1.0.0 polish. |
| **Pipeline full but <10% close rate by Month 4 (Oct 10)** | Likely a "Promptfoo / Lakera shadow" — buyers prefer the acquired incumbent | Reposition as the open-source independent alternative ("the WordPress to their Squarespace"). Lean into vendor-lock-in messaging and on-prem deployment for the EU. |
| **Microsoft AGT eats the OSS layer** | AGT (April 2, 2026, free, covers all 10 OWASP ASI risks, sub-millisecond enforcement, integrates with LangChain, CrewAI, ADK, OpenAI SDK, AutoGen, Haystack, LangGraph, PydanticAI, Dify, LlamaIndex) is a free runtime governance layer | AASTF's wedge is **pre-deployment adversarial testing + audit-grade compliance reports** — AGT is runtime, AASTF is build-time. Lead every demo with this distinction. |
| **EU AI Act Omnibus VII passes per the May 13, 2026 provisional agreement** | High-risk obligations linked to "supporting tools availability" — could push enforcement to Dec 2, 2027 for stand-alone systems and Aug 2, 2028 for embedded. **But** even the delayed scenario keeps Aug 2, 2026 binding under current Regulation (EU) 2024/1689 until formally adopted. | The conservative legal play (per netguardia.com analysis: "assume August 2026 binds, prepare accordingly") still drives 2026 buying urgency. No change to plan. If full delay materializes Q3 2026, pivot to NIST AI RMF + ISO 42001 + India's RBI FREE-AI framework as the compliance hooks. |
| **Adarsh's IIM PGP commitments collide with launch** | PGP 2026 graduation is mid-2026; if he can't go full-time post-graduation, motion stalls | Plan must assume full-time founders by July 1 latest. If not, drop $1M target to $250K conservative. |
| **No technical security credibility** | Buyers want to see a Black Hat speaker, OWASP project lead, or CVE researcher as the technical face | Recruit a Security Advisor with name recognition (e.g., a former Lakera/Aim/Robust engineer, an OWASP GenAI Security Project committee member) by Week 6. Offer 0.5–1% equity + $5K honorarium. |
| **Confident AI / DeepTeam launches an "EU AI Act Compliance" SKU before Q3 2026** | They have YC backing and Microsoft/AXA/BCG logos — they could outmaneuver AASTF on the same wedge | Move faster — ship the lead magnet Week 1, not Week 4. Lock in 3 EU design-partner logos via free pilot by Week 6. Beat them to publication on EU AI Act ↔ ASI mapping. |

---

### Section H — The Probability Verdict

**Base rate for OSS security startups reaching $1M ARR**: historical median is 18–24 months from commercial launch; Promptfoo did it in ~12 months by being first-mover with a16z funding; Lakera reached only $5.7M ARR over 4 years; Confident AI is still pre-disclosure on revenue 12+ months in. **AASTF starting June 10, 2026 with 6 months and a three-person India team has no comparable precedent for $1M.**

The math says:
- **$1M ARR by Dec 10, 2026: ~10–15% probability.** Requires every wedge to hit upper-bound and a single F500 design-partner deal worth $75K+.
- **$500K ARR by Dec 10, 2026: ~50% probability.** This is the bet to plan for — achievable with disciplined execution on the EU AI Act wedge + India partner channel.
- **$250K ARR by Dec 10, 2026: ~75% probability.** This is the floor; if you're below this by Week 22, the timeline needs to extend.

**Set the public-facing goal at $500K and the internal stretch goal at $1M, with $250K as the kill-switch floor. Optimize all decisions for the $500K plan because that's the probability-weighted highest-value outcome. The $1M is a stretch outcome, not a plan.**

---

## Recommendations

### Monday-morning checklist (June 10, 2026 week)

1. **Incorporate Delaware C-corp this week** (Stripe Atlas, $500). Maintain Indian Pvt Ltd for INR billing.
2. **Ship the EU AI Act lead magnet** by end of Week 1. This is the single highest-leverage asset.
3. **Open a Stripe / self-serve Starter checkout** at $499/month and $4,990/year by Week 1.
4. **Submit OWASP AppSec Days India 2026 Virtual CFP + OWASP US chapter speaking slot** (Bay Area, NYC, DC) by Week 1.
5. **Begin SDR list-build of 50 EU AI Act named accounts + 150 YC W26/S26 AI agent companies** by Week 1.
6. **Recruit a Security Advisor with public credibility** — Black Hat speaker history, OWASP GenAI Security Project committee membership, or a published CVE — by Week 6.
7. **Publish GTG-1002 + EchoLeak technical teardown blog** by Week 3; pitch to tl;dr sec and Risky Business as guest content by Week 4.
8. **Apply to AWS Marketplace as a seller** by Week 2 (4–8 week approval cycle). Submit FTR-prep docs in parallel.
9. **Book Black Hat USA + DEF CON travel** by Week 4 (Vegas rooms fill by July). At least one founder on the ground August 1–10.
10. **Set up weekly metrics dashboard**: GitHub stars, PyPI installs, free-tier signups, Compliance-tier inbound, ABM reply rate, demos booked, $ pipeline, $ closed-won. Review every Friday IST.

### Staged escalation thresholds

- **Week 8**: ≥$15K booked → proceed; <$15K → pivot positioning OR product.
- **Week 16**: ≥$100K booked → proceed on $500K plan; <$100K → narrow ICP to EU AI Act only and extend timeline 1 quarter.
- **Week 22**: ≥$300K booked → close-out push for $500K; <$300K → reset target to $250K and plan Q1 2027 fundraise (if revenue strategy is failing, OSS-attention metrics may still support a seed round despite the "no fundraising" preference).

---

## Caveats

- **Hypothetical accelerated scenario**: This plan assumes the full AASTF v1.0.0 feature set (Compliance Report Engine, EU AI Act + NIST AI RMF + ISO 42001 mappings, web dashboard, SSO, RBAC, MCP Top 10 scanner, AutoGen/Semantic Kernel adapters, multi-agent testing, Helm chart, Docker, GitHub Action) ships by June 10, 2026 as specified in the brief. If any of these slip, especially the Compliance Report Engine, Tier 2 revenue drops by 50–80%.
- **Competitive moves that would invalidate this plan**: (a) Microsoft adds a Compliance Report Engine + ISO 42001 mapping to AGT before Q4 2026; (b) Confident AI / DeepTeam announces an "EU AI Act Compliance" SKU before Q3 2026 (they have YC backing and the Microsoft/AXA logos already); (c) Promptfoo (now inside OpenAI) launches an OpenAI Compliance Pack bundled with Enterprise ChatGPT; (d) the European Commission delays high-risk obligations to 2027 in the final Omnibus VII trilogue text.
- **Source confidence**: ARR figures for Promptfoo, Confident AI, and Aim Security are estimated from secondary reporting (PitchBook valuation, employee counts, customer disclosures) — Promptfoo and Confident AI did not publicly disclose ARR. Aim Security's $300–350M acquisition price comes from Calcalist (Hebrew-press original); Cato did not officially confirm. Lakera's $5.7M ARR figure is from getlatka.com (third-party scraping, not audited).
- **The Snyk + Invariant Labs deal closed June 24, 2025, not 2026 as stated in the source brief.** Worth correcting in any internal documents.
- **The Omnibus VII provisional agreement (Council and Parliament, May 13, 2026) is not yet final law** — it must complete trilogue and formal adoption. If adopted as proposed, high-risk obligations move to Dec 2, 2027 (stand-alone) and Aug 2, 2028 (embedded). For now, plan as if Aug 2, 2026 binds.
- **The team's lack of a credentialed technical security founder is the single biggest risk factor** to the entire plan. If the Security Advisor recruitment (Week 6) fails, every revenue scenario downgrades by 30–40%.
- **The Thycotic/Delinea "77% incident-driven" figure is from August 2020** and may understate the 2026 boardroom dynamic (which has since shifted toward proactive AI governance budgets), but directionally remains the best public benchmark.