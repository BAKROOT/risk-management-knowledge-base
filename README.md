# Security Risk Management — A Concept Knowledge Base
## A practical guide to frameworks, quantitative risk, cloud posture, vulnerability management, and program operations

---

## 0. What a Senior Security Risk Management role actually is

A Senior Information Security Engineer for Security Risk Management is not a penetration testing role, not a SOC role, and not a pure auditor role. It sits in the middle, and its purpose is best framed as:

> *"Design, automate, and scale the controls, workflows, and tooling that reduce and manage security risk across the organization."*

In practice this means running a risk program like an engineering system: a risk register that behaves like a ticketing pipeline, risk scoring that is repeatable rather than opinion-based, dashboards that generate themselves, and enough Python and automation skill to stop doing the mechanics by hand.

The role sits primarily in the **GOVERN** and **IDENTIFY** functions of NIST CSF 2.0, consumes outputs from **DETECT** and the vulnerability management side of **PROTECT**, and reports upward in business terms rather than in technical severity scores.

---

# PART I — RISK AS A DISCIPLINE

## 1. The core vocabulary

**Asset** — anything of value: data, a service, a pipeline, a reputation. In a SaaS or CCaaS context, an "asset" is usually a *service* or *data store*, not a laptop.

**Threat** — a source (actor, system failure, nature) with the potential to cause harm. NIST splits this into:
- **Threat source** — who or what (ransomware affiliate, insider, misconfigured automation)
- **Threat event** — what they do (exfiltrate call recordings via over-permissive bucket)

**Vulnerability** — a weakness that a threat can act on. In risk language a vulnerability is *not* only a CVE. A missing process, an unassigned owner, or a lack of logging are all vulnerabilities.

**Likelihood** — probability the threat event occurs *and* succeeds. NIST 800-30 splits it: likelihood of *initiation* × likelihood of *adverse impact*.

**Impact** — magnitude of harm if the event happens. Always expressed in business terms (revenue, contractual penalty, customer churn, regulatory fine, downtime minutes).

**Risk** = a function of likelihood × impact, in the context of a specific asset.

**Inherent risk** — the risk *before* any controls. Mostly theoretical; useful to show control value.
**Current / actual risk** — risk with controls as they exist today (this is what most registers actually hold, even when they call it "residual").
**Residual risk** — risk remaining *after* the planned treatment is complete.
**Target risk** — the level the program is aiming for.

> **Practical nuance:** many organisations conflate *current* and *residual*. Distinguishing them cleanly is a mark of program maturity.

**Risk appetite** — the amount and type of risk the organisation is *willing to pursue* to meet objectives. Set by leadership. Strategic and qualitative.
**Risk tolerance** — the acceptable *variation* around appetite, usually per-category and expressed as thresholds ("no unremediated Critical on internet-facing production beyond 7 days").
**Risk capacity** — the maximum risk the organisation could absorb before it fails.

**Risk owner** — the person accountable for the *risk outcome*; must have budget and authority. Usually a service owner or engineering director.
**Control owner** — the person who operates the control.
**Remediation owner** — whoever does the work.

These are frequently different people. Resolving ambiguity around risk ownership is the daily operational work of the role.

**Key Risk Indicator (KRI)** — leading; predicts risk increasing (e.g. % of prod services with no named owner).
**Key Performance Indicator (KPI)** — lagging; measures how the program performs (e.g. mean time to risk closure).
**Key Control Indicator (KCI)** — is the control actually operating?

**Issue vs Risk** — a *risk* is potential; an *issue* or *finding* has already materialised or is a confirmed defect. A scanner finding is a finding. "Unpatched internet-facing services persist beyond SLA because ownership is unclear" is a risk. Registers rot when findings get dumped into them without being converted into risk scenarios.

---

## 2. Risk assessment methodologies

### 2.1 Qualitative
Ordinal scales — Very Low → Very High, or 1–5 — for likelihood and impact, combined in a matrix (heat map).

**Strengths:** fast, needs no loss data, universally understood.
**Weaknesses:**
- Ordinal scores are **not arithmetic** — a 4 is not "twice" a 2, so multiplying them is mathematically illegitimate ("range compression").
- Scores drift to the middle ("medium").
- Two assessors give different answers for the same risk.

**Mitigations:** anchored rubrics (define exactly what "High impact" means in €, hours downtime, records exposed), calibrated estimation training, a mandatory second reviewer, and forcing a distribution.

### 2.2 Semi-quantitative
NIST SP 800-30's approach: ordinal bands backed by numeric ranges (e.g. Very High = 96–100 on a 0–100 scale, or "> 10 times per year"). Produces sortable numbers without pretending to precision. This is what most mature registers actually use.

### 2.3 Quantitative — classic
- **SLE** (Single Loss Expectancy) = Asset Value × **EF** (Exposure Factor, % of asset lost)
- **ARO** (Annualised Rate of Occurrence) = expected events per year
- **ALE** (Annualised Loss Expectancy) = SLE × ARO
- **Control justification:** if ALE drops from €400k to €50k and the control costs €90k/yr, the benefit is €260k/yr. This is the "should we fund it" conversation.

*Worked example:* Call-recording store exposed. AV = €2M (breach cost for 500k records), EF = 20% → SLE = €400k. ARO = 0.25 (once in 4 years) → **ALE = €100k/yr.** A €30k/yr CSPM plus bucket-policy control that cuts ARO to 0.05 gives ALE €20k → €80k/yr avoided loss. Fund it.

### 2.4 Quantitative — FAIR (Factor Analysis of Information Risk)
The Open Group's Open FAIR standard is the reference model for quantitative cyber risk.

```
Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)

LEF = Threat Event Frequency (TEF) × Vulnerability
    TEF = Contact Frequency × Probability of Action
    Vulnerability = f(Threat Capability, Resistance Strength)

LM  = Primary Loss + Secondary Loss
```

**Six forms of loss:** productivity, response, replacement, fines and judgements, competitive advantage, reputation.

Key FAIR ideas:
- Estimate **distributions**, not point values (min / most likely / max, with a confidence level).
- Run **Monte Carlo** simulation over those distributions.
- Output is a **Loss Exceedance Curve** — "there is a 10% chance we lose more than €5M this year from this scenario." Executives understand this format because it speaks their language.
- **Calibrated estimation** (Hubbard) — training people to give 90% confidence intervals they are actually right about 90% of the time.
- FAIR forces **scenario discipline**: a FAIR scenario must be *asset + threat actor + effect* ("malicious external actor causes confidentiality loss of customer call recordings"), not "cloud security is bad."

**When to use which:** qualitative or semi-quantitative for the whole register at scale; FAIR for the top 5–10 risks, funding decisions, cyber insurance sizing, and board reporting. The mature approach is to *triage qualitatively and quantify selectively.*

### 2.5 Supporting techniques
- **Bow-tie analysis** — threats → preventive controls → the event → detective and corrective controls → consequences. A strong visual for exec audiences.
- **RCSA** (Risk and Control Self-Assessment) — service owners assess their own risks against a defined control set; risk management validates a sample. This is how a program scales across a large estate.
- **Threat modelling** (STRIDE, PASTA, attack trees) — feeds new risks in at design time.
- **Scenario / tabletop-driven risk discovery** — often surfaces more real risk than a control checklist.

---

## 3. The Risk Register — the central artefact

The risk register is the operational centre of the discipline. How it is built, populated, and maintained determines whether a program is real or performative.

### 3.1 What a register entry must contain
| Field | Why it exists |
|---|---|
| Risk ID | Immutable reference for audit and reporting |
| Title (scenario-formatted) | Forces clarity; see format below |
| Description / scenario narrative | Threat, asset, vector, consequence |
| Category / taxonomy | Enables aggregation and trend reporting |
| Affected asset / service / business unit | Enables scoping and ownership |
| Source of identification | Pentest, audit, scanner, incident, RCSA, threat intel, M&A DD |
| Inherent likelihood / impact / score | Shows control value |
| Existing controls | What is already reducing it |
| Current (residual) likelihood / impact / score | The number people act on |
| Risk owner (named human, not team) | Accountability |
| Treatment decision | Mitigate / Accept / Transfer / Avoid |
| Treatment plan + linked remediation tickets | Where the actual work lives |
| Target residual score + target date | Makes progress measurable |
| Status (Identified → Assessed → Treatment → Monitoring → Closed) | Lifecycle |
| Review date / cadence | Prevents rot |
| Framework mapping (CSF/800-53/ISO/SOC 2/PCI ref) | Audit reuse |
| Evidence links | Audit survival |

**Scenario title format:**
> *"[Threat actor] may [action] against [asset] via [weakness], resulting in [business impact]."*

### 3.2 The lifecycle
1. **Identify** — intake from many channels; deduplicate aggressively.
2. **Assess** — score with the organisation's rubric; second-reviewer for High and above.
3. **Assign ownership** — the hardest step in practice.
4. **Decide treatment** — the four options below.
5. **Track treatment** — linked engineering tickets, dates, escalation on slip.
6. **Monitor / re-assess** — cadence by severity (Critical monthly, Low annually).
7. **Close** — with evidence, not with optimism.

### 3.3 The four treatment options
- **Mitigate / Modify** — implement or strengthen controls.
- **Transfer / Share** — insurance, contractual indemnity, outsourcing. Financial loss can be transferred; accountability and reputational damage cannot.
- **Avoid / Terminate** — stop doing the activity, decommission the service.
- **Accept / Retain** — formally, with expiry. Not "ignore."

### 3.4 Common register failure modes
- Becomes a **findings dump** rather than a scenario-based register.
- Risks owned by *teams*, so nobody is accountable.
- No expiry on acceptances → permanent amnesty.
- Scores never change → no evidence the program does anything.
- Register lives in a spreadsheet nobody outside security reads.
- No linkage between a risk and the engineering work that fixes it.
- Everything is "Medium."

---

## 4. Risk acceptance and exception management

**Risk acceptance** = a formal, documented, time-bound decision to live with a risk. **Exception** = a formal deviation from a policy or standard (often the mechanism that creates an accepted risk).

A defensible acceptance record contains:
- The risk scenario and its current score
- **Why** remediation is not happening now (cost, technical constraint, roadmap, business necessity)
- **Compensating controls** in place, and what residual exposure remains after them
- **Expiry date** — never open-ended; 90 / 180 / 365 days by severity
- **Approver at the right level** — approval authority scales with severity: Low → service owner; Medium → director; High → CISO or VP; Critical → CISO plus business exec, sometimes with audit or risk committee notification
- **Conditions that void the acceptance** (e.g. "if this becomes internet-facing, acceptance lapses")
- Re-review trigger and process

**Key principles:**
- The **business owner accepts risk, not security.** Security frames, quantifies, recommends, documents. If security signs the acceptance, security owns the breach.
- Acceptance must be **as hard as remediation, but not harder** — if the process is too painful, people stop reporting risks. If it is too easy, everything gets accepted.
- Track **acceptance aging and volume as a KRI** — a spike in acceptances is a signal that remediation capacity is under-resourced.
- **Compensating control** vs **mitigating control**: compensating = an alternative that meets the *intent* of a requirement that cannot be met literally (a PCI concept, formalised in the Customized Approach in 4.0.x); mitigating = anything that reduces the risk.

---

## 5. Policy hierarchy

- **Policy** — mandatory, high-level, "what and why," approved by leadership, rarely changes. ("All production data at rest shall be encrypted.")
- **Standard** — mandatory, specific, technology-bound. ("AES-256; KMS-managed keys; rotation ≤ 365 days.")
- **Procedure** — step-by-step "how," role-assigned.
- **Guideline** — recommended, not mandatory.
- **Playbook / runbook** — operational, scenario-triggered sequence (e.g. "Risk intake from a pentest report," "High-risk acceptance escalation").

These are auditable artefacts for ISO 27001 and SOC 2 — the ISMS and control environment require documented and *approved* policies, reviewed at a defined cadence, with evidence of communication.

---

# PART II — FRAMEWORKS

## 6. NIST Cybersecurity Framework 2.0

Released **February 2024**, replacing 1.1. Voluntary, outcome-based, sector-agnostic, and explicitly no longer "critical infrastructure only."

**Six Functions:**

| Function | What it covers |
|---|---|
| **GOVERN (GV)** | *New in 2.0.* Risk management strategy, roles and responsibilities, policy, oversight, supply chain risk management. Wraps the other five. |
| **IDENTIFY (ID)** | Asset management, risk assessment, improvement |
| **PROTECT (PR)** | Identity and access, awareness, data security, platform security, resilience |
| **DETECT (DE)** | Continuous monitoring, adverse event analysis |
| **RESPOND (RS)** | Incident management, analysis, reporting, mitigation |
| **RECOVER (RC)** | Recovery plan execution, communication |

Structure: Functions → **Categories** → **Subcategories** (the actual outcome statements, e.g. `ID.RA-05`). Supported by **Implementation Examples** and **Informative References** (crosswalks to 800-53, ISO, CSA CCM).

**Tiers 1–4** — Partial, Risk Informed, Repeatable, Adaptive. They describe *rigour of risk governance*, **not** a maturity score and **not** a target to max out.

**Profiles** — Current Profile vs Target Profile; the gap between them is the roadmap. **Community Profiles** exist for sectors.

A security risk management function lives primarily in **GOVERN** and in **ID.RA** (risk assessment), and closes the loop by reporting outcomes back to leadership.

## 7. The NIST 800-series ecosystem

| Document | Purpose |
|---|---|
| **SP 800-39** | Enterprise risk management. Four steps: **Frame → Assess → Respond → Monitor.** Three tiers: Organisation / Mission-Business Process / Information System. |
| **SP 800-30 Rev 1** | *Guide for Conducting Risk Assessments.* The methodology: threat sources, threat events, vulnerabilities, predisposing conditions, likelihood, impact, risk. Includes the semi-quantitative tables. The default methodology citation. |
| **SP 800-37 Rev 2 (RMF)** | Lifecycle: **Prepare → Categorize → Select → Implement → Assess → Authorize → Monitor.** |
| **SP 800-53 Rev 5** | The control catalogue — 20 families, ~1,000+ controls. |
| **SP 800-53B** | Control **baselines**: Low / Moderate / High plus a privacy baseline. |
| **SP 800-53A** | Assessment procedures — *how to test* each control. |
| **SP 800-137** | Information Security Continuous Monitoring (ISCM). |
| **SP 800-161 Rev 1** | Cyber supply chain risk management (C-SCRM). |
| **SP 800-171** | Protecting CUI in non-federal systems. |
| **AI RMF 1.0** | GOVERN / MAP / MEASURE / MANAGE — the reference for AI risk governance. |

**800-53 Rev 5 families:** AC (Access Control), AT (Awareness and Training), AU (Audit and Accountability), CA (Assessment, Authorization and Monitoring), CM (Configuration Management), CP (Contingency Planning), IA (Identification and Authentication), IR (Incident Response), MA (Maintenance), MP (Media Protection), PE (Physical and Environmental), PL (Planning), **PM (Program Management)**, PT (PII Processing and Transparency), **RA (Risk Assessment)**, SA (System and Services Acquisition), SC (System and Communications Protection), SI (System and Information Integrity), **SR (Supply Chain Risk Management)**, PS (Personnel Security).

Rev 5 changes: added **SR** and **PT** families, made controls outcome-based and "federal-neutral," integrated privacy controls rather than bolting them on.

The **RA family** is the operational home of a risk function: RA-1 policy, RA-2 categorization, RA-3 risk assessment, RA-5 vulnerability monitoring and scanning, RA-7 **risk response** (the acceptance and mitigation decision), RA-9 critical component identification, RA-10 threat hunting.

## 8. ISO/IEC 27001:2022 and companion standards

**Clauses 4–10 are the mandatory ISMS requirements** (Annex A is not the standard itself — a common misconception):
- **4** Context of the organisation — interested parties, scope
- **5** Leadership — policy, roles, commitment
- **6** Planning — **6.1.2 risk assessment**, **6.1.3 risk treatment plus Statement of Applicability**, 6.2 objectives, 6.3 change planning (new in 2022)
- **7** Support — resources, competence, awareness, communication, documented information
- **8** Operation — 8.2 perform risk assessments, 8.3 implement treatment plan
- **9** Performance evaluation — monitoring and measurement, **9.2 internal audit**, **9.3 management review**
- **10** Improvement — nonconformity and corrective action, continual improvement

**Annex A 2022: 93 controls in 4 themes** (down from 114 in 14 domains):
- Organizational (37) · People (8) · Physical (14) · Technological (34)

**11 new controls in 2022:** threat intelligence (5.7), information security for use of cloud services (5.23), ICT readiness for business continuity (5.30), physical security monitoring (7.4), configuration management (8.9), information deletion (8.10), data masking (8.11), data leakage prevention (8.12), monitoring activities (8.16), web filtering (8.23), secure coding (8.28).

Also new: **control attributes** (control type, information security properties, cybersecurity concepts aligned to CSF, operational capabilities, security domains) — these enable filtering and crosswalking.

**Statement of Applicability (SoA)** — the bridge document: every Annex A control, whether it applies, justification for inclusion or exclusion, and implementation status. Auditors live in this document.

**Certification cycle:** Stage 1 (documentation readiness) → Stage 2 (implementation audit) → surveillance audits years 1 and 2 → recertification year 3. **Nonconformities:** major (systemic or absent control, blocks certification) vs minor (isolated lapse) vs observation / OFI.

**Related standards:**
- **ISO 31000** — generic enterprise risk management principles
- **ISO/IEC 27005:2022** — guidance on information security risk management (the assessment methodology companion)
- **ISO/IEC 27002:2022** — implementation guidance for the Annex A controls
- **ISO/IEC 27017 / 27018** — cloud security / PII in public cloud
- **ISO/IEC 27701** — privacy information management (PIMS) extension
- **ISO/IEC 27036** — supplier relationships
- **ISO/IEC 42001** — AI management system

## 9. SOC 2

American, attestation-based, governed by the **AICPA** under **SSAE 18 / SSAE 21**. Performed by a **licensed CPA firm**, not a certification body — the output is an **opinion**, not a certificate.

**Trust Services Criteria (TSC):**
- **Security** (the "Common Criteria") — **always required**
- Availability
- Processing Integrity
- Confidentiality
- Privacy

The Common Criteria are **CC1–CC9**, aligned to the **COSO** framework's 17 principles:
CC1 control environment · CC2 communication and information · CC3 risk assessment · CC4 monitoring activities · CC5 control activities · CC6 logical and physical access · CC7 system operations · CC8 change management · CC9 risk mitigation.

**CC3 and CC9 are the core mapping for a risk management function.** CC3 requires the entity to specify objectives, identify and analyse risk, consider fraud, and assess significant change. CC9 covers risk mitigation and vendor / business-partner risk.

**Type I vs Type II:**
- **Type I** — design of controls at a *point in time*
- **Type II** — design *and operating effectiveness* over a *period* (typically 3–12 months). Type II is what customers demand.

**Key terms:**
- **CUEC** (Complementary User Entity Controls) — things the *customer* must do for the controls to work. Central to any SaaS or CCaaS vendor.
- **CSOC** (Complementary Subservice Organization Controls) — controls at underlying providers (GCP / AWS).
- **Carve-out vs inclusive method** — whether subservice organisations are excluded from or included in the report scope.
- **Bridge letter / gap letter** — covers the period between the end of the report window and today.
- **Opinion types** — unqualified (clean), qualified (exceptions), adverse, disclaimer.
- **Exception** — a control instance that failed testing; needs management response.

**SOC 1 vs SOC 2 vs SOC 3:** SOC 1 = financial reporting controls (ICFR); SOC 2 = TSC, restricted distribution; SOC 3 = public-facing summary of a SOC 2.

## 10. PCI DSS

**Current version: v4.0.1** — a minor revision of 4.0 (clarifications and corrections rather than new requirements). All previously "future-dated" requirements became mandatory on **31 March 2025**, so every requirement is now in scope and needs a full period of operational evidence.

**Structure: 6 goals, 12 requirements**
1. Install and maintain network security controls
2. Apply secure configurations
3. Protect stored account data
4. Protect cardholder data with strong cryptography during transmission
5. Protect all systems and networks from malicious software
6. Develop and maintain secure systems and software
7. Restrict access by business need to know
8. Identify users and authenticate access
9. Restrict physical access
10. Log and monitor all access
11. Test security of systems and networks regularly
12. Support information security with organisational policies and programs

**Concepts that matter for a risk role:**
- **CDE** (Cardholder Data Environment) — scope is everything. Anything that stores, processes, or transmits CHD, *or can affect the security of* the CDE, is in scope. **Segmentation reduces scope**, and segmentation must be validated by penetration testing (Req 11.4.5).
- **CHD vs SAD** — Cardholder Data (PAN, name, expiry, service code) vs Sensitive Authentication Data (full track, CVV, PIN). **SAD must never be stored after authorisation.**
- **Defined approach vs Customized Approach** — 4.0's biggest structural change. The Customized Approach lets an entity meet a requirement's *objective* by other means, but it **mandates a documented targeted risk analysis and is assessed accordingly**.
- **Targeted Risk Analysis (TRA)** — Req 12.3.1 requires a documented risk analysis for each requirement that allows flexibility in frequency.
- **Validation artefacts** — **SAQ** (self-assessment, several types by merchant channel), **ROC** (Report on Compliance, done by a **QSA** or ISA), **AOC** (Attestation of Compliance). **ASV** scans quarterly by an approved vendor; internal scans quarterly and after significant change; annual internal and external penetration testing (Req 11.4).
- **Notable 4.x controls:** MFA for all access into the CDE (8.4.2) and for all system and application accounts (8.6), 12-character minimum passwords (8.3.6), client-side script management and payment page change-detection (6.4.3 and 11.6.1 — a direct answer to Magecart), authenticated internal scanning (11.3.1.2), automated log review, and a shift from annual snapshot to **business-as-usual continuous control operation**.

**Why PCI matters in a contact centre:** agents take card payments over the phone. That drags the telephony platform, call recording, screen recording, agent desktops, and the IVR into scope unless controlled with **DTMF masking / suppression**, **pause-and-resume recording**, or redirect-to-IVR payment flows.

## 11. Crosswalks and control mapping

Frameworks are not implemented in parallel — controls are mapped once and tested once.

- **NIST CSF 2.0 Informative References** — the official crosswalk to 800-53, ISO 27001, CSA CCM.
- **Secure Controls Framework (SCF)** — a free "metaframework" mapping hundreds of authoritative sources to one control set.
- **CSA Cloud Controls Matrix (CCM) v4** — cloud-specific control framework with mappings; paired with **CAIQ** (the questionnaire) and the **STAR Registry**.
- **OSCAL** (Open Security Controls Assessment Language) — NIST's machine-readable format for catalogues, profiles, SSPs, assessment plans, and results. The foundation for compliance-as-code at scale.
- **CIS Controls v8.x** and **CIS Benchmarks** — prioritised safeguards and hardening baselines; benchmarks are the practical config standard for cloud and OS.

The operative concept is *one control, many labels.* MFA on admin access satisfies 800-53 IA-2, ISO A.8.5, SOC 2 CC6.1, and PCI 8.4 / 8.6 simultaneously. A mature program maintains a **unified control framework** with framework tags, collects evidence once, and reuses it across audits.

---

# PART III — THE TECHNICAL SURFACE

## 12. Vulnerability management → risk management pipeline

Familiarity with vulnerability management is part of the role — but the operational question is about the **feed** into risk management, not the mechanics of scanning.

### 12.1 The signals
- **CVE** — the identifier. Assigned by CNAs, published via NVD. NVD enrichment backlogs have been a real operational issue, so mature teams pull from multiple sources (vendor advisories, OSV, GitHub Advisory DB, and in the EU, **ENISA's EUVD**).
- **CVSS** — *severity*, not risk. v3.1 is still widespread; **v4.0** is the current version and adoption is ongoing. v4.0 changes: base metrics split attacker-side vs system-side, **Subsequent System** impact metrics (replacing "Scope"), a proper **Threat** metric group with **Exploit Maturity** (Attacked / POC / Unreported / Not Defined), **Supplemental** metrics (Safety, Automatable, Recovery, Value Density, Provider Urgency), and the nomenclature CVSS-B / BT / BE / BTE.
- **EPSS** — probability a CVE will be exploited in the wild in the next 30 days, from FIRST. Updated daily. Effective for triage at scale; the current generation is v4.
- **CISA KEV** — catalogue of vulnerabilities with *confirmed* in-the-wild exploitation. Binary signal, highest confidence.
- **SSVC** — Stakeholder-Specific Vulnerability Categorization. A **decision tree** rather than a score: inputs like exploitation status, exposure, automatable, mission or wellbeing impact → outputs **Track / Track\* / Attend / Act**. Increasingly the mature alternative to score-sorting.

### 12.2 The correct prioritisation order

> **Confirmed exploitation (KEV) → exploit likelihood (EPSS) → technical severity (CVSS) → adjusted for asset exposure, business criticality, data sensitivity, and compensating controls.**

Illustration: a CVSS 9.8 on an air-gapped internal box with EPSS 0.02% loses to a CVSS 6.5 internet-facing bug with EPSS 60% every time. Sorting by CVSS alone means sorting by hypothetical worst case with infinite capacity assumed.

### 12.3 The feed into the register
Individual CVEs do **not** belong in a risk register. What belongs is:
- **Systemic risks** revealed by the vuln data: *"Patch SLA compliance for internet-facing production is 62% because ownership of three legacy services is unassigned."*
- **Aggregated exposure**: *"Recurring critical findings in the acquired platform's container base images due to no golden-image pipeline."*
- **Accepted deviations**: a service that cannot be patched due to a vendor dependency → risk acceptance with compensating controls and expiry.

Metrics that bridge the two: SLA attainment by severity, **mean time to remediate (MTTR)** by severity and asset class, backlog aging, recurrence rate (same finding returning = process failure, not a patching failure), scanner and asset coverage %, and % of KEV entries closed within the mandated window.

## 13. Cloud risk

### 13.1 Shared responsibility
- **IaaS** — provider owns hardware, hypervisor, physical, network fabric; customer owns OS, patching, config, IAM, data, application.
- **PaaS** — provider extends to runtime and middleware; customer owns config, identity, data, code.
- **SaaS** — provider owns nearly all of it; customer owns identity, access governance, data classification, tenant configuration, and integrations.
- **Constant across all three:** the customer always owns their data, their identities, and their configuration.

A SaaS or CCaaS vendor sits on the *provider* side of that line, which raises **CUECs**, tenant isolation, and multi-tenancy risk.

### 13.2 The risk classes that actually cause incidents
- **Identity and entitlement sprawl** — over-permissive roles, wildcard policies, long-lived static keys, unused service accounts, cross-account trust, privilege escalation paths (e.g. `iam:PassRole` chains, GCP service-account impersonation).
- **Public exposure by misconfiguration** — open storage buckets, permissive security groups or firewall rules, publicly reachable management planes, exposed metadata services (**SSRF → IMDS** — IMDSv2 / metadata concealment).
- **Missing or unmonitored logging** — CloudTrail / Cloud Audit Logs / Azure Activity Log not enabled, not centralised, or not retained.
- **Weak key and secret management** — hardcoded secrets in repos and CI, unmanaged KMS keys, absent rotation.
- **Insecure CI/CD and supply chain** — over-privileged pipeline identities, unsigned artefacts, dependency confusion, unreviewed IaC.
- **Network architecture** — flat VPCs, no egress control, no segmentation between environments, absent private connectivity to managed services (VPC Service Controls / PrivateLink / Private Endpoints).
- **Data governance** — unclassified data, uncontrolled replication across regions (a **residency** problem in the EU), unmanaged snapshots and backups.
- **Drift** — a state that was compliant at build time and is not now. Argues for continuous rather than periodic assessment.

### 13.3 Tooling categories
- **CSPM** — Cloud Security Posture Management: misconfiguration and compliance-baseline detection.
- **CWPP** — Cloud Workload Protection: VMs, containers, serverless runtime security.
- **CIEM** — Cloud Infrastructure Entitlement Management: identity and permission risk, least-privilege analysis.
- **CNAPP** — the consolidated platform (CSPM + CWPP + CIEM + IaC scanning + often ASPM).
- **SSPM** — SaaS Security Posture Management (Okta / Workspace / Salesforce tenant config).
- **DSPM** — Data Security Posture Management: where sensitive data actually lives.
- **KSPM** — Kubernetes posture.
- **Policy-as-code** — **OPA/Rego**, AWS SCPs, **GCP Organization Policy**, Azure Policy; preventive guardrails rather than detective findings.
- Native services: **AWS Security Hub / GuardDuty / Config / Access Analyzer**, **GCP Security Command Center / Policy Intelligence / Recommender**, **Microsoft Defender for Cloud**.

In practice, CSPM produces thousands of findings. Risk management does not act on them individually — it converts their *patterns* into a small number of owned, tracked, quantified risks, and pushes the recurring ones back into preventive guardrails so the finding class stops existing.

### 13.4 Acquisitions and integration

**Pre-close due diligence:** breach history, certifications and audit reports, architecture and data flows, third parties, regulatory exposure, IP and code provenance, insurance, open litigation. Constraint: limited access, limited time, often no hands-on testing allowed.

**Post-close integration risks:** unknown asset inventory, no shared identity (federation debt), differing patch and logging standards, unmanaged shadow IT, inherited technical debt and end-of-life systems, culture mismatch, contractual commitments the acquired entity made that the parent must now honour, data commingling versus data segregation obligations, and **scope contamination** — an acquired platform can drag the parent's PCI, SOC 2, or ISO scope wider.

**A working playbook:** rapid baseline assessment in the first 30/60/90 days → all findings enter the *same* register with an "acquisition" tag → time-boxed integration roadmap with a named integration risk owner → temporary risk acceptances with hard expiry while integration proceeds → exit criteria for declaring the entity "in-standard."

---

# PART IV — RUNNING THE PROGRAM

## 14. Jira as a risk workflow engine

Many programs run the Security Risk Register in Jira. The mechanics matter.

**Concepts:**
- **Project types** — Jira Software (team-managed vs company-managed) vs **Jira Service Management** (request portal, SLAs, approvals — often better for intake and acceptance workflows).
- **Issue types and schemes** — a custom `Risk` issue type, plus `Risk Acceptance` and `Exception` types, each with its own screen scheme and field configuration.
- **Custom fields** — likelihood (select), impact (select), inherent score (calculated or scripted), residual score, risk owner (user picker), treatment option, framework mapping (multi-select), review date, acceptance expiry, business unit, affected service.
- **Workflow** — statuses and transitions: `Identified → Assessing → Awaiting Owner → Treatment Planned → In Treatment → Monitoring → Accepted → Closed`, with **conditions** (who can transition), **validators** (mandatory fields on transition — e.g. cannot move to Accepted without an approver and expiry), and **post-functions** (auto-set review dates, notify).
- **Approvals** — native in JSM; in Jira Software usually implemented with a status plus a required approver field.
- **Issue linking** — the risk links to the engineering tickets that treat it (`is blocked by` / `relates to`), so treatment progress is real, not narrated.
- **JQL** — the query language. Example queries a risk lead uses daily:
  - `project = RISK AND issuetype = Risk AND "Residual Score" >= 15 AND status != Closed ORDER BY "Residual Score" DESC`
  - `"Acceptance Expiry" <= 30d AND status = Accepted`
  - `status = "Awaiting Owner" AND created <= -14d`
- **Automation for Jira** — rules to auto-escalate overdue treatments, notify on approaching acceptance expiry, auto-create the quarterly review task, re-open a risk when its linked remediation ticket is closed without evidence.
- **Dashboards and gadgets**, plus **Atlassian Analytics** or an external BI tool for executive views. **Confluence** for the narrative artefacts (methodology, policy, acceptance records, meeting minutes).
- **REST API** (`/rest/api/3/`) — the automation surface. Token auth, JQL search, bulk field updates, webhooks.

The strategic point is that a register living in Jira alongside engineering work is *the* reason risks get fixed. A register in a spreadsheet is a document; a register in Jira is a **workflow**. Engineers already live there.

**Trade-offs to note:** Jira was not built as a GRC tool. Weaknesses are audit-trail immutability, complex scoring logic, evidence retention, and cross-framework mapping. These are compensated with strict field validation, restricted transitions, snapshotting for point-in-time reporting, and API exports to a data layer.

## 15. Metrics, dashboards, executive reporting

**Design principle:** every metric should answer *"what do we do differently based on this?"* If nothing changes based on the number, delete it.

**Program health (KPIs):**
- % of risks with a named individual owner
- Mean time from identification → assessment → treatment decision
- Mean time to closure by severity
- % of treatment plans on schedule / overdue
- Risk review currency (% reviewed within cadence)
- Register growth vs closure rate (burn-down / burn-up)

**Exposure (KRIs):**
- Count and aggregate score of open High and Critical risks, trended
- Aggregate residual exposure in € (where quantified)
- Open risk acceptances: count, aging, and total exposure accepted
- % of production services covered by an assessment in the last N months
- Concentration: which service, BU, or framework domain holds the most risk
- Exception volume trend (a proxy for remediation capacity)

**Presentation rules for executives:**
- Lead with **trend and decision**, not with the register.
- Three questions every exec slide must answer: *Are we getting better or worse? What is the biggest thing that could hurt us? What do you need to decide today?*
- Use **money, time, and customer impact** as units. Never CVSS scores.
- **Top N risks** with one-line scenarios, owner, and status — not a 200-row table.
- Show **what changed since last quarter**, and attribute it.
- Distinguish clearly: *"this is what has been accepted on your behalf, and here is the expiry."* Executives should never be surprised by an acceptance.
- Heat maps are fine for the middle layer but dangerous at board level (false precision). Loss-exceedance curves or a simple trended exposure line are stronger.

**Audience laddering:** engineer → concrete finding, reproduction, fix; service owner → what it costs to fix vs to carry, and the deadline; director → aggregate risk in their area vs tolerance; exec or board → capital allocation and accountability.

## 16. Python and automation for GRC

Modern security risk teams automate the mechanics. A working knowledge of Python and agentic coding tools is now standard.

**What can realistically be automated:**
- **Jira REST API work** — bulk register hygiene, auto-recalculating residual scores, generating the monthly review queue, closing stale items, syncing external tool findings into risk tickets. Libraries: `requests`, `atlassian-python-api`, `jira`.
- **Reporting pipelines** — `pandas` for aggregation, `matplotlib` or `plotly` for charts, `jinja2` plus `weasyprint` for templated PDF risk reports, or push to a BI tool. Replaces the monthly manual deck.
- **Evidence collection** — `boto3`, `google-cloud-*`, Azure SDK to pull configuration state and IAM snapshots as audit evidence on a schedule.
- **Ingesting scanner and CSPM output** — normalise, deduplicate, correlate to asset inventory, enrich with EPSS or KEV via API, and raise aggregated risks rather than per-finding noise.
- **Control testing as code** — scheduled checks that assert a control is operating, producing a pass or fail record with a timestamp (the essence of continuous control monitoring).
- **Policy-as-code** — OPA/Rego or cloud-native policy to make a class of risk structurally impossible.
- **OSCAL** — machine-readable control catalogues, profiles, and assessment results for framework mapping at scale.

**Agentic coding tools:**
- What they are: LLM-backed assistants that read a repository or context and write, refactor, and run code — **Cursor** (IDE), **Claude Code** (terminal / agentic), **GitHub Copilot** (inline plus agent modes).
- Where they help a security engineer: scaffolding API integrations fast, writing throwaway data-wrangling scripts, generating test coverage, translating a control requirement into a check.
- **Governance angle:** review everything before it runs, never paste customer data or secrets into a tool without knowing the data-handling terms, keep generated code in review or PR flow, treat generated IaC as untrusted until scanned, and be aware of the risk classes — prompt injection via repo content, dependency hallucination (a real supply-chain vector — "slopsquatting"), and over-trust in unreviewed output.

## 17. Domain context: SaaS and CCaaS

**CCaaS** = Contact Center as a Service. Cloud-delivered voice and digital customer interaction: inbound and outbound routing (ACD), IVR, dialers, omnichannel (voice, chat, email, SMS), workforce optimisation, CRM integrations (Salesforce, ServiceNow, Zendesk), analytics, and increasingly AI agents. The major players in this space increasingly position themselves as **AI-native CX platforms** with proprietary AI suites for agent assistance, summarisation, and virtual agents.

**Risk themes specific to this environment:**
- **Multi-tenancy and tenant isolation** — the highest-consequence architectural risk in any SaaS; a cross-tenant data leak is existential.
- **Voice and recording data** — call recordings and transcripts are PII, sometimes special-category, and **voiceprints may be biometric data** under GDPR Art. 9 and laws like Illinois BIPA. Retention, access control, and consent are hard problems.
- **PCI in the call flow** — as covered in §10; DTMF masking, pause-and-resume, IVR redirect, agent desktop scope.
- **Availability as a security property** — a contact centre outage stops the customer's business. Availability belongs in the register and is a SOC 2 TSC.
- **Telephony-specific abuse** — toll fraud, traffic pumping, SIP trunk abuse, caller-ID spoofing, **vishing and deepfake voice** against agents, and the **STIR/SHAKEN** call-authentication framework.
- **Regulatory surface** — GDPR (data residency for EU customers), ePrivacy, call-recording consent laws that vary by jurisdiction, TCPA for outbound dialing in the US, sector rules where customers are in healthcare or finance (HIPAA BAAs, financial-sector obligations).
- **Integration and API risk** — CRM connectors, webhooks, partner apps, and marketplace integrations widen the trust boundary considerably.
- **Agent endpoint and insider risk** — thousands of low-privilege agents with access to customer PII; screen capture, exfil, and social engineering.
- **AI and LLM risk** — prompt injection, training or inference data leakage, hallucinated responses to customers, model supply chain, agentic actions taken on a customer's behalf, bias, and explainability. Governance references: **OWASP Top 10 for LLM Applications**, **MITRE ATLAS**, **NIST AI RMF 1.0**, **ISO/IEC 42001**, **EU AI Act**.

## 18. Adjacent domains

- **Third-party and vendor risk (TPRM)** — inherent-risk tiering, due diligence depth by tier, SIG or CAIQ questionnaires, reviewing SOC 2 reports properly (scope, period, exceptions, CUECs, subservice treatment), contractual security terms, right-to-audit, continuous monitoring, and offboarding. Fourth-party and concentration risk.
- **BCDR** — **BIA** determining **RTO** (recovery time), **RPO** (data loss tolerance), **MTD / MTPD**; DR testing evidence; ISO A.5.29 / 5.30 and SOC 2 Availability criteria.
- **Incident response linkage** — incidents are a risk-identification source; post-incident reviews should generate register entries, and the register should predict where incidents will occur. Also GDPR's 72-hour notification and, in the EU, **NIS2** and **DORA** where relevant to customers.
- **Change and configuration management** — SOC 2 CC8, ISO A.8.9, PCI Req 6. Unmanaged change is a top root cause.
- **Asset and data inventory** — the foundation. Risk cannot be assessed on assets that cannot be enumerated; "% of production services with a named owner" is often the highest-value KRI a new risk lead can introduce.

---

# PART V — OPERATING THE PROGRAM

## 19. Diagnostic questions to ask about an existing risk program

- How mature is the register today — is it a findings backlog or a scenario-based register?
- Who currently accepts risk, and at what thresholds? Is there a documented approval matrix?
- How does an acquisition's risk get onboarded — same register, or a parallel process?
- What is the relationship between this team and vulnerability management — does it own the SLAs, or influence them?
- What does risk reporting look like at the executive level today, and what should it look like?
- Is the program quantitative anywhere, or fully qualitative? Is there appetite for FAIR on the top risks?
- What is the automation ambition — Jira automation, or pipelines and control-testing-as-code?
- How is AI risk currently governed, and does it sit in this register?

## 20. Core concepts to master

The competencies below define fluency in security risk management. Each should be explainable in plain language, without notes.

1. Inherent vs current vs residual vs target risk
2. Risk appetite vs tolerance vs capacity
3. Why multiplying ordinal likelihood × impact is mathematically dubious, and what to do about it
4. ALE, SLE, ARO, EF — with a worked example
5. The FAIR decomposition and what a loss exceedance curve tells an executive
6. The fields that make a risk register entry actionable
7. The four treatment options, with an example of each from a SaaS context
8. What a defensible risk acceptance record contains, and who signs it
9. NIST CSF 2.0's six functions and why GOVERN was added
10. NIST 800-30 vs 800-37 vs 800-39 vs 800-53 — the role of each
11. ISO 27001 clauses 4–10 vs Annex A, and the purpose of the SoA
12. SOC 2 Type I vs Type II; the requirements of CC3 and CC9; what a CUEC is
13. PCI DSS: CDE scoping, SAD vs CHD, Customized Approach, targeted risk analysis, and why a contact centre is in scope
14. KEV vs EPSS vs CVSS vs SSVC, and the correct prioritisation order
15. Shared responsibility across IaaS / PaaS / SaaS — and what is constant
16. CSPM vs CWPP vs CIEM vs CNAPP
17. How a CSPM's 5,000 findings become 6 risk register entries
18. How to model a risk register in Jira: issue types, fields, workflow, validators, JQL
19. Six metrics that belong on a CISO dashboard and the decision each one drives
20. A first-90-days plan for a risk program at a SaaS company that has been acquiring
21. How to assess and integrate an acquired platform's risk
22. Three risks specific to an AI-powered contact centre, and how to treat them
23. How to explain a critical cloud IAM risk to (a) the engineer, (b) the VP of Engineering, (c) the CFO
24. How to use agentic coding tools safely on a security team

## 21. A first-90-days plan for a new risk lead

**Days 1–30 — understand and stabilise.** Read the existing register, the SoA, the last SOC 2 and any PCI ROC or AOC, the vuln management SLAs, and the last two quarters of exec reporting. Meet every service owner. Identify the risks with no owner and the acceptances with no expiry. Deliver a baseline: register health metrics and the top 10 risks as they stand.

**Days 31–60 — make it repeatable.** Publish a documented assessment methodology and scoring rubric so scoring stops being personal. Rebuild the Jira workflow with validators so a risk cannot exist without an owner, a treatment decision, and a review date. Establish the risk acceptance process with an approval matrix and mandatory expiry. Start the intake pipeline from vuln management, pentest, and audit into a single front door.

**Days 61–90 — make it scale and land it upward.** Automate the reporting pack so it generates rather than being assembled. Introduce two or three KRIs the leadership team actually uses. Quantify the top 3–5 risks with a FAIR-style analysis to anchor budget conversations. Propose the acquisition-onboarding playbook. Then show a trend line: what moved, and why.

---

## 22. Note on version currency

Standards move — the versions and dates below reflect a snapshot and should be verified against the primary sources.
- **PCI DSS v4.0.1** is the current active version; all future-dated requirements have been mandatory since 31 March 2025.
- **NIST CSF 2.0** (Feb 2024) is current; **800-53 Rev 5**, **800-37 Rev 2**, **800-30 Rev 1**.
- **ISO/IEC 27001:2022** with the 93-control Annex A; the transition from the 2013 edition has closed.
- **CVSS v4.0** is the current version, with v3.1 still widely present in tooling; **EPSS** is on its fourth generation.
- SOC 2 sits under **SSAE 18 / 21** with the 2017 TSC as revised.
