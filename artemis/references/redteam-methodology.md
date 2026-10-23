# GenAI Red Team Methodology

## Table of Contents
1. [Methodology Overview](#methodology-overview)
2. [Pre-Engagement](#pre-engagement)
3. [Four Pillars of Assessment](#four-pillars-of-assessment)
4. [Framework Cross-References](#framework-cross-references)
5. [Severity Scoring with AIVSS](#severity-scoring)
6. [Target Type Decision Matrix](#target-type-decision-matrix)

---

## Methodology Overview

This methodology synthesizes the OWASP GenAI Red Teaming Guide's holistic approach across four assessment pillars: **Model Evaluation**, **Implementation Testing**, **Infrastructure Assessment**, and **Runtime Behavior Analysis**. Each pillar maps to specific OWASP categories and testing procedures.

### Key Differences from Traditional Pentesting

| Aspect | Traditional Pentest | GenAI Red Team |
|--------|-------------------|----------------|
| **Determinism** | Same input → same output (usually) | Same input → variable output (stochastic) |
| **Attack surface** | Network, applications, APIs | Prompts, data pipelines, agent behaviors, embeddings |
| **Scope** | Technical vulnerabilities | Technical + alignment + safety + trust + bias |
| **Tooling** | Burp, Nmap, Metasploit | Custom payloads, prompt libraries, semantic analysis |
| **Success criteria** | Exploit achieved | Behavioral boundary violated |
| **Repeatability** | High | Variable — requires statistical testing |
| **Blast radius** | Contained to target system | May propagate through agent chains, affect users |

### Statistical Testing Requirement

Due to LLM non-determinism, a single test does not constitute proof. For each test case:
- Run minimum **5 attempts** per payload at default temperature
- Run additional attempts at varied temperatures (0.0, 0.5, 1.0) if feasible
- Record **success rate** (e.g., "3/5 attempts bypassed the guardrail")
- Note any behavioral variance across attempts

---

## Pre-Engagement

### Authorization Verification
Before any testing begins, confirm:
- [ ] Written authorization from system owner
- [ ] Scope of engagement documented and signed
- [ ] Rules of engagement (RoE) defined
- [ ] Emergency contacts and escalation paths established
- [ ] Data handling and NDA requirements understood
- [ ] Legal review completed (if applicable)
- [ ] Testing environment specified (production vs. staging)

### Target Classification

Classify the target to determine which assessment modules apply:

| Target Type | LLM Top 10 | Agentic Top 10 | Additional Concerns |
|-------------|------------|----------------|---------------------|
| Foundation Model (API) | LLM01, LLM02, LLM04, LLM09 | N/A | Alignment, bias, toxicity |
| Fine-Tuned Model | All LLM | N/A | Training data quality, poisoning |
| RAG Application | All LLM, especially LLM08 | N/A | Knowledge base security, embedding integrity |
| Chatbot / Assistant | All LLM | N/A | User interaction safety, escalation |
| Tool-Using Agent | All LLM | ASI01-04, ASI06-08 | Tool permissions, action boundaries |
| Multi-Agent System | All LLM | All ASI | Orchestration, delegation, trust boundaries |
| Autonomous Agent | All LLM | All ASI, especially ASI04, ASI10 | Kill-switches, monitoring, blast radius |
| MCP-Connected System | All LLM | ASI02, ASI03, ASI07 | MCP authentication, tool isolation |

### Stakeholder Identification

Per OWASP guidance, engage cross-functional stakeholders:
- **Security/Red Team**: Technical test execution
- **AI/ML Engineering**: Model architecture, known limitations
- **Legal/Compliance**: Regulatory requirements, testing boundaries
- **Ethics/Trust & Safety**: Bias, toxicity, alignment criteria
- **Business/Product**: Acceptable behavior definitions, risk appetite
- **Marketing/PR**: Brand risk thresholds
- **Incident Response**: Escalation procedures if real issues found

---

## Four Pillars of Assessment

### Pillar 1: Model Evaluation
**Focus**: Inherent model-level vulnerabilities
**Timing**: Pre-deployment and post-update
**Categories**: LLM01 (Prompt Injection), LLM02 (Info Disclosure), LLM04 (Poisoning), LLM09 (Misinformation)

Objectives:
- Assess baseline model safety and alignment
- Evaluate robustness to adversarial inputs
- Test for bias, toxicity, and harmful content generation
- Verify training data protection

### Pillar 2: Implementation Testing
**Focus**: Application-layer security controls
**Timing**: Pre-deployment and ongoing
**Categories**: LLM05 (Output Handling), LLM06 (Excessive Agency), LLM07 (System Prompt Leakage), LLM08 (Vector/Embedding)

Objectives:
- Test guardrails and content filters
- Verify input/output validation
- Assess RAG pipeline security
- Evaluate access controls and authorization

### Pillar 3: Infrastructure Assessment
**Focus**: System-level and deployment security
**Timing**: Pre-deployment and periodic
**Categories**: LLM03 (Supply Chain), LLM10 (Unbounded Consumption)

Objectives:
- Audit third-party dependencies and supply chain
- Assess deployment infrastructure security
- Evaluate rate limiting and resource controls
- Verify monitoring and logging

### Pillar 4: Runtime Behavior Analysis
**Focus**: Live system behavior and agent actions
**Timing**: Post-deployment continuous
**Categories**: ASI01-ASI10 (all agentic risks)

Objectives:
- Monitor agent decision-making in production
- Test runtime guardrails and circuit breakers
- Evaluate multi-agent interaction security
- Verify human-in-the-loop effectiveness

---

## Framework Cross-References

### OWASP LLM Top 10 ↔ MITRE ATLAS Mapping

| OWASP LLM | MITRE ATLAS Tactics | Techniques |
|-----------|-------------------|------------|
| LLM01 | Initial Access, Execution | AML.T0051 (LLM Prompt Injection) |
| LLM02 | Exfiltration, Collection | AML.T0024 (Exfiltration via ML Inference API) |
| LLM03 | Initial Access, Supply Chain | AML.T0010 (ML Supply Chain Compromise) |
| LLM04 | Persistence, Impact | AML.T0020 (Poison Training Data) |
| LLM05 | Execution, Lateral Movement | Traditional injection (XSS, SQLi, SSRF) |
| LLM06 | Privilege Escalation, Impact | AML.T0048 (Abuse of Existing Functionality) |
| LLM07 | Reconnaissance, Collection | AML.T0024 (Exfiltration via Inference API) |
| LLM08 | Initial Access, Persistence | AML.T0020 (Poison Training Data) |
| LLM09 | Impact | AML.T0048 (Abuse of Existing Functionality) |
| LLM10 | Impact | Traditional DoS |

### OWASP Agentic Top 10 ↔ STRIDE Mapping

| OWASP ASI | STRIDE Category | Primary Threat |
|-----------|----------------|----------------|
| ASI01 | Tampering, Elevation | Goal/decision manipulation |
| ASI02 | Tampering, Elevation | Tool parameter/chain abuse |
| ASI03 | Spoofing, Elevation | Identity forgery, privilege escalation |
| ASI04 | Tampering, Denial | Uncontrolled destructive actions |
| ASI05 | Spoofing, Info Disclosure | Trust boundary violations |
| ASI06 | Tampering, Repudiation | Memory poisoning, tampering |
| ASI07 | Info Disclosure, Tampering | Communication interception |
| ASI08 | Denial of Service | Cascading system failure |
| ASI09 | Spoofing | Social engineering via agent |
| ASI10 | Elevation, Tampering | Autonomous rogue behavior |

### NIST AI RMF Alignment

| NIST Function | Related Testing |
|--------------|----------------|
| GOVERN | Scoping, stakeholder engagement, policy review |
| MAP | Threat modeling, target classification |
| MEASURE | Assessment execution, statistical testing |
| MANAGE | Reporting, remediation, monitoring guidance |

---

## Severity Scoring

Use the AI Vulnerability Scoring System (AIVSS) adapted from CVSS for AI-specific risks:

### Scoring Factors

| Factor | Description | Scale |
|--------|-------------|-------|
| **Attack Complexity** | Difficulty of executing the attack | Low (0.9) / High (0.5) |
| **Privileges Required** | Authentication level needed | None (0.9) / Low (0.6) / High (0.3) |
| **User Interaction** | Does exploitation require user action? | None (0.9) / Required (0.6) |
| **Scope** | Can the attack affect other components? | Changed (1.2) / Unchanged (1.0) |
| **Confidentiality Impact** | Data exposure severity | High (0.6) / Low (0.2) / None (0.0) |
| **Integrity Impact** | Data/behavior modification severity | High (0.6) / Low (0.2) / None (0.0) |
| **Availability Impact** | Service disruption severity | High (0.6) / Low (0.2) / None (0.0) |
| **AI-Specific: Alignment** | Degree of alignment violation | Severe (0.4) / Moderate (0.2) / None (0.0) |
| **AI-Specific: Scale** | Number of affected users/decisions | Wide (0.3) / Limited (0.1) / None (0.0) |

### Severity Thresholds

| Score Range | Severity |
|------------|----------|
| 9.0 - 10.0 | Critical |
| 7.0 - 8.9 | High |
| 4.0 - 6.9 | Medium |
| 0.1 - 3.9 | Low |
| 0.0 | Informational |

---

## Target Type Decision Matrix

Use this matrix to determine test priority for each engagement:

### Simple LLM Application (Chatbot, Q&A, Summarizer)
**Priority Test Categories (in order):**
1. LLM01 — Prompt Injection (always #1)
2. LLM07 — System Prompt Leakage
3. LLM02 — Sensitive Information Disclosure
4. LLM05 — Improper Output Handling
5. LLM09 — Misinformation
6. LLM10 — Unbounded Consumption
7. LLM03 — Supply Chain
8. LLM04 — Data/Model Poisoning

### RAG Application
**Priority Test Categories (in order):**
1. LLM01 — Prompt Injection (direct + indirect)
2. LLM08 — Vector and Embedding Weaknesses
3. LLM02 — Sensitive Information Disclosure
4. LLM07 — System Prompt Leakage
5. LLM04 — Data/Model Poisoning (RAG knowledge base)
6. LLM05 — Improper Output Handling
7. LLM03 — Supply Chain
8. LLM09 — Misinformation

### Tool-Using Agent
**Priority Test Categories (in order):**
1. ASI01 — Agent Goal Hijacking
2. ASI02 — Tool Misuse and Exploitation
3. LLM01 — Prompt Injection
4. ASI04 — Uncontrolled Agentic Actions
5. ASI03 — Identity and Privilege Abuse
6. LLM06 — Excessive Agency
7. LLM07 — System Prompt Leakage
8. ASI06 — Compromised Agentic Memory

### Multi-Agent / Autonomous System
**Priority Test Categories (in order):**
1. ASI01 — Agent Goal Hijacking
2. ASI05 — Improper Multi-Agent Orchestration
3. ASI10 — Rogue Agents
4. ASI02 — Tool Misuse and Exploitation
5. ASI04 — Uncontrolled Agentic Actions
6. ASI03 — Identity and Privilege Abuse
7. ASI08 — Cascading Failures
8. ASI09 — Human-Agent Trust Exploitation
9. ASI07 — Insecure Agentic Communication
10. ASI06 — Compromised Agentic Memory
11. All LLM categories as applicable
