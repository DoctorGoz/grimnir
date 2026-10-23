# Threat Modeling for Generative AI Systems

## Overview

GenAI threat modeling extends traditional methodologies (STRIDE, PASTA, LINDDUN) with AI-specific considerations from MITRE ATLAS and the OWASP GenAI frameworks. This reference provides structured approaches for identifying, categorizing, and prioritizing threats to AI systems.

---

## Step 1: System Decomposition

### AI System Architecture Components

Map each component of the target system:

```
┌─────────────────────────────────────────────────────────┐
│                    USER INTERFACE LAYER                   │
│  (Web UI, API, Chat, Voice, Mobile App)                 │
├─────────────────────────────────────────────────────────┤
│                 APPLICATION LOGIC LAYER                   │
│  (Input Validation, Session Mgmt, Auth, Rate Limiting)  │
├─────────────────────────────────────────────────────────┤
│                   ORCHESTRATION LAYER                     │
│  (Agent Framework, Tool Router, MCP, Prompt Templates)  │
├─────────────────────────────────────────────────────────┤
│                      MODEL LAYER                          │
│  (Foundation Model, Fine-Tuned Model, Model API)        │
├─────────────────────────────────────────────────────────┤
│                   KNOWLEDGE/DATA LAYER                    │
│  (Vector DB, RAG Pipeline, Training Data, Memory Store) │
├─────────────────────────────────────────────────────────┤
│                    TOOL/ACTION LAYER                      │
│  (Plugins, APIs, Databases, File Systems, External Svcs)│
├─────────────────────────────────────────────────────────┤
│                  INFRASTRUCTURE LAYER                     │
│  (Cloud, Containers, Network, Secrets, Monitoring)      │
└─────────────────────────────────────────────────────────┘
```

### Decomposition Checklist

For each layer, document:
- [ ] Components and their versions
- [ ] Data flows (what data enters and leaves)
- [ ] Trust boundaries (where trust level changes)
- [ ] Authentication/authorization mechanisms
- [ ] External dependencies
- [ ] Access controls
- [ ] Logging and monitoring coverage

---

## Step 2: Threat Identification

### STRIDE for GenAI

Apply STRIDE to each component, with AI-specific threat examples:

#### Spoofing
- Prompt injection impersonating system instructions
- Agent identity impersonation in multi-agent systems
- Fake MCP server connections
- Model API key theft and unauthorized access
- User session hijacking through AI-mediated flows

#### Tampering
- Training/fine-tuning data poisoning
- RAG knowledge base manipulation
- Agent memory corruption
- Embedding vector manipulation
- Tool parameter injection
- Conversation history modification

#### Repudiation
- Lack of audit trail for agent actions
- Missing provenance for AI-generated decisions
- Untraceable tool invocations
- No attribution for multi-agent handoffs
- Inability to reconstruct decision chains

#### Information Disclosure
- System prompt leakage
- Training data extraction
- Cross-tenant data exposure
- PII in model responses
- Credential exposure through prompts
- RAG data unauthorized access
- Agent memory content exposure

#### Denial of Service
- Context window exhaustion
- Unbounded token generation
- Cascading agent failures
- Rate limit bypass
- Resource-intensive query patterns
- Vector database overload

#### Elevation of Privilege
- Agent privilege escalation through tool chaining
- Permission amplification in multi-agent delegation
- Role boundary bypass through prompt manipulation
- Unauthorized tool access through goal hijacking
- Admin function access through conversational manipulation

---

### MITRE ATLAS Tactics for GenAI

Map discovered threats to ATLAS tactics:

| ATLAS Tactic | Description | Relevant OWASP Categories |
|-------------|-------------|--------------------------|
| **Reconnaissance** | Gathering info about the AI system | LLM07 (System Prompt Leakage) |
| **Resource Development** | Preparing attack resources | LLM03 (Supply Chain) |
| **Initial Access** | Gaining entry to AI system | LLM01 (Prompt Injection), ASI01 (Goal Hijack) |
| **ML Model Access** | Accessing the model directly | LLM02 (Info Disclosure) |
| **Execution** | Running adversarial techniques | ASI02 (Tool Misuse), LLM05 (Output Handling) |
| **Persistence** | Maintaining access | ASI06 (Memory), LLM04 (Poisoning) |
| **Privilege Escalation** | Gaining higher access | ASI03 (Identity/Privilege), LLM06 (Agency) |
| **Defense Evasion** | Bypassing security controls | LLM01 (encoding tricks, multi-turn) |
| **Collection** | Gathering target data | LLM02 (Info Disclosure), LLM08 (Embedding) |
| **Exfiltration** | Extracting data from AI system | ASI02 (Tool chain exfil), LLM02 |
| **Impact** | Causing harm via AI system | ASI04 (Uncontrolled Actions), ASI08 (Cascading) |

---

## Step 3: Risk Assessment

### OWASP Five Threat Categories

The OWASP GenAI Red Teaming Guide groups all threats into five categories:

1. **Adversarial Attacks**: External threats exploiting system vulnerabilities
   - Prompt injection (direct and indirect)
   - Goal hijacking in agentic systems
   - Model extraction and theft
   - Evasion attacks against safety filters

2. **Alignment Risks**: AI outputs that violate organizational values
   - Harmful content generation
   - Biased or discriminatory outputs
   - Brand-damaging responses
   - Unauthorized commitments or promises

3. **Data Risks**: Threats to data confidentiality, integrity, availability
   - Training data exposure
   - PII leakage
   - Knowledge base compromise
   - Cross-tenant data bleed

4. **Interaction Risks**: Harmful behavior in user-AI interactions
   - Social engineering through AI
   - Manipulation of human trust
   - Inappropriate emotional engagement
   - Dangerous advice or instructions

5. **Knowledge Risks**: Misinformation, hallucination, and unreliability
   - Confident hallucinations on critical topics
   - Fabricated citations and sources
   - Outdated or incorrect information
   - Inconsistent responses to same query

### Risk Priority Matrix

Score each identified threat:

| Factor | Score Range | Description |
|--------|-----------|-------------|
| **Likelihood** | 1-5 | How probable is exploitation? |
| **Impact** | 1-5 | How severe would exploitation be? |
| **Detectability** | 1-5 | How difficult is it to detect? (5 = hardest) |

**Risk Score** = Likelihood × Impact × Detectability

| Score Range | Priority | Action |
|------------|----------|--------|
| 75-125 | Critical | Immediate testing and remediation |
| 40-74 | High | Priority testing in current engagement |
| 15-39 | Medium | Include in assessment if time permits |
| 1-14 | Low | Document for future consideration |

---

## Step 4: Threat Model Documentation

### Template for Each Threat

```markdown
## Threat: [ID] — [Title]

**Category**: Adversarial / Alignment / Data / Interaction / Knowledge
**STRIDE**: S / T / R / I / D / E
**ATLAS Tactic**: [Tactic ID]
**OWASP Reference**: [LLM## / ASI##]

**Description**: [What the threat is]
**Attack Vector**: [How it would be exploited]
**Affected Component**: [Which system component]
**Preconditions**: [What must be true for attack to work]

**Likelihood**: [1-5] — [Justification]
**Impact**: [1-5] — [Justification]
**Detectability**: [1-5] — [Justification]
**Risk Score**: [Calculated]

**Existing Controls**: [What's currently in place]
**Recommended Tests**: [Which test procedures to run]
**Recommended Mitigations**: [What should be implemented]
```

---

## Step 5: Data Flow Diagrams for AI

### DFD Elements for AI Systems

In addition to standard DFD elements, include:

- **Prompt Flow**: How user input becomes model input (mark injection points)
- **Retrieval Flow**: How data moves from knowledge bases to model context
- **Tool Invocation Flow**: How the model triggers external actions
- **Agent Delegation Flow**: How tasks pass between agents
- **Memory Flow**: How information persists across interactions
- **Training/Fine-Tuning Flow**: How data enters the model
- **Feedback Flow**: How user interactions influence future behavior

### Trust Boundary Identification

Mark trust boundaries at every point where:
- User input enters the system
- Data passes from untrusted to trusted context
- Agent-to-agent communication occurs
- Tool invocations cross system boundaries
- Data moves between tenants or security domains
- Model output is rendered or executed
- External data enters the RAG pipeline

Each trust boundary is a priority point for security testing.

---

## Quick Reference: Threat Model Kickstart Questions

Answer these to rapidly scope your threat model:

1. What type of AI system is this? (chatbot, agent, multi-agent, RAG, etc.)
2. What data does it have access to? (public, internal, PII, classified)
3. What actions can it take? (read-only, write, transact, communicate externally)
4. Who interacts with it? (public users, employees, other agents)
5. What's the worst thing that could happen? (data breach, financial loss, safety incident)
6. What regulatory requirements apply? (GDPR, HIPAA, EU AI Act, SOC2)
7. Has it been tested before? (baseline security posture)
8. What monitoring exists? (logs, alerts, behavioral analysis)
