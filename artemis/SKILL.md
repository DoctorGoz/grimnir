---
name: genai-redteam
description: >
  AI/LLM Penetration Testing and Red Teaming agent based on OWASP GenAI Red Teaming Guide,
  OWASP Top 10 for LLM Applications (2025), and OWASP Top 10 for Agentic Applications (2026).
  Use this skill for ANY task involving: AI security testing, LLM red teaming, GenAI penetration testing,
  prompt injection testing, AI vulnerability assessment, LLM guardrail bypass testing, RAG security testing,
  agentic AI security evaluation, AI threat modeling, model evaluation, system prompt extraction testing,
  or any mention of OWASP LLM/GenAI risks. Also trigger when the user mentions testing chatbots,
  AI assistants, copilots, AI agents, or any LLM-powered application for security vulnerabilities.
  Trigger on phrases like "test this AI", "red team", "pentest the LLM", "is this chatbot secure",
  "prompt injection", "jailbreak testing", "AI security assessment", or any OWASP LLM/Agentic category
  codes (LLM01-LLM10, ASI01-ASI10).
---

# GenAI Red Teaming & Penetration Testing Skill

## Quick Start

1. Read `CLAUDE.md` for the full agent identity, operating modes, and engagement rules
2. Read the appropriate reference file for the assessment category being tested
3. Follow the engagement workflow below

## When to Use This Skill

This skill activates for any AI/LLM security testing task, including but not limited to:

- Penetration testing of LLM-powered applications (chatbots, copilots, agents, RAG systems)
- Red teaming exercises targeting GenAI systems
- Vulnerability assessment against OWASP LLM Top 10 or Agentic Top 10
- Prompt injection and jailbreak testing
- Guardrail and content filter bypass testing
- System prompt extraction and leakage testing
- Data exfiltration testing through AI interfaces
- Agentic AI goal hijacking and tool misuse testing
- AI supply chain security assessment
- Threat modeling for AI/ML systems
- Building test plans or payloads for AI security assessments
- Generating pentest reports for AI/GenAI engagements

## Engagement Workflow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   SCOPING   │───▶│    RECON     │───▶│   ASSESS    │
│  /scope     │    │  /recon      │    │  /assess     │
└─────────────┘    └─────────────┘    └──────┬───────┘
                                             │
                   ┌─────────────┐    ┌──────▼───────┐
                   │   REPORT    │◀───│   EXPLOIT    │
                   │  /report    │    │  /exploit     │
                   └──────┬──────┘    └──────────────┘
                          │
                   ┌──────▼──────┐
                   │   MONITOR   │
                   │  /monitor   │
                   └─────────────┘
```

### Phase 1: Scoping
- Confirm authorization and legal basis for testing
- Identify target type and technology stack
- Define in-scope and out-of-scope items
- Prioritize risk categories based on threat model
- Output: `scope.md` and `test-plan.md`

### Phase 2: Reconnaissance
- Fingerprint the AI system (model, provider, version)
- Map input/output interfaces and API surface
- Identify guardrails, filters, and safety mechanisms
- Enumerate tools, plugins, data sources (for agentic systems)
- Output: `recon-notes.md`

### Phase 3: Assessment
- Execute test cases per OWASP category (see references/)
- Start with highest-priority categories from test plan
- Document each finding immediately using the finding template
- Output: Individual `ART-NNN.md` files

### Phase 4: Exploitation
- Build attack chains from confirmed findings
- Demonstrate maximum realistic impact
- Create proof-of-concept narratives
- Output: Updated findings with exploitation evidence

### Phase 5: Reporting
- Compile all findings into structured report
- Include executive summary, risk matrix, and remediation roadmap
- Map findings to framework references (OWASP, MITRE ATLAS, NIST)
- Output: `report.md`

### Phase 6: Monitoring Guidance
- Recommend detection rules for discovered attack patterns
- Suggest logging enhancements
- Provide templates for recurring red team exercises
- Output: Monitoring recommendations in report appendix

## Reference Files

Read these BEFORE executing assessments:

| File | Purpose | When to Read |
|------|---------|-------------|
| `references/owasp-llm-top10.md` | Complete LLM Top 10 test procedures | Before any LLM01-LLM10 assessment |
| `references/owasp-agentic-top10.md` | Complete Agentic Top 10 test procedures | Before any ASI01-ASI10 assessment |
| `references/redteam-methodology.md` | Overall red team methodology and process | At engagement start |
| `references/payload-library.md` | Categorized test payloads and techniques | When building test cases |
| `references/threat-modeling.md` | Threat modeling frameworks for AI systems | During scoping phase |

## Integration Points

This skill can be called by a PM orchestrator agent. See `CLAUDE.md` for the handoff payload schema and status update format.

## Templates

- `templates/scope-template.md` — Engagement scoping document
- `templates/finding-template.md` — Individual finding report
- `templates/report-template.md` — Full pentest report
- `templates/test-plan-template.md` — Assessment test plan
