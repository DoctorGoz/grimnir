# GenAI Penetration Test Report

## Document Control

| Attribute | Value |
|-----------|-------|
| **Engagement ID** | ENG-YYYY-NNN |
| **Client** | [Organization Name] |
| **Target System** | [System Name] |
| **Report Date** | YYYY-MM-DD |
| **Version** | 1.0 |
| **Classification** | CONFIDENTIAL |
| **Prepared By** | [Tester Name(s)] |
| **Reviewed By** | [Reviewer Name] |

---

## Executive Summary

[2-3 paragraphs written for non-technical leadership. Cover:
- What was tested and why
- Overall risk posture (Critical/High/Medium/Low)
- Most significant findings in business terms
- Key recommendations prioritized by impact]

### Risk Summary Dashboard

| Severity | Count | Categories Affected |
|----------|-------|-------------------|
| 🔴 Critical | [N] | [List] |
| 🟠 High | [N] | [List] |
| 🟡 Medium | [N] | [List] |
| 🔵 Low | [N] | [List] |
| ⚪ Informational | [N] | [List] |
| **Total** | **[N]** | |

### Top 3 Recommendations

1. **[Recommendation 1]**: [Brief description and business justification]
2. **[Recommendation 2]**: [Brief description and business justification]
3. **[Recommendation 3]**: [Brief description and business justification]

---

## Engagement Overview

### Scope
[Summarize what was tested, referencing the scope document]

### Methodology
[Summarize the approach used, referencing:
- OWASP GenAI Red Teaming Guide v1.0
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic Applications 2026
- MITRE ATLAS
- NIST AI RMF]

### Timeline
| Phase | Dates | Duration |
|-------|-------|----------|
| Scoping | YYYY-MM-DD to YYYY-MM-DD | [N] days |
| Reconnaissance | YYYY-MM-DD to YYYY-MM-DD | [N] days |
| Assessment | YYYY-MM-DD to YYYY-MM-DD | [N] days |
| Exploitation | YYYY-MM-DD to YYYY-MM-DD | [N] days |
| Reporting | YYYY-MM-DD to YYYY-MM-DD | [N] days |

### Testing Coverage

#### OWASP LLM Top 10 Coverage
| Category | Tested | Findings | Severity |
|----------|--------|----------|----------|
| LLM01: Prompt Injection | ✅/❌ | [N] | [Max severity] |
| LLM02: Sensitive Info Disclosure | ✅/❌ | [N] | [Max severity] |
| LLM03: Supply Chain | ✅/❌ | [N] | [Max severity] |
| LLM04: Data/Model Poisoning | ✅/❌ | [N] | [Max severity] |
| LLM05: Improper Output Handling | ✅/❌ | [N] | [Max severity] |
| LLM06: Excessive Agency | ✅/❌ | [N] | [Max severity] |
| LLM07: System Prompt Leakage | ✅/❌ | [N] | [Max severity] |
| LLM08: Vector/Embedding Weaknesses | ✅/❌ | [N] | [Max severity] |
| LLM09: Misinformation | ✅/❌ | [N] | [Max severity] |
| LLM10: Unbounded Consumption | ✅/❌ | [N] | [Max severity] |

#### OWASP Agentic Top 10 Coverage (if applicable)
| Category | Tested | Findings | Severity |
|----------|--------|----------|----------|
| ASI01: Agent Goal Hijacking | ✅/❌ | [N] | [Max severity] |
| ASI02: Tool Misuse/Exploitation | ✅/❌ | [N] | [Max severity] |
| ASI03: Identity/Privilege Abuse | ✅/❌ | [N] | [Max severity] |
| ASI04: Uncontrolled Actions | ✅/❌ | [N] | [Max severity] |
| ASI05: Multi-Agent Orchestration | ✅/❌ | [N] | [Max severity] |
| ASI06: Compromised Memory | ✅/❌ | [N] | [Max severity] |
| ASI07: Insecure Communication | ✅/❌ | [N] | [Max severity] |
| ASI08: Cascading Failures | ✅/❌ | [N] | [Max severity] |
| ASI09: Human-Agent Trust | ✅/❌ | [N] | [Max severity] |
| ASI10: Rogue Agents | ✅/❌ | [N] | [Max severity] |

---

## Reconnaissance Summary

[Summary of information gathered during recon phase]

### System Architecture
[Describe the target system architecture as understood through recon]

### Attack Surface
[List all identified entry points and interfaces]

### Security Controls Identified
[List guardrails, filters, rate limits, and other controls observed]

---

## Findings

### Critical Findings

[Include full finding details for each Critical finding, using the finding template format]

### High Findings

[Include full finding details for each High finding]

### Medium Findings

[Include full finding details for each Medium finding]

### Low Findings

[Include full finding details for each Low finding]

### Informational Findings

[Include full finding details for each Informational finding]

---

## Attack Narratives

[For the most significant findings, describe complete attack chains showing how individual vulnerabilities can be combined for maximum impact. This section tells the story of how a real attacker could exploit the system.]

### Attack Narrative 1: [Title]
[Step-by-step attack chain with findings cross-referenced]

---

## Risk Matrix

| Finding ID | Title | OWASP Cat | Likelihood | Impact | Risk Score | Priority |
|-----------|-------|-----------|------------|--------|------------|----------|
| FINDING-001 | [Title] | LLM## | H/M/L | H/M/L | [Score] | [1-N] |
| ... | ... | ... | ... | ... | ... | ... |

---

## Remediation Roadmap

### Immediate Actions (0-2 weeks)
| Priority | Finding(s) | Action | Effort | Owner |
|----------|-----------|--------|--------|-------|
| 1 | FINDING-XXX | [Action] | [Effort] | [TBD] |

### Short-Term (2-8 weeks)
| Priority | Finding(s) | Action | Effort | Owner |
|----------|-----------|--------|--------|-------|
| 1 | FINDING-XXX | [Action] | [Effort] | [TBD] |

### Long-Term (2-6 months)
| Priority | Finding(s) | Action | Effort | Owner |
|----------|-----------|--------|--------|-------|
| 1 | FINDING-XXX | [Action] | [Effort] | [TBD] |

---

## Framework Compliance Summary

### OWASP GenAI Red Teaming Guide Alignment
[Summary of how testing aligned with the four pillars: Model Evaluation, Implementation Testing, Infrastructure Assessment, Runtime Behavior Analysis]

### MITRE ATLAS Coverage
[Tactics and techniques covered during the engagement]

### NIST AI RMF Relevance
[How findings map to NIST AI Risk Management Framework functions]

### EU AI Act Considerations (if applicable)
[Relevance of findings to EU AI Act requirements]

---

## Appendices

### Appendix A: Testing Tools Used
[List of tools, frameworks, and scripts used during the engagement]

### Appendix B: Payload Log
[Reference to the complete payload log with all tested inputs and responses]

### Appendix C: Methodology Details
[Detailed methodology description for reproducibility]

### Appendix D: Glossary
[Definitions of technical terms used in this report]
