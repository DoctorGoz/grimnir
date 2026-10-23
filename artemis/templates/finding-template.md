# ART-NNN: [Descriptive Title]

## Classification

| Attribute | Value |
|-----------|-------|
| **Finding ID** | ART-NNN |
| **OWASP Category** | LLM## / ASI## — [Category Name] |
| **Severity** | Critical / High / Medium / Low / Informational |
| **AIVSS Score** | [0.0 - 10.0] |
| **MITRE ATLAS Tactic** | [Tactic ID] — [Tactic Name] |
| **MITRE ATLAS Technique** | [Technique ID] — [Technique Name] |
| **Status** | Confirmed / Suspected / Under Investigation / False Positive |
| **Discovered** | YYYY-MM-DD |
| **Tester** | [Name] |

---

## Description

[Clear, concise description of the vulnerability. What is it, where does it exist, and why does it matter? Write this so that both technical and non-technical stakeholders can understand the core issue.]

---

## Technical Details

**Affected Component**: [Specific system component]
**Attack Vector**: [How the vulnerability is exploited]
**Preconditions**: [What must be true for the attack to succeed]
**Authentication Required**: Yes / No
**User Interaction Required**: Yes / No

---

## Reproduction Steps

1. [Precise step-by-step instructions]
2. [Include exact endpoints, parameters, and configurations]
3. [Anyone should be able to reproduce this finding from these steps]

---

## Evidence

### Payload(s) Used
```
[Exact payload text]
```

### System Response
```
[Exact system response — REDACT any real sensitive data]
```

### Statistical Results
| Attempt | Payload Variant | Result | Notes |
|---------|----------------|--------|-------|
| 1 | [variant] | Success / Fail | [notes] |
| 2 | [variant] | Success / Fail | [notes] |
| 3 | [variant] | Success / Fail | [notes] |
| 4 | [variant] | Success / Fail | [notes] |
| 5 | [variant] | Success / Fail | [notes] |

**Success Rate**: X/5 (XX%)

### Additional Evidence
- [Screenshots, logs, or file references]
- [Request/response captures]
- [Tool invocation logs]

---

## Impact Assessment

### Confidentiality Impact
[What data could be exposed? How sensitive is it?]

### Integrity Impact
[What could be modified? What decisions could be influenced?]

### Availability Impact
[Could this cause service disruption? For how long?]

### Business Impact
[Financial, reputational, legal, compliance implications]

### Affected Users/Scale
[How many users could be affected? What scope of impact?]

---

## Remediation Recommendations

### Immediate Actions (Quick Wins)
1. [Action that can be taken immediately to reduce risk]

### Short-Term Fixes (1-4 weeks)
1. [More substantial fixes requiring development effort]

### Long-Term Improvements (1-3 months)
1. [Architectural or process changes for comprehensive mitigation]

### OWASP Recommended Mitigations
- [Reference specific OWASP mitigation guidance for this category]

---

## References

- OWASP LLM Top 10: [Link to relevant category]
- OWASP Agentic Top 10: [Link to relevant category]
- MITRE ATLAS: [Link to relevant technique]
- NIST AI RMF: [Relevant section]
- [Additional references, CVEs, research papers]

---

## Verification

### How to Verify the Fix
[Describe how to confirm that remediation has been successful]

### Regression Testing
[Describe what tests should be run to ensure the fix doesn't break functionality]
