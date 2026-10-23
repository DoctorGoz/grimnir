# Security Finding Report

## [SEVERITY] Finding Title

**Date**: YYYY-MM-DD
**Tester**: Specter Agent
**OWASP Category**: APIx:2023 / WSTG-XXXX-XX
**Endpoint**: METHOD /api/v1/endpoint
**Severity**: Critical / High / Medium / Low / Info
**CVSS Score**: X.X
**CWE**: CWE-XXX

### Description
Technical description of the vulnerability.

### Evidence

#### Authorized Request (Baseline)
    METHOD /endpoint HTTP/1.1
    Host: target
    Authorization: Bearer VALID_TOKEN

#### Unauthorized Request (Proof)
    METHOD /endpoint HTTP/1.1
    Host: target
    Authorization: Bearer ATTACKER_TOKEN

### Steps to Reproduce
1. Step one
2. Step two
3. Step three

### Impact
Business impact and worst-case scenario.

### Remediation
1. Specific fix recommendation
2. Code-level guidance
3. Testing verification steps

### References
- OWASP: https://owasp.org/...
- CWE: https://cwe.mitre.org/...
