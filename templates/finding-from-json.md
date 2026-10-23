# Finding JSON to Markdown Rendering Reference

This document defines how agents and the report-compiler render an `AGT-NNN.json` file (e.g. `SPE-024.json`; legacy `FINDING-NNN.json` renders identically) into human-readable markdown. The `finding.sh` script produces both formats automatically.

## Layout

```markdown
# AGT-NNN: {title}

| Field | Value |
|-------|-------|
| **Severity** | {severity (uppercase)} |
| **CVSS** | {cvss_score or N/A} |
| **Status** | {status} |
| **Agent** | {agent} |
| **Created** | {created_at} |
| **Categories** | {frameworks.* values, comma-separated} |
| **CWE** | {frameworks.cwe values, comma-separated} |

## Description

{description}

## Affected Targets

- `{affected_targets[0]}`
- `{affected_targets[1]}`

## Technical Details

### For Specter (specter_ext):
- **Endpoint**: `{endpoint}`
- **Method**: {method}
- **Response Code**: {response_code}

### For ARTEMIS (artemis_ext):
- **Success Rate**: {success_rate.successes}/{success_rate.attempts}
- **Model**: {model_identified}
- **Guardrail Status**: {guardrail_status}
- **Attack Vector**: {attack_vector}

### For Hunter (hunter_ext):
- **Hosts**: {affected_hosts[].ip, comma-separated}
- **Ports**: {ports, comma-separated}
- **Service**: {service_name} {service_version}
- **Access Gained**: {access_gained}
- **CVEs**: {cve_ids, comma-separated}

### For Nimbus (cloud_ext):
- **Provider / Account**: {provider} / {account_id}
- **Region / Service**: {region} / {service}
- **Resource**: `{resource}`
- **Permission**: {permission}
- **Access Gained**: {access_gained}
- **Exploit**: {exploit}

### For Nomad (mobile_ext):
- **Platform / Package**: {platform} / `{package_id}`
- **Component**: {component} (exported: {exported})
- **Analysis**: {analysis}
- **Access Gained**: {access_gained}
- **Exploit**: {exploit}

## Impact

{impact.summary}

- **Confidentiality**: {impact.confidentiality}
- **Integrity**: {impact.integrity}
- **Availability**: {impact.availability}
- **Business**: {impact.business}

## Steps to Reproduce

1. {reproduction_steps[0]}
2. {reproduction_steps[1]}

## Evidence

- {evidence[0].description}: `{evidence[0].path}`
- {evidence[1].description} (inline):
  ```
  {evidence[1].inline}
  ```

## Remediation

**Immediate:**
- {remediation.immediate[0]}

**Short-term:**
- {remediation.short_term[0]}

**Long-term:**
- {remediation.long_term[0]}

## References

- {references[0]}
- {references[1]}
```

## Notes

- Only include sections where data exists (skip empty sections)
- The `finding.sh` script auto-generates this format alongside the JSON
- For inline evidence, use fenced code blocks
- For file evidence, use relative paths from `$PROJECT_DIR`
