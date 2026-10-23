---
name: service-vulnerabilities
description: Service vulnerability identification — known CVEs, misconfigurations, default credentials. Maps to Hunter NET02.
allowed-tools: Read, Grep, Glob, Bash
---

# Service Vulnerability Scanning Skill

## When to Use
- After service enumeration identifies running services and versions
- When checking for known CVEs against detected software
- When testing for common misconfigurations

## Tool Chain

### 1. Nuclei Network Templates
    nuclei -u TARGET -t network/ -severity critical,high,medium -o $PROJECT_DIR/hunter/recon/nuclei-network.txt
    nuclei -u TARGET -t cves/ -severity critical,high -o $PROJECT_DIR/hunter/recon/nuclei-cves.txt

### 2. Nmap Vuln Scripts
    nmap --script vuln -p OPEN_PORTS TARGET -oA $PROJECT_DIR/hunter/recon/nmap-vuln
    nmap --script exploit -p OPEN_PORTS TARGET -oA $PROJECT_DIR/hunter/recon/nmap-exploit

### 3. Exploit Research
    searchsploit SERVICE VERSION
    searchsploit --nmap $PROJECT_DIR/hunter/recon/nmap-services.xml

### 4. Service-Specific Checks
    # SMB: EternalBlue, SMBGhost, PrintNightmare
    nmap --script smb-vuln* -p 445 TARGET

    # SSH: weak algorithms, known vulnerable versions
    nmap --script ssh2-enum-algos -p 22 TARGET

    # SSL/TLS: Heartbleed, POODLE, weak ciphers
    nmap --script ssl-heartbleed,ssl-poodle -p 443 TARGET

## Severity Guidelines
- **Critical**: RCE (EternalBlue, Log4Shell), unauthenticated admin access
- **High**: Authenticated RCE, privilege escalation CVEs, default admin creds
- **Medium**: DoS vulnerabilities, information disclosure CVEs
- **Low**: Version disclosure, deprecated protocols

## Output
Cross-reference all findings with CVE databases. Log validated vulnerabilities with CVE IDs via finding.sh.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Match the EXACT deployed version to the CVE (banner->version) and confirm config makes it exploitable; do NOT run destructive PoCs on prod.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method tool-output \
  --negative-control "<what you proved, and the control result>" --by hunter
```
