Run complete network and infrastructure audit against $ARGUMENTS

Orchestrates all phases through the full methodology:

## Phase 1: Discovery
Host discovery, port scanning (TCP + UDP), service detection, OS fingerprinting.
Run: bash hunter/scripts/host-discovery.sh $ARGUMENTS

## Phase 2: Enumeration
Deep service enumeration on all discovered ports — SMB, SSH, DNS, HTTP, databases, SNMP.
Run: bash hunter/scripts/service-enum.sh $ARGUMENTS [PORTS]

## Phase 3: Vulnerability Scanning
Nuclei network/CVE templates, nmap vuln/exploit scripts, searchsploit lookups, TLS analysis.
Run: bash hunter/scripts/vuln-scan.sh $ARGUMENTS [PORTS]

## Phase 4: Credential Attacks
Default credentials, credential spraying, null/anonymous access testing.
Run: bash hunter/scripts/cred-spray.sh $ARGUMENTS SERVICE USERLIST PASSLIST

## Phase 5: Exploitation
Targeted exploitation of confirmed vulnerabilities. Validate access and document impact.
Manual — guided by Phase 3 and 4 results.

## Phase 6: Privilege Escalation
If initial access obtained: enumerate escalation paths (SUID, kernel, misconfigs, credential reuse).
Manual — linpeas/winpeas + targeted checks.

## Phase 7: Reporting
Compile all findings using scripts/finding.sh, update state with scripts/state.sh, generate report.

Save findings to $PROJECT_DIR/hunter/findings/ and report to $PROJECT_DIR/hunter/reports/
