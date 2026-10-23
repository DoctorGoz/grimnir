---
name: network-services
description: Mail, DNS, and SNMP service testing — zone transfers, open relays, community strings. Maps to Hunter NET07.
allowed-tools: Read, Grep, Glob, Bash
---

# Network Services (Mail/DNS/SNMP) Skill

## When to Use
- When DNS (53), SMTP (25/587), SNMP (161), NTP (123), or LDAP (389/636) are discovered
- When testing infrastructure services for misconfigurations

## Tool Chain

### DNS (Port 53)
    # Zone transfer attempt
    dnsrecon -d DOMAIN -t axfr
    dig axfr DOMAIN @TARGET

    # DNS brute-force
    dnsx -d DOMAIN -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o $PROJECT_DIR/hunter/recon/dns-brute.txt

    # Reverse lookups
    dnsrecon -r TARGET_RANGE -n TARGET

    # Cache snooping
    nmap --script dns-cache-snoop -p 53 TARGET

### SMTP (Port 25/587)
    # Banner grab and commands
    nmap --script smtp-commands,smtp-ntlm-info -p 25 TARGET

    # Open relay test
    nmap --script smtp-open-relay -p 25 TARGET

    # User enumeration (VRFY/EXPN/RCPT)
    nmap --script smtp-enum-users -p 25 TARGET

### SNMP (Port 161)
    # Community string brute-force
    nmap --script snmp-brute -p 161 TARGET
    # Test known strings:
    for community in $(cat hunter/wordlists/snmp-communities.txt); do
        snmpwalk -v2c -c "$community" TARGET system 2>/dev/null && echo "VALID: $community"
    done

    # Full SNMP walk (if community found)
    snmpwalk -v2c -c COMMUNITY TARGET . > $PROJECT_DIR/hunter/recon/snmpwalk.txt

### LDAP (Port 389/636)
    nmap --script ldap-rootdse,ldap-search -p 389 TARGET
    # Anonymous bind test
    ldapsearch -x -H ldap://TARGET -b "" -s base namingContexts

### NTP (Port 123)
    nmap --script ntp-info,ntp-monlist -p 123 TARGET

## Key Findings
- DNS zone transfer allowed (High — exposes internal infrastructure)
- SMTP open relay (High — spam/phishing vector)
- SNMP default/weak community strings (High — info disclosure, potential write access)
- LDAP anonymous bind (Medium — user/group enumeration)
- NTP monlist enabled (Medium — amplification attack vector)

## Output
Document: service, misconfiguration, data exposed, and remediation steps.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Confirm the service is exploitable/sensitive, not merely open; prefer version+config evidence over destructive checks.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by hunter
```
