---
name: ssh-remote-access
description: SSH and remote access testing — weak keys, misconfigurations, tunneling abuse. Maps to Hunter NET05.
allowed-tools: Read, Grep, Glob, Bash
---

# SSH/Remote Access Testing Skill

## When to Use
- When SSH (22), RDP (3389), VNC (5900), Telnet (23), or WinRM (5985/5986) are open
- When testing remote access configurations for weaknesses

## Tool Chain

### SSH (Port 22)
    # Algorithm enumeration
    nmap --script ssh2-enum-algos -p 22 TARGET

    # Auth methods
    nmap --script ssh-auth-methods -p 22 TARGET

    # Host key check
    ssh-keyscan TARGET 2>/dev/null

    # Banner grab
    ncat TARGET 22 < /dev/null

    # Credential spray (low and slow)
    hydra -L hunter/wordlists/common-users.txt -P hunter/wordlists/common-passwords.txt TARGET ssh -t 4

### RDP (Port 3389)
    # Encryption check
    nmap --script rdp-enum-encryption -p 3389 TARGET

    # NLA check
    nmap --script rdp-ntlm-info -p 3389 TARGET

    # BlueKeep (CVE-2019-0708)
    nmap --script rdp-vuln-ms12-020 -p 3389 TARGET

### VNC (Port 5900)
    # Auth check
    nmap --script vnc-info -p 5900 TARGET

    # No-auth test
    nmap --script vnc-brute -p 5900 TARGET

### Telnet (Port 23)
    # Banner grab + default creds
    ncat TARGET 23

### WinRM (Port 5985/5986)
    netexec winrm TARGET -u USER -p PASS

## Key Findings
- SSH with password auth enabled (should be key-only)
- Weak SSH algorithms (diffie-hellman-group1-sha1, ssh-dss)
- RDP without NLA
- VNC without authentication
- Telnet in use (cleartext protocol)

## Output
Document: service, version, auth methods, weak configurations, and valid credentials.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Version+config evidence for the CVE; never run destructive/race PoCs (regreSSHion-class) on prod to prove it.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method tool-output \
  --negative-control "<what you proved, and the control result>" --by hunter
```
