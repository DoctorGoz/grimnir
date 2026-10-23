---
name: smb-windows
description: SMB and Windows enumeration and attacks — share enumeration, null sessions, relay attacks, AD recon. Maps to Hunter NET04.
allowed-tools: Read, Grep, Glob, Bash
---

# SMB/Windows Attack Skill

## When to Use
- When ports 139/445 are open
- When targeting Windows hosts or Active Directory environments
- When SMB signing is disabled (relay attacks)

## Tool Chain

### 1. SMB Signing Check
    netexec smb TARGET --gen-relay-list $PROJECT_DIR/hunter/recon/relay-targets.txt

### 2. Share Enumeration
    netexec smb TARGET --shares
    smbclient -L //TARGET -N
    # Test read/write on each share:
    smbclient //TARGET/SHARE -N -c "ls"

### 3. User & Group Enumeration
    netexec smb TARGET --users
    netexec smb TARGET --groups
    netexec smb TARGET --rid-brute
    enum4linux -a TARGET > $PROJECT_DIR/hunter/recon/enum4linux.txt

### 4. Password Policy
    netexec smb TARGET --pass-pol
    # Check: lockout threshold, complexity, min length, history

### 5. Known SMB Vulnerabilities
    # EternalBlue (MS17-010)
    nmap --script smb-vuln-ms17-010 -p 445 TARGET

    # SMBGhost (CVE-2020-0796)
    nmap --script smb-vuln-cve-2020-0796 -p 445 TARGET

    # PrintNightmare
    nmap --script smb-vuln* -p 445 TARGET

### 6. Authenticated Enumeration (if creds obtained)
    netexec smb TARGET -u USER -p PASS --shares
    netexec smb TARGET -u USER -p PASS --sessions
    netexec smb TARGET -u USER -p PASS --loggedon-users
    netexec smb TARGET -u USER -p PASS --disks

## Key Findings to Watch For
- Writable shares (especially SYSVOL, NETLOGON)
- SMB signing disabled (relay potential)
- Null session access to users/shares
- GPP passwords in SYSVOL
- Weak password policy (no lockout, low complexity)

## Output
Document shares, users, groups, password policy, signing status, and any vulnerabilities found.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Confirm the share/RPC exposes data or access with the creds used; null-session vs authed differential.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by hunter
```
