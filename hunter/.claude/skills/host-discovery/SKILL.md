---
name: host-discovery
description: Host and service discovery — open ports, running services, OS identification. Maps to Hunter NET01 and PTES Intelligence Gathering.
allowed-tools: Read, Grep, Glob, Bash
---

# Host & Service Discovery Skill

## When to Use
- Beginning of any network/infrastructure assessment
- When given an IP, CIDR range, or hostname
- When mapping the attack surface of a network segment

## Tool Chain

### 1. Host Discovery (ping sweep)
    nmap -sn TARGET_RANGE -oG $PROJECT_DIR/hunter/recon/hosts-alive.gnmap
    # Parse live hosts:
    grep "Status: Up" hosts-alive.gnmap | awk '{print $2}' | sort -u > live-hosts.txt

### 2. Fast Port Scan (TCP top 1000)
    nmap -sS -T4 --top-ports 1000 -iL live-hosts.txt -oA $PROJECT_DIR/hunter/recon/nmap-top1000

### 3. Full TCP Port Scan
    nmap -sS -p- -T4 --min-rate 1000 TARGET -oA $PROJECT_DIR/hunter/recon/nmap-allports
    # Or for speed on large ranges:
    masscan TARGET_RANGE -p1-65535 --rate 1000 -oG $PROJECT_DIR/hunter/recon/masscan-full.gnmap

### 4. Service Version Detection
    nmap -sV -sC -p OPEN_PORTS TARGET -oA $PROJECT_DIR/hunter/recon/nmap-services

### 5. OS Fingerprinting
    nmap -O --osscan-guess TARGET -oA $PROJECT_DIR/hunter/recon/nmap-os

### 6. UDP Scan (top 50)
    nmap -sU --top-ports 50 -T4 TARGET -oA $PROJECT_DIR/hunter/recon/nmap-udp

## Key Ports to Watch For
- 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS)
- 80/443 (HTTP/S), 110/143/993/995 (Mail), 139/445 (SMB)
- 161 (SNMP), 389/636 (LDAP), 1433 (MSSQL), 3306 (MySQL)
- 3389 (RDP), 5432 (PostgreSQL), 5900 (VNC), 6379 (Redis), 27017 (MongoDB)

## Output
Compile host/port/service/OS matrix into reports/discovery-summary.md. Tag web services for Specter via intel.sh.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Confirm the host/service is live and in scope (not a shared CDN/edge); recon is rarely a standalone finding.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent hunter \
  --id HUN-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by hunter
```
