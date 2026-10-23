---
name: port-service-scan
description: Port and service scanning — fast discovery then targeted version detection. HUGINN Phase 2. Feeds hosts/ports/services to the asset map and Hunter.
allowed-tools: Read, Grep, Glob, Bash
---

# Port & Service Scan Skill (HUGINN Phase 2)

Map open ports and identify services/versions so Hunter can go straight to
enumeration and exploitation. Two-stage: fast sweep, then deep on what's open.

## Methodology

### Step 1: Fast port sweep
```bash
naabu -host target.com -top-ports 1000 -silent
# or wide+fast:
masscan -p1-65535 10.0.0.0/24 --rate 1000 -oL masscan.txt
```

### Step 2: Targeted service/version detection
```bash
nmap -sV -sC -p <open-ports> -oA recon/nmap-target target.com
```
Add `-O` for OS fingerprint where authorized. Respect the engagement rate limit.

### Step 3: Banner/context
Note service, version, TLS, and anything Hunter will need (auth required? default
landing? admin panel?).

## Scope & safety
Stay within authorized hosts and rate limits. No exploitation — observe only.

## Output to record
hosts[] with ip, ports[], services, versions, os → `asset-map.json` `hosts`.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Log each notable service.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type service --confidence confirmed --host 10.0.0.5 --port 22 --protocol tcp \
  --service-name openssh --service-version "8.9p1" --tag needs-hunter
```
Non-HTTP services → `needs-hunter`; HTTP/S → also probe in `tech-fingerprint` and route web to `needs-specter`.
