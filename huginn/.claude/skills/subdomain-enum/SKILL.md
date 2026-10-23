---
name: subdomain-enum
description: Subdomain enumeration — passive sources, certificate transparency, brute, and permutations. HUGINN Phase 1. Feeds the asset map and routes new hosts to specialists.
allowed-tools: Read, Grep, Glob, Bash
---

# Subdomain Enumeration Skill (HUGINN Phase 1)

Build the broadest accurate set of in-scope subdomains. Breadth here multiplies
every specialist's attack surface — a missed subdomain is a missed engagement.

## Methodology

### Step 1: Passive sources (fast, no target traffic)
```bash
subfinder -d target.com -all -silent
assetfinder --subs-only target.com
findomain -t target.com -q
amass enum -passive -d target.com
```

### Step 2: Certificate transparency + archives
crt.sh / CT logs and `gau`/`waybackurls` host extraction often reveal hosts the
passive APIs miss.

### Step 3: Permutations / alterations
```bash
alterx -l subs.txt | dnsx -silent   # dev-, staging-, api-, -v2 patterns
```

### Step 4: Resolve and dedupe
```bash
dnsx -l all-subs.txt -a -resp -silent | sort -u
```

## Scope discipline
Keep only in-scope hosts (match the program's wildcard). Flag interesting
out-of-scope hosts in notes but do NOT route them for testing.

## Output to record
Resolved subdomains + IPs + which source found them → `asset-map.json` `subdomains`.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Log each live subdomain as you find it and fold it into `asset-map.json`.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type subdomain --confidence confirmed --subdomain "api.target.com" \
  --resolved-ip "10.0.0.5" --tag needs-specter
```
Route by nature: web/API → `needs-specter`; non-HTTP service host → `needs-hunter`; AI surface → `needs-artemis`; cloud-hosted asset → `needs-nimbus`; app/mobile backend → `needs-nomad` (cloud/mobile tags apply once those agents are enabled). Add `--tag high-value` for admin/api/internal hosts.
