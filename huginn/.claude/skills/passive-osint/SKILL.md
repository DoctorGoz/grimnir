---
name: passive-osint
description: Passive OSINT — WHOIS/ASN, code/secret leaks, breach data, org footprint. HUGINN Phase 1. Zero-touch intelligence before any active recon.
allowed-tools: Read, Grep, Glob, Bash
---

# Passive OSINT Skill (HUGINN Phase 1)

Gather intelligence without touching the target: ownership, infrastructure
ranges, leaked code/secrets, and breach exposure. Pure passive — no requests to
the target's own assets.

## Methodology

### Step 1: Ownership & infrastructure
WHOIS (registrant, dates), ASN/netblock ranges (expands IP scope), reverse DNS,
related domains (shared registrant/favicon hash).

### Step 2: Public code & secret leaks
GitHub/GitLab dorking for the org and its domains: hardcoded keys, internal
hostnames, API references, `.env` commits. (Fold in hits from any
leaked-credential monitor you run.)

### Step 3: Breach / paste exposure
Note employee credential exposure patterns relevant to credential-stuffing scope
(record only; testing is Hunter/Specter, and only if in scope).

### Step 4: Org footprint
Tech job posts (stack hints), public docs, status pages, third-party SaaS in use
(from DNS TXT, email headers), cloud tenancy hints.

## Scope & ethics
Passive only. Do not log into or probe leaked credentials; record and route.

## Output to record
WHOIS, ASN ranges, related domains, leaked-secret leads (redacted), SaaS/cloud
vendors → asset map + notes.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Route leaks/ranges to the right specialist.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type credential --confidence high --name "Leaked token in public GitHub (unverified)" \
  --tag needs-specter --tag high-value
```
ASN ranges → expand scope for `port-service-scan`; cloud keys → `needs-nimbus`; leaked app secrets → `needs-nomad`; web creds/endpoints → `needs-specter`. (cloud/mobile tags apply once those agents are enabled.)
