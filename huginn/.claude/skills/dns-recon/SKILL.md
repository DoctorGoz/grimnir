---
name: dns-recon
description: DNS reconnaissance — records, zone transfers, CT/SAN pivots, takeover detection. HUGINN Phase 1. Surfaces hosts, mail/SPF, and dangling records.
allowed-tools: Read, Grep, Glob, Bash
---

# DNS Reconnaissance Skill (HUGINN Phase 1)

DNS reveals infrastructure, related domains, and subdomain-takeover candidates.

## Methodology

### Step 1: Records
```bash
dnsx -d target.com -a -aaaa -cname -mx -ns -txt -resp -silent
```
Note A/AAAA (hosts), CNAME (third-party services), MX (mail), TXT (SPF/DMARC,
verification tokens that hint at SaaS vendors), NS (DNS provider).

### Step 2: Zone transfer (cheap, occasionally a jackpot)
```bash
for ns in $(dig +short NS target.com); do dig AXFR target.com @"$ns"; done
```

### Step 3: CT / SAN pivots
Pull SANs from certs (see `tech-fingerprint`/openssl) to discover sibling domains,
then loop back into `subdomain-enum`.

### Step 4: Subdomain takeover detection
For each CNAME pointing at a third-party (S3, GitHub Pages, Heroku, Azure, etc.),
check whether the target resource is unclaimed (dangling) — a takeover candidate.

## Output to record
Record providers (CDN, mail, DNS, SaaS from TXT) and any dangling CNAMEs.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Log providers/relationships and route takeover candidates.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type relationship --confidence high --name "dangling CNAME -> unclaimed S3 bucket" \
  --tag needs-specter --tag high-value
```
Dangling CNAME / cloud bucket → `needs-nimbus`/`needs-specter`; mail/SPF/infra context → asset map. (cloud tag applies once Nimbus is enabled.)
