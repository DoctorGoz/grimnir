---
name: tech-fingerprint
description: Technology + WAF + TLS fingerprinting. HUGINN Phase 3. Identifies stacks, CDNs, WAFs, and cert SANs that drive specialist routing.
allowed-tools: Read, Grep, Glob, Bash
---

# Technology Fingerprinting Skill (HUGINN Phase 3)

Identify the stack so specialists pick the right playbooks (e.g. Node → proto-
pollution; XML/SOAP → XXE; a chat widget → ARTEMIS; an S3/CloudFront origin →
Nimbus). Also detect WAFs so testing accounts for them.

## Methodology

### Step 1: HTTP probe + tech
```bash
httpx -l subs.txt -title -tech-detect -status-code -web-server -silent
whatweb -a 3 https://target.com
```
Capture: server, framework, language, CMS, CDN, analytics, JS libs.

### Step 2: WAF detection
```bash
wafw00f https://target.com
```
Record the WAF (Akamai/Cloudflare/etc.) — it changes how specialists test and
which bypasses apply (`waf-bypass`).

### Step 3: TLS / certificate
```bash
echo | openssl s_client -connect target.com:443 -servername target.com 2>/dev/null | openssl x509 -noout -text
```
Extract SANs (pivot to more domains), issuer, expiry.

### Step 4: Cloud / mobile signals
CloudFront/S3/Azure/GCP headers and metadata → cloud surface; app-store links,
deep-link schemes, `/.well-known/assetlinks.json` / `apple-app-site-association`
→ mobile surface.

## Output to record
technologies[], waf, certificates[] → `asset-map.json`.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Log notable stacks/WAFs/AI/cloud signals.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type technology --confidence confirmed --name "Express.js" --version "4.x" \
  --tech-category framework --tag needs-specter
```
AI/chat widget → `needs-artemis`; cloud provider/origin → `needs-nimbus`; app-link metadata → `needs-nomad`; WAF → note for `waf-bypass`. (cloud/mobile tags apply once those agents are enabled.)
