---
name: content-discovery
description: Endpoint and content discovery — crawling, archives, directory brute, robots/sitemap. HUGINN Phase 4. Builds the endpoint inventory specialists test.
allowed-tools: Read, Grep, Glob, Bash
---

# Content & Endpoint Discovery Skill (HUGINN Phase 4)

Enumerate routes, parameters, and hidden paths so specialists have a concrete
endpoint inventory instead of guessing.

## Methodology

### Step 1: Crawl
```bash
katana -u https://target.com -d 3 -jc -kf all -silent
gospider -s https://target.com -d 2 -c 10
```

### Step 2: Historical URLs (archives)
```bash
gau target.com ; waybackurls target.com   # old/deprecated endpoints often weaker
```

### Step 3: Known files
`/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/security.txt`, `/openapi.json`,
`/swagger.json`, `/.git/`, `/.env` (note, don't exploit — route to specialist).

### Step 4: Directory/route brute (if authorized + rate allows)
```bash
ffuf -u https://target.com/FUZZ -w wordlist -mc 200,204,301,302,401,403 -of json
```
Prefer API-aware wordlists for API targets.

### Step 5: Parameter mining
Collect parameter names from crawl/archives for specialists' fuzzing.

## Output to record
endpoints[] with url, method, params, auth-required → `asset-map.json` `endpoints`.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Log high-value endpoints as you find them.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type endpoint --confidence high --url "https://target.com/api/v1/internal/users" \
  --method GET --tag needs-specter --tag high-value
```
API/admin/internal routes → `needs-specter` (+`high-value`); AI/chat endpoints → `needs-artemis`; exposed config/secret files → flag `high-value`.
