---
name: api-recon
description: Full API reconnaissance and attack surface mapping. Use at the start of any engagement to discover endpoints, parameters, authentication mechanisms, and technology stack.
allowed-tools: Read, Grep, Glob, Bash
---

# API Reconnaissance Skill

## When to Use
- Beginning of any API security assessment
- When discovering new API endpoints or services
- When mapping attack surface for bug bounty targets

## Tool Chain

### 1. WAF Detection (always first)
    wafw00f -a TARGET -o reports/raw/waf.json -f json

### 2. Web Crawling with JS Parsing
    katana -u TARGET -d 5 -jc -silent -f qurl | sort -u > reports/raw/endpoints.txt
    katana -u TARGET -d 3 -jc -silent | grep -E ".js" | sort -u > reports/raw/js_files.txt

### 3. JavaScript Analysis
    python3 linkfinder.py -i JS_URL -o cli
    python3 SecretFinder.py -i JS_URL -e -o cli
    getJS -url TARGET --complete --resolve

### 4. API Route Brute-Forcing
    kr scan TARGET -A=apiroutes-210328:20000 -x 5 -j 100 --fail-status-codes 400,401,404,403,501,502,426,411
    ffuf -w wordlists/api-endpoints.txt -u TARGET/FUZZ -mc all -fc 404

### 5. API Documentation Discovery
Check: /swagger.json /swagger-ui.html /openapi.json /api-docs /v2/api-docs
/v3/api-docs /.well-known/openid-configuration /graphql /graphiql /playground

### 6. HTTP Method Enumeration
    ffuf -w wordlists/http-methods.txt -u TARGET/endpoint -X FUZZ -mc all -fc 405

### 7. Hidden Parameter Discovery
    arjun -u TARGET/endpoint -m JSON
    arjun -i reports/raw/endpoints.txt -m JSON -oJ reports/raw/params.json -t 5

### 8. Version Testing
Always try: /v1/, /v2/, /v3/, /api/v1/, /api/v2/, /api/latest/, /api/beta/

## Output
Save structured results to reports/raw/recon-TIMESTAMP.json

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Recon rarely yields a standalone finding. If it does (live secret, sensitive shadow endpoint), prove the secret is VALID / the endpoint returns sensitive data before confirming.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by specter
```
