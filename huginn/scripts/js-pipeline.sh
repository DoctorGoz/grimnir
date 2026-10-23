#!/usr/bin/env bash
# =============================================================================
# js-pipeline.sh — HUGINN multi-phase JavaScript analysis pipeline
# =============================================================================
# Replaces the single-linkfinder-call pattern with systematic per-file processing.
#
# Phases:
#   1. COLLECT    — katana + gospider + getJS + gau/wayback → js-urls.txt
#   2. DOWNLOAD   — parallel curl each JS URL → js/raw/
#   3. BEAUTIFY   — js-beautify / prettier each file → js/beautified/
#   4. EXTRACT    — linkfinder per file → js-endpoints.txt (annotated)
#   5. SECRETS    — secretfinder per file → js-secrets.txt (annotated)
#   6. FINGERPRINT— detect frameworks/bundlers/libraries → js-stack.json
#   7. CONFIGS    — grep for Firebase/S3/API URLs → js-interesting.txt + intel
#   8. POPULATE   — update asset-map.json js_analysis fields
#
# Usage:
#   huginn/scripts/js-pipeline.sh --project-dir DIR --target TARGET [OPTIONS]
#
# Options:
#   --project-dir DIR     Absolute path to engagement directory (required)
#   --target TARGET       Target URL or domain (required)
#   --skip-download       Skip Phase 2 (use existing js/raw/ files)
#   --skip-beautify       Skip Phase 3
#   --historical          Also recover historical JS bundles via Wayback CDX (slower)
#   --header "H: V"       Custom header for curl downloads (repeatable)
#
# Output:
#   $PROJECT_DIR/recon/js-urls.txt          Collected JS URLs
#   $PROJECT_DIR/recon/js-urls-count.txt    URL count (for asset map)
#   $PROJECT_DIR/recon/js/raw/              Downloaded JS files
#   $PROJECT_DIR/recon/js/beautified/       Beautified JS files
#   $PROJECT_DIR/recon/js-endpoints.txt     Extracted endpoints (annotated)
#   $PROJECT_DIR/recon/js-secrets.txt       Extracted secrets (annotated)
#   $PROJECT_DIR/recon/js-interesting.txt   Interesting strings/configs
#   $PROJECT_DIR/recon/js-stack.json        Framework/bundler fingerprint
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()   { printf "${CYAN}[*]${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[!]${NC} %s\n" "$*" >&2; }

usage() {
    cat <<'HELPEOF'
Usage: huginn/scripts/js-pipeline.sh --project-dir DIR --target TARGET [OPTIONS]

Multi-phase JavaScript analysis pipeline for systematic JS recon.

Options:
  --project-dir DIR     Absolute path to engagement directory (required)
  --target TARGET       Target URL (required)
  --skip-download       Skip Phase 2 download (use existing js/raw/)
  --skip-beautify       Skip Phase 3 beautification
  --historical          Also recover historical JS bundles via Wayback CDX (slower)
  --header "H: V"       Custom header for curl downloads (repeatable)

Output:
  recon/js-urls.txt          Collected JS URLs
  recon/js-urls-count.txt    URL count
  recon/js/raw/              Downloaded JS
  recon/js/beautified/       Beautified JS
  recon/js-endpoints.txt     Extracted endpoints (annotated)
  recon/js-secrets.txt       Extracted secrets (annotated)
  recon/js-interesting.txt   Interesting strings/configs
  recon/js-stack.json        Fingerprint results
HELPEOF
    exit 0
}

# ── Parse arguments ──
PROJECT_DIR=""
TARGET=""
SKIP_DOWNLOAD=false
SKIP_BEAUTIFY=false
HISTORICAL=false
HEADERS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)   PROJECT_DIR="$2"; shift 2 ;;
        --target)        TARGET="$2"; shift 2 ;;
        --skip-download) SKIP_DOWNLOAD=true; shift ;;
        --skip-beautify) SKIP_BEAUTIFY=true; shift ;;
        --historical)    HISTORICAL=true; shift ;;
        --header)        HEADERS+=("$2"); shift 2 ;;
        --help|-h)       usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir is required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be absolute" >&2; exit 1; }
[[ -z "$TARGET" ]] && { echo "Error: --target is required" >&2; exit 1; }

RECON_DIR="$PROJECT_DIR/recon"
LOG_DIR="$PROJECT_DIR/logs"
JS_DIR="$RECON_DIR/js"
mkdir -p "$RECON_DIR" "$LOG_DIR" "$JS_DIR"/{raw,beautified}

# The program's egress proxy (roe.json / GRIMNIR_PROXY) carries the target traffic: katana and the
# curl downloads ride it; gospider and getJS open their own connections, so they are skipped when
# proxied rather than run direct. gau/waybackurls/CDX are third-party archive lookups, not target
# traffic, and stay direct. An unusable proxy refuses the run (exit 4).
source "$(cd "$(dirname "$0")/../.." && pwd)/scripts/egress-env.sh"
egress_init "$PROJECT_DIR" || exit 4
PROXY_ARGS=()
[[ -n "${GRIMNIR_PROXY:-}" ]] && PROXY_ARGS=(-proxy "${GRIMNIR_PROXY/socks5h:\/\//socks5://}")

HEADER_ARGS=()
for h in "${HEADERS[@]}"; do
    HEADER_ARGS+=(-H "$h")
done

# ════════════════════════════════════════════════════════
# Phase 1: COLLECT
# ════════════════════════════════════════════════════════
log "Phase 1/8: Collecting JS URLs..."

# katana crawl for JS
if command -v katana &>/dev/null; then
    log "  katana crawl..."
    # KATANA_RATE honors a program's requested crawl rate (default 20 preserves
    # the historical standalone behavior).
    # Bounded crawl: KATANA_DURATION overrides the 120s default. A JS-URL collection
    # pass must not become an unbounded whole-site crawl; timeout is a hard backstop
    # for the version that ignores -ct.
    timeout 300 katana -u "$TARGET" -d 3 -jc -kf all -fs fqdn -silent \
        -rl "${KATANA_RATE:-20}" -ct "${KATANA_DURATION:-120s}" "${HEADER_ARGS[@]}" ${PROXY_ARGS[@]+"${PROXY_ARGS[@]}"} 2>"$LOG_DIR/katana-js.log" \
        | grep -E '\.js(\?|#|$)' \
        | sort -u > "$RECON_DIR/js-urls-katana.txt" || true
    ok "  katana: $(wc -l < "$RECON_DIR/js-urls-katana.txt" 2>/dev/null || echo 0) JS URLs"
fi

# gospider
if [[ -n "${GRIMNIR_PROXY:-}" ]]; then
    log "  gospider/getJS skipped (cannot ride the program's egress proxy)"
elif command -v gospider &>/dev/null; then
    log "  gospider crawl..."
    gospider -s "$TARGET" -d 2 -c 10 --js 2>"$LOG_DIR/gospider-js.log" \
        | grep -E '\.js(\?|#|$)' \
        | sort -u > "$RECON_DIR/js-urls-gospider.txt" || true
    ok "  gospider: $(wc -l < "$RECON_DIR/js-urls-gospider.txt" 2>/dev/null || echo 0) JS URLs"
fi

# getJS
if [[ -z "${GRIMNIR_PROXY:-}" ]] && command -v getJS &>/dev/null; then
    log "  getJS..."
    getJS --url "$TARGET" --complete --resolve 2>"$LOG_DIR/getJS.log" \
        | sort -u > "$RECON_DIR/js-urls-getjs.txt" || true
    ok "  getJS: $(wc -l < "$RECON_DIR/js-urls-getjs.txt" 2>/dev/null || echo 0) JS URLs"
fi

# URL archives filtered to .js
if command -v gau &>/dev/null; then
    timeout 30 gau "$TARGET" 2>/dev/null | grep -E '\.js(\?|#|$)' \
        | sort -u > "$RECON_DIR/js-urls-gau.txt" || true
fi
if command -v waybackurls &>/dev/null; then
    timeout 30 waybackurls "$TARGET" 2>/dev/null | grep -E '\.js(\?|#|$)' \
        | sort -u > "$RECON_DIR/js-urls-wayback.txt" || true
fi

# Historical JS via Wayback CDX (opt-in, --historical). gau/waybackurls only LIST
# current archive URLs; CDX enumerates one snapshot per unique historical JS URL and
# emits replay URLs (web/<ts>id_/<orig>) so Phase 2 fetches the OLD bundle bytes —
# recovering endpoints/secrets that were stripped from the current build. mimetype
# is filtered server-side, so these are JS even when the URL lacks a .js suffix.
if [[ "$HISTORICAL" == true ]]; then
    log "  Wayback CDX historical JS..."
    host=$(printf '%s' "$TARGET" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s/:.*$//')
    cdx="http://web.archive.org/cdx/search/cdx?url=${host}/*&output=json&fl=timestamp,original&filter=mimetype:application/javascript&filter=statuscode:200&collapse=urlkey&limit=500"
    timeout 60 curl -sL --noproxy '*' "$cdx" 2>"$LOG_DIR/cdx.log" \
        | jq -r '.[1:][]? | "http://web.archive.org/web/\(.[0])id_/\(.[1])"' 2>/dev/null \
        | sort -u > "$RECON_DIR/js-urls-cdx.txt" || true
    ok "  CDX: $(wc -l < "$RECON_DIR/js-urls-cdx.txt" 2>/dev/null || echo 0) historical JS snapshots"
fi

# Merge + deduplicate.
#
# Two guards here, and both earned their place. `js-urls-count.txt` is written three
# lines below, into this same directory, so a bare `js-urls-*.txt` glob re-ingests it
# on the NEXT run and last run's count becomes this run's "URL". curl reads a bare
# number as an integer-form IP -- `0` is 0.0.0.0, i.e. loopback -- so the pipeline then
# fetched the operator's own machine and analysed the reply as though it were target
# JS, complete with "secrets". The count also stops being 0, so the no-JS early exit
# below never fires again and every later phase runs on the junk.
#
# So: exclude the metadata file from the glob (by name, so a new js-urls-<source>.txt
# collector is still picked up automatically), and independently require every merged
# line to be an absolute http(s) URL. The filter is the load-bearing one -- it means no
# future junk in a collector's output can become an outbound request.
find "$RECON_DIR" -maxdepth 1 -type f -name 'js-urls-*.txt' ! -name 'js-urls-count.txt' \
    -exec cat {} + 2>/dev/null \
    | grep -aE '^https?://[^[:space:]]+$' \
    | sort -u > "$RECON_DIR/js-urls.txt" || true
[[ -f "$RECON_DIR/js-urls.txt" ]] || : > "$RECON_DIR/js-urls.txt"
JS_COUNT=$(wc -l < "$RECON_DIR/js-urls.txt" 2>/dev/null || echo 0)
echo "$JS_COUNT" > "$RECON_DIR/js-urls-count.txt"
ok "Phase 1 complete: $JS_COUNT unique JS URLs collected"

[[ "$JS_COUNT" -eq 0 ]] && { warn "No JS URLs found — pipeline complete with no analysis"; exit 0; }

# ════════════════════════════════════════════════════════
# Phase 2: DOWNLOAD
# ════════════════════════════════════════════════════════
if [[ "$SKIP_DOWNLOAD" == true ]]; then
    log "Phase 2/8: SKIPPED (--skip-download)"
else
    log "Phase 2/8: Downloading JS files (parallel x4)..."
    download_one() {
        local url="$1" out="$2" headers=("${@:3}")
        # Hash URL for filename
        local fname
        fname=$(echo "$url" | sha256sum | cut -c1-16)
        # Skip if already downloaded
        [[ -f "$out/${fname}.js" ]] && return 0
        curl -sL --max-time 15 "${headers[@]}" "$url" -o "$out/${fname}.js" 2>/dev/null && \
            echo "[$fname] $url" || true
    }
    export -f download_one
    export JS_DIR HEADER_ARGS
    head -100 "$RECON_DIR/js-urls.txt" | xargs -P 4 -I {} bash -c \
        'download_one "$1" "$JS_DIR/raw" "${HEADER_ARGS[@]}"' _ {} \
        > "$RECON_DIR/js-download-log.txt" 2>"$LOG_DIR/js-download.log" || true
    DOWNLOADED=$(find "$JS_DIR/raw" -name '*.js' -type f 2>/dev/null | wc -l)
    ok "Phase 2 complete: $DOWNLOADED files downloaded"
fi

# ════════════════════════════════════════════════════════
# Phase 3: BEAUTIFY
# ════════════════════════════════════════════════════════
if [[ "$SKIP_BEAUTIFY" == true ]]; then
    log "Phase 3/8: SKIPPED (--skip-beautify)"
    BEAUTIFY_DIR="$JS_DIR/raw"  # Use raw as source for subsequent phases
else
    log "Phase 3/8: Beautifying..."
    BEAUTIFIER=""
    command -v js-beautify &>/dev/null && BEAUTIFIER="js-beautify"
    [[ -z "$BEAUTIFIER" ]] && command -v prettier &>/dev/null && BEAUTIFIER="prettier --parser babel"
    if [[ -n "$BEAUTIFIER" ]]; then
        for f in "$JS_DIR"/raw/*.js; do
            [[ -f "$f" ]] || continue
            base=$(basename "$f")
            $BEAUTIFIER "$f" > "$JS_DIR/beautified/$base" 2>/dev/null || cp "$f" "$JS_DIR/beautified/$base"
        done
        ok "Phase 3 complete: $(find "$JS_DIR/beautified" -name '*.js' | wc -l) files beautified"
    else
        warn "No js-beautify or prettier found — copying raw as beautified"
        cp "$JS_DIR"/raw/*.js "$JS_DIR/beautified/" 2>/dev/null || true
    fi
    BEAUTIFY_DIR="$JS_DIR/beautified"
fi

# ════════════════════════════════════════════════════════
# Phase 4: EXTRACT ENDPOINTS
# ════════════════════════════════════════════════════════
log "Phase 4/8: Extracting endpoints..."
> "$RECON_DIR/js-endpoints.txt"

LINKFINDER_CMD=""
command -v linkfinder &>/dev/null && LINKFINDER_CMD="linkfinder"
[[ -z "$LINKFINDER_CMD" && -x /usr/local/bin/linkfinder ]] && LINKFINDER_CMD="/usr/local/bin/linkfinder"

if [[ -n "$LINKFINDER_CMD" ]]; then
    for f in "$BEAUTIFY_DIR"/*.js; do
        [[ -f "$f" ]] || continue
        fname=$(basename "$f" .js)
        src=$(grep "\[$fname\]" "$RECON_DIR/js-download-log.txt" 2>/dev/null | head -1 | sed 's/\[.*\] //' || echo "unknown")
        echo "  [source: $src]" >> "$RECON_DIR/js-endpoints.txt"
        $LINKFINDER_CMD -i "$f" -o cli 2>/dev/null | head -50 >> "$RECON_DIR/js-endpoints.txt" || true
    done
    ok "Phase 4 complete: $(wc -l < "$RECON_DIR/js-endpoints.txt" 2>/dev/null || echo 0) lines"
else
    warn "linkfinder not found — skipping endpoint extraction"
fi

# ════════════════════════════════════════════════════════
# Phase 5: EXTRACT SECRETS
# ════════════════════════════════════════════════════════
log "Phase 5/8: Extracting secrets..."
> "$RECON_DIR/js-secrets.txt"

SECRETFINDER_CMD=""
command -v secretfinder &>/dev/null && SECRETFINDER_CMD="secretfinder"
[[ -z "$SECRETFINDER_CMD" && -x /usr/local/bin/secretfinder ]] && SECRETFINDER_CMD="/usr/local/bin/secretfinder"

SECRET_PATTERNS=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/../wordlists/js-secret-patterns.txt" ]] && SECRET_PATTERNS="$SCRIPT_DIR/../wordlists/js-secret-patterns.txt"

for f in "$BEAUTIFY_DIR"/*.js; do
    [[ -f "$f" ]] || continue
    fname=$(basename "$f" .js)
    src=$(grep "\[$fname\]" "$RECON_DIR/js-download-log.txt" 2>/dev/null | head -1 | sed 's/\[.*\] //' || echo "unknown")
    echo "  [source: $src]" >> "$RECON_DIR/js-secrets.txt"
    if [[ -n "$SECRETFINDER_CMD" ]]; then
        $SECRETFINDER_CMD -i "$f" -o cli 2>/dev/null | head -30 >> "$RECON_DIR/js-secrets.txt" || true
    fi
    # Additional grep for custom patterns
    if [[ -n "$SECRET_PATTERNS" ]]; then
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" =~ ^# ]] && continue
            grep -n "$pattern" "$f" 2>/dev/null | head -3 >> "$RECON_DIR/js-secrets.txt" || true
        done < "$SECRET_PATTERNS"
    fi
done
ok "Phase 5 complete: $(wc -l < "$RECON_DIR/js-secrets.txt" 2>/dev/null || echo 0) lines"

# ════════════════════════════════════════════════════════
# Phase 6: FINGERPRINT
# ════════════════════════════════════════════════════════
log "Phase 6/8: Fingerprinting JS frameworks..."

STACK_JSON='{"frameworks":[],"bundlers":[],"libraries":[]}'

detect_fw() {
    local dir="$1"
    local fw=() bundlers=() libs=()
    # Framework detection
    grep -rl 'React\.createElement\|__REACT_DEVTOOLS_GLOBAL_HOOK__\|react-dom\|from "react"' "$dir" 2>/dev/null | head -1 | grep -q . && fw+=("React")
    grep -rl '__vue__\|Vue\.component\|createApp\|from "vue"' "$dir" 2>/dev/null | head -1 | grep -q . && fw+=("Vue")
    grep -rl 'ng\.core\|@angular/core\|NgModule' "$dir" 2>/dev/null | head -1 | grep -q . && fw+=("Angular")
    grep -rl 'from "svelte"\|SvelteComponent' "$dir" 2>/dev/null | head -1 | grep -q . && fw+=("Svelte")
    grep -rl 'jQuery\|$\.fn\.' "$dir" 2>/dev/null | head -1 | grep -q . && fw+=("jQuery")
    # Bundler detection
    grep -rl 'webpackJsonp\|__webpack_require__\|webpackChunk' "$dir" 2>/dev/null | head -1 | grep -q . && bundlers+=("webpack")
    grep -rl 'import.meta\.hot\|vite' "$dir" 2>/dev/null | head -1 | grep -q . && bundlers+=("Vite")
    grep -rl '__parcel_requiire__\|parcelRequire' "$dir" 2>/dev/null | head -1 | grep -q . && bundlers+=("Parcel")
    grep -rl 'System\.register\|System\.import' "$dir" 2>/dev/null | head -1 | grep -q . && bundlers+=("SystemJS")
    # Library detection
    grep -rl 'lodash\|_\.VERSION\|_.extend' "$dir" 2>/dev/null | head -1 | grep -q . && libs+=("lodash")
    grep -rl 'axios' "$dir" 2>/dev/null | head -1 | grep -q . && libs+=("axios")
    grep -rl 'moment' "$dir" 2>/dev/null | head -1 | grep -q . && libs+=("moment")
    grep -rl 'd3\.\|from "d3"' "$dir" 2>/dev/null | head -1 | grep -q . && libs+=("d3")
    local fw_s="${fw[*]:-none}"
    local bd_s="${bundlers[*]:-none}"
    local lb_s="${libs[*]:-none}"
    jq -n --arg fw "$fw_s" --arg bd "$bd_s" --arg lb "$lb_s" \
        '{frameworks: $fw, bundlers: $bd, libraries: $lb}'
}

STACK_JSON=$(detect_fw "$BEAUTIFY_DIR")
echo "$STACK_JSON" | jq . > "$RECON_DIR/js-stack.json" 2>/dev/null || true
ok "Phase 6 complete"

# ════════════════════════════════════════════════════════
# Phase 7: FIND CONFIGS
# ════════════════════════════════════════════════════════
log "Phase 7/8: Finding configurations and interesting strings..."
> "$RECON_DIR/js-interesting.txt"

# Firebase configs
grep -rh 'firebaseConfig\|apiKey.*AIza\|authDomain\|projectId.*firebase' "$BEAUTIFY_DIR" 2>/dev/null | head -20 >> "$RECON_DIR/js-interesting.txt" || true

# AWS/S3 URLs
grep -rh 's3\.amazonaws\.com\|s3://\|cloudfront\.net\|amazonaws\.com' "$BEAUTIFY_DIR" 2>/dev/null | head -20 >> "$RECON_DIR/js-interesting.txt" || true

# GCP
grep -rh 'storage\.googleapis\.com\|gcp-[a-z0-9]*\.appspot\.com' "$BEAUTIFY_DIR" 2>/dev/null | head -20 >> "$RECON_DIR/js-interesting.txt" || true

# API base URLs
grep -rhE '(baseURL|API_URL|apiUrl|api_url|BASE_URL)\s*[:=]\s*["\x27]' "$BEAUTIFY_DIR" 2>/dev/null | head -30 >> "$RECON_DIR/js-interesting.txt" || true

# Internal IPs
grep -rhE '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b' "$BEAUTIFY_DIR" 2>/dev/null | head -20 >> "$RECON_DIR/js-interesting.txt" || true

# OAuth/SSO configs
grep -rh 'client_secret\|client_id.*["\x27][A-Za-z0-9_-]\{20,\}\|redirect_uri\|openid-configuration' "$BEAUTIFY_DIR" 2>/dev/null | head -20 >> "$RECON_DIR/js-interesting.txt" || true

# Hosted identity providers (auth0/okta/cognito) — name the tenant for IdP-side tests
grep -rhoE '[a-zA-Z0-9.-]+\.(auth0\.com|okta\.com|amazoncognito\.com)' "$BEAUTIFY_DIR" 2>/dev/null | sort -u | head -20 >> "$RECON_DIR/js-interesting.txt" || true

# GraphQL + WebSocket endpoints (hidden API surface beyond REST)
grep -rhoE 'wss?://[a-zA-Z0-9./_-]+|https?://[a-zA-Z0-9./_-]*graphql[a-zA-Z0-9./_-]*' "$BEAUTIFY_DIR" 2>/dev/null | sort -u | head -20 >> "$RECON_DIR/js-interesting.txt" || true

# Algolia / Segment app IDs (frequently over-permissioned client keys)
grep -rhE '(algolia|segment)[A-Za-z_]*[[:space:]]*[:=][[:space:]]*["\x27][A-Za-z0-9]{8,}' "$BEAUTIFY_DIR" 2>/dev/null | head -10 >> "$RECON_DIR/js-interesting.txt" || true

ok "Phase 7 complete: $(wc -l < "$RECON_DIR/js-interesting.txt" 2>/dev/null || echo 0) lines"

# ════════════════════════════════════════════════════════
# Phase 8: POPULATE ASSET MAP
# ════════════════════════════════════════════════════════
log "Phase 8/8: Populating asset-map.json..."

ASSET_MAP="$PROJECT_DIR/asset-map.json"
if [[ -f "$ASSET_MAP" ]]; then
    # Update files_analyzed
    if [[ -f "$RECON_DIR/js-urls-count.txt" ]]; then
        JS_COUNT=$(cat "$RECON_DIR/js-urls-count.txt")
        TMP=$(mktemp)
        jq --argjson c "$JS_COUNT" '.js_analysis.files_analyzed = $c' "$ASSET_MAP" > "$TMP" && mv "$TMP" "$ASSET_MAP"
        ok "  files_analyzed = $JS_COUNT"
    fi
    # Update api_endpoints_found
    if [[ -f "$RECON_DIR/js-endpoints.txt" && -s "$RECON_DIR/js-endpoints.txt" ]]; then
        JS_EPS=$(head -200 "$RECON_DIR/js-endpoints.txt" | grep -v '^\s*$' | grep -v '^\[' | jq -R . | jq -s .)
        TMP=$(mktemp)
        jq --argjson eps "$JS_EPS" '.js_analysis.api_endpoints_found = $eps' "$ASSET_MAP" > "$TMP" && mv "$TMP" "$ASSET_MAP"
        ok "  api_endpoints_found populated"
    fi
    # Update secrets_found
    if [[ -f "$RECON_DIR/js-secrets.txt" && -s "$RECON_DIR/js-secrets.txt" ]]; then
        JS_SECRETS=$(head -50 "$RECON_DIR/js-secrets.txt" | grep -v '^\s*$' | grep -v '^\[' | jq -R . | jq -s .)
        TMP=$(mktemp)
        jq --argjson s "$JS_SECRETS" '.js_analysis.secrets_found = $s' "$ASSET_MAP" > "$TMP" && mv "$TMP" "$ASSET_MAP"
        ok "  secrets_found populated"
    fi
    # Update interesting_strings
    if [[ -f "$RECON_DIR/js-interesting.txt" && -s "$RECON_DIR/js-interesting.txt" ]]; then
        JS_INT=$(head -100 "$RECON_DIR/js-interesting.txt" | jq -R . | jq -s .)
        TMP=$(mktemp)
        jq --argjson s "$JS_INT" '.js_analysis.interesting_strings = $s' "$ASSET_MAP" > "$TMP" && mv "$TMP" "$ASSET_MAP"
        ok "  interesting_strings populated"
    fi
    ok "Phase 8 complete: asset-map.json updated"
else
    warn "No asset-map.json at $ASSET_MAP — skipping population"
fi

echo ""
ok "JS pipeline complete"
echo "  JS URLs:        $RECON_DIR/js-urls.txt ($JS_COUNT unique)"
echo "  Downloaded:     $JS_DIR/raw/ ($(find "$JS_DIR/raw" -name '*.js' 2>/dev/null | wc -l) files)"
echo "  Endpoints:      $RECON_DIR/js-endpoints.txt"
echo "  Secrets:        $RECON_DIR/js-secrets.txt"
echo "  Configs:        $RECON_DIR/js-interesting.txt"
echo "  Stack:          $RECON_DIR/js-stack.json"
echo ""
echo "Next: run huginn/scripts/asset-map.sh to rebuild the asset map"
