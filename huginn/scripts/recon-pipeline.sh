#!/bin/bash
set -euo pipefail

# HUGINN Recon Pipeline
# Unified reconnaissance workflow for all target types
# Produces raw recon data in $PROJECT_DIR/recon/

usage() {
    cat <<'EOF'
Usage: huginn/scripts/recon-pipeline.sh TARGET [OPTIONS]

Arguments:
  TARGET                 Primary target (URL, domain, IP, or CIDR)

Options:
  --project-dir DIR      Absolute path to project directory (required)
  --type TYPE            Target type: web, api, network, ai, mixed (default: mixed)
  --scope-file FILE      Path to scope.md for in-scope/out-of-scope filtering
  --rate-limit N         Max requests per second (default: 10)
  --header "H: V"        Custom header sent by active tools (httpx/katana/curl).
                         Use for required program identifiers, e.g. X-Bug-Bounty.
  --light                Light profile: passive + httpx + fingerprint + crawl/JS,
                         but NEVER a port scan. For bounded unattended recon.
  --no-subdomain-enum    Skip subdomain enumeration but keep URL-archive (gau/
                         wayback). For specific hosts where enum is pointless.
  --api-probe            Probe common API paths (/v1, /graphql, /openapi.json...)
                         on the target host; record status + content-type.
  --skip-passive         Skip passive recon (subdomain enum, OSINT)
  --skip-active          Skip active recon (port scan, crawl)
  --skip-js              Skip JavaScript analysis
  --require-tools        Exit 3 if any tool this profile needs is missing from
                         PATH, instead of running a silently degraded pipeline.
                         Use for unattended/cron runs.
  -h, --help             Show this help

Output:
  $PROJECT_DIR/recon/           Raw recon data files
  $PROJECT_DIR/recon/preflight.json  Tool inventory + degraded flag for this run
  $PROJECT_DIR/asset-map.json   Structured asset inventory (built by asset-map.sh)

Examples:
  huginn/scripts/recon-pipeline.sh https://target.com --project-dir $HOME/workspace/target
  huginn/scripts/recon-pipeline.sh 10.10.10.0/24 --project-dir $HOME/workspace/lab --type network
EOF
    exit 0
}

# ── Parse arguments ──
TARGET=""
PROJECT_DIR=""
TARGET_TYPE="mixed"
SCOPE_FILE=""
RATE_LIMIT=10
HEADER=""
LIGHT=false
SKIP_PASSIVE=false
SKIP_SUBENUM=false
API_PROBE=false
SKIP_ACTIVE=false
SKIP_JS=false
REQUIRE_TOOLS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir) PROJECT_DIR="$2"; shift 2 ;;
        --type) TARGET_TYPE="$2"; shift 2 ;;
        --scope-file) SCOPE_FILE="$2"; shift 2 ;;
        --rate-limit) RATE_LIMIT="$2"; shift 2 ;;
        --header) HEADER="$2"; shift 2 ;;
        --light) LIGHT=true; shift ;;
        --no-subdomain-enum) SKIP_SUBENUM=true; shift ;;
        --api-probe) API_PROBE=true; shift ;;
        --skip-passive) SKIP_PASSIVE=true; shift ;;
        --skip-active) SKIP_ACTIVE=true; shift ;;
        --skip-js) SKIP_JS=true; shift ;;
        --require-tools) REQUIRE_TOOLS=true; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) [[ -z "$TARGET" ]] && TARGET="$1" || { echo "Unexpected argument: $1" >&2; exit 1; }; shift ;;
    esac
done

# Build optional header args for tools that hit the target directly.
HTTPX_HDR=();  KATANA_HDR=();  CURL_HDR=()
if [[ -n "$HEADER" ]]; then
    HTTPX_HDR=(-H "$HEADER"); KATANA_HDR=(-H "$HEADER"); CURL_HDR=(-H "$HEADER")
fi

[[ -z "$TARGET" ]] && { echo "Error: TARGET is required" >&2; usage; }
[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir is required" >&2; exit 1; }
[[ "$PROJECT_DIR" != /* ]] && { echo "Error: --project-dir must be absolute" >&2; exit 1; }

RECON_DIR="$PROJECT_DIR/recon"
LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$RECON_DIR" "$LOG_DIR"

# ── Egress ──
# A program's proxy (roe.json "proxy" / GRIMNIR_PROXY) carries ALL target traffic. egress_init exports
# it for curl and the Go tools; a configured-but-unusable proxy refuses the whole run (exit 4).
# What cannot ride a proxy (raw-socket scans, whatweb, openssl s_client) is SKIPPED when proxied,
# never run direct, and named in preflight.json "skipped_proxied". Passive third-party lookups
# (subfinder, assetfinder, findomain, gau, waybackurls) and dnsx (public resolvers, not the target)
# are not target traffic and stay direct.
source "$(cd "$(dirname "$0")/../.." && pwd)/scripts/egress-env.sh"
egress_init "$PROJECT_DIR" || exit 4
SKIPPED_PROXIED=()
PROXY_ARGS=()   # httpx/katana/wafw00f take their own proxy flag; they get the Go-style scheme
if [[ -n "${GRIMNIR_PROXY:-}" ]]; then
    GO_PROXY="${GRIMNIR_PROXY/socks5h:\/\//socks5://}"   # Go's dialer sends the hostname to a socks5 proxy
    PROXY_ARGS=(-proxy "$GO_PROXY")
    echo "Egress:      $GRIMNIR_PROXY (all target traffic; raw-socket tools skipped)"
fi

DOMAIN=""
if [[ "$TARGET" =~ ^https?:// ]]; then
    DOMAIN=$(echo "$TARGET" | sed -E 's|https?://([^/]+).*|\1|')
elif [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    DOMAIN="$TARGET"
else
    DOMAIN="$TARGET"
fi

# ── Scope filter ──
# --scope-file gates every host list before an active tool touches it (dnsx, naabu, httpx). Passive
# sources still see the whole domain: enumeration is how exclusions get discovered, not a test of them.
# scope.py also reads the engagement's structured-scope JSON and host lists from PROJECT_DIR. With no
# parseable scope the list passes through unfiltered and the run says so (recon ran unscoped before
# this flag did anything; the fire-time gate in the calling harness fails closed on its own).
SCOPE_PY="$(cd "$(dirname "$0")/../.." && pwd)/scripts/scope.py"
scope_filter() {  # scope_filter FILE — rewrite FILE to its in-scope lines; dropped ones are logged
    local f="$1" kept
    [[ -n "$SCOPE_FILE" && -s "$f" && -f "$SCOPE_PY" ]] || return 0
    kept="$(mktemp)"
    if python3 "$SCOPE_PY" filter --project-dir "$PROJECT_DIR" --scope-md "$SCOPE_FILE" \
            --passthrough-unscoped < "$f" > "$kept" 2>>"$LOG_DIR/scope.log"; then
        comm -23 <(sort -u "$f") <(sort -u "$kept") >> "$RECON_DIR/scope-dropped-hosts.txt"
        echo "  [scope] $(tail -1 "$LOG_DIR/scope.log")"
        mv "$kept" "$f"
    else
        rm -f "$kept"
        echo "  [scope] !! filter failed on $(basename "$f"); see logs/scope.log" >&2
    fi
}

echo "=== HUGINN Recon Pipeline ==="
echo "Target:      $TARGET"
echo "Domain:      $DOMAIN"
echo "Type:        $TARGET_TYPE"
echo "Project:     $PROJECT_DIR"
echo "Rate Limit:  $RATE_LIMIT req/s"
if [[ -n "$SCOPE_FILE" ]]; then
    echo "Scope:       $SCOPE_FILE"
    if [[ -f "$SCOPE_PY" ]] && ! python3 "$SCOPE_PY" check --project-dir "$PROJECT_DIR" \
            --scope-md "$SCOPE_FILE" "$TARGET" >/dev/null 2>&1; then
        # A warning, not a stop: an apex seed under a `*.acme.com` scope is not itself in scope,
        # but it is still the right enumeration root.
        echo "Scope:       !! target $TARGET is not an in-scope host (seed only; its subdomains are filtered)"
    fi
fi
[[ "$LIGHT" == "true" ]] && echo "Profile:     light (no port scan)"
[[ -n "$HEADER" ]] && echo "Header:      $HEADER"
echo ""

# ── Preflight: tool inventory ──
# Every phase below probes for its tool with `command -v` and skips silently when
# it is absent. That makes a missing binary indistinguishable from a target that
# genuinely had nothing to find, which is the most expensive kind of silent
# failure: the output looks like a clean negative result. Take the inventory once
# up front, say so out loud, and record it next to the findings so a consumer can
# tell "we looked and found nothing" from "we never looked".
MISSING_TOOLS=(); MISSING_DESC=(); PRESENT_TOOLS=()

preflight_check() {  # tool  required|optional  purpose
    if command -v "$1" &>/dev/null; then
        PRESENT_TOOLS+=("$1")
    elif [[ "$2" == "required" ]]; then
        MISSING_TOOLS+=("$1"); MISSING_DESC+=("$1 — $3")
    fi
}

if [[ "$SKIP_PASSIVE" == "false" ]]; then
    [[ "$SKIP_SUBENUM" == "false" ]] && {
        preflight_check subfinder   required "subdomain enumeration"
        preflight_check assetfinder optional "secondary subdomain source"
        preflight_check dnsx        required "DNS resolution"
    }
    preflight_check gau         required "URL archive"
    preflight_check waybackurls required "URL archive"
fi
[[ "$SKIP_ACTIVE" == "false" ]] && preflight_check httpx required "HTTP probing / live-host discovery"
PORT_SCAN=false
[[ "$SKIP_ACTIVE" == "false" && "$LIGHT" == "false" && ( "$TARGET_TYPE" == "network" || "$TARGET_TYPE" == "mixed" ) ]] && PORT_SCAN=true
if [[ -n "${GRIMNIR_PROXY:-}" ]]; then
    # naabu is a raw-socket scanner, whatweb and openssl s_client open their own connections: none
    # can ride the program's proxy, so they do not run. Recorded, so "skipped" is not read as "clean".
    [[ "$PORT_SCAN" == "true" ]] && SKIPPED_PROXIED+=(naabu)
    SKIPPED_PROXIED+=(whatweb openssl)
    PORT_SCAN=false
fi
[[ "$PORT_SCAN" == "true" ]] && preflight_check naabu required "port scan"
[[ "$SKIP_JS" == "false" ]] && preflight_check katana required "crawl / JS discovery"
[[ -z "${GRIMNIR_PROXY:-}" ]] && preflight_check whatweb required "technology fingerprint"
preflight_check wafw00f required "WAF detection"
[[ "$API_PROBE" == "true" ]] && preflight_check curl required "API path probe"

DEGRADED=false
if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    DEGRADED=true
    echo "[preflight] !! DEGRADED — ${#MISSING_TOOLS[@]} tool(s) required by this profile are NOT on PATH:"
    for d in "${MISSING_DESC[@]}"; do echo "[preflight]    MISSING: $d"; done
    echo "[preflight]    PATH=$PATH"
    echo "[preflight]    Results below are INCOMPLETE. Absence of findings is not evidence of absence."
else
    echo "[preflight] ok — ${#PRESENT_TOOLS[@]} tool(s) available for this profile"
fi

# Machine-readable, written where the consumer already looks.
_json_arr() { local out="" x; for x in "$@"; do out+="${out:+, }\"$x\""; done; printf '[%s]' "$out"; }
{
    printf '{\n  "generated": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "profile": {"light": %s, "skip_passive": %s, "skip_subenum": %s, "skip_active": %s, "skip_js": %s, "api_probe": %s, "type": "%s"},\n' \
        "$LIGHT" "$SKIP_PASSIVE" "$SKIP_SUBENUM" "$SKIP_ACTIVE" "$SKIP_JS" "$API_PROBE" "$TARGET_TYPE"
    printf '  "present": %s,\n' "$(_json_arr ${PRESENT_TOOLS[@]+"${PRESENT_TOOLS[@]}"})"
    printf '  "missing": %s,\n' "$(_json_arr ${MISSING_TOOLS[@]+"${MISSING_TOOLS[@]}"})"
    printf '  "skipped_proxied": %s,\n' "$(_json_arr ${SKIPPED_PROXIED[@]+"${SKIPPED_PROXIED[@]}"})"
    printf '  "degraded": %s\n}\n' "$DEGRADED"
} > "$RECON_DIR/preflight.json"

if [[ "$DEGRADED" == "true" && "$REQUIRE_TOOLS" == "true" ]]; then
    echo "[preflight] --require-tools set: refusing to run a degraded pipeline." >&2
    exit 3
fi
echo ""

# ── Phase 1: Passive Recon ──
if [[ "$SKIP_PASSIVE" == "false" && ! "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "[Phase 1] Passive Recon..."

  if [[ "$SKIP_SUBENUM" == "false" ]]; then
    # Subdomain enumeration
    if command -v subfinder &>/dev/null; then
        echo "  [+] subfinder..."
        subfinder -d "$DOMAIN" -silent -o "$RECON_DIR/subdomains-subfinder.txt" 2>"$LOG_DIR/subfinder.log" || true
    fi

    if command -v findomain &>/dev/null; then
        echo "  [+] findomain..."
        findomain -t "$DOMAIN" -u "$RECON_DIR/subdomains-findomain.txt" 2>"$LOG_DIR/findomain.log" || true
    fi

    if command -v assetfinder &>/dev/null; then
        echo "  [+] assetfinder..."
        assetfinder --subs-only "$DOMAIN" > "$RECON_DIR/subdomains-assetfinder.txt" 2>"$LOG_DIR/assetfinder.log" || true
    fi

    # Merge and deduplicate subdomains. Filtered to things that are actually hostnames,
    # for the reason documented at the same merge step in js-pipeline.sh: a glob over a
    # directory this script also writes metadata into will eventually eat its own
    # output, and whatever it eats gets fed to a resolver and then to httpx as a target.
    find "$RECON_DIR" -maxdepth 1 -type f -name 'subdomains-*.txt' ! -name 'subdomains-count.txt' \
        -exec cat {} + 2>/dev/null \
        | grep -aE '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+\.?$' \
        | sort -u > "$RECON_DIR/subdomains.txt" || true
    [[ -f "$RECON_DIR/subdomains.txt" ]] || : > "$RECON_DIR/subdomains.txt"
    SUB_COUNT=$(wc -l < "$RECON_DIR/subdomains.txt" 2>/dev/null || echo 0)
    echo "  [=] $SUB_COUNT unique subdomains found"
    scope_filter "$RECON_DIR/subdomains.txt"

    # DNS resolution
    if command -v dnsx &>/dev/null && [[ -s "$RECON_DIR/subdomains.txt" ]]; then
        echo "  [+] dnsx resolution..."
        dnsx -l "$RECON_DIR/subdomains.txt" -silent -a -resp -o "$RECON_DIR/dns-resolved.txt" 2>"$LOG_DIR/dnsx.log" || true
    fi
  else
    echo "  [=] subdomain enumeration skipped (--no-subdomain-enum)"
  fi

    # URL archive (historical endpoints) — bounded so a huge history can't
    # starve the higher-value httpx / api-probe phases that follow.
    if command -v gau &>/dev/null; then
        echo "  [+] gau (URL archive)..."
        echo "$DOMAIN" | timeout 30 gau --threads 2 --o "$RECON_DIR/urls-gau.txt" 2>"$LOG_DIR/gau.log" || true
    fi

    if command -v waybackurls &>/dev/null; then
        echo "  [+] waybackurls..."
        echo "$DOMAIN" | timeout 30 waybackurls > "$RECON_DIR/urls-wayback.txt" 2>"$LOG_DIR/waybackurls.log" || true
    fi

    echo "  [Phase 1 Complete]"
    echo ""
fi

# ── Phase 2: Host & Service Discovery ──
if [[ "$SKIP_ACTIVE" == "false" ]]; then
    echo "[Phase 2] Active Discovery..."

    if [[ "$PORT_SCAN" == "true" ]]; then
        if command -v naabu &>/dev/null; then
            echo "  [+] naabu port scan..."
            if [[ -s "$RECON_DIR/subdomains.txt" ]]; then
                naabu -list "$RECON_DIR/subdomains.txt" -rate "$RATE_LIMIT" -silent -o "$RECON_DIR/ports-naabu.txt" 2>"$LOG_DIR/naabu.log" || true
            else
                echo "$DOMAIN" | naabu -rate "$RATE_LIMIT" -silent -o "$RECON_DIR/ports-naabu.txt" 2>"$LOG_DIR/naabu.log" || true
            fi
        fi
    fi

    # HTTP probing
    if command -v httpx &>/dev/null; then
        echo "  [+] httpx probing..."
        INPUT_FILE="$RECON_DIR/subdomains.txt"
        # Always probe the target host itself, regardless of subdomain enum.
        touch "$INPUT_FILE"
        grep -qxF "$DOMAIN" "$INPUT_FILE" 2>/dev/null || echo "$DOMAIN" >> "$INPUT_FILE"
        # httpx takes a single -o: a second -o silently discards the first format.
        # Emit JSON (the machine-readable artifact consumers parse), then derive the
        # text summary locally so no extra requests hit the target.
        httpx -l "$INPUT_FILE" -silent -status-code -title -tech-detect -follow-redirects \
            ${HTTPX_HDR[@]+"${HTTPX_HDR[@]}"} ${PROXY_ARGS[@]+"${PROXY_ARGS[@]}"} \
            -rate-limit "$RATE_LIMIT" \
            -json -o "$RECON_DIR/httpx-results.json" 2>"$LOG_DIR/httpx.log" || true
        if [[ -s "$RECON_DIR/httpx-results.json" ]] && command -v jq &>/dev/null; then
            jq -r 'select(.url) | "\(.url) [\(.status_code // "?")] [\((.tech // []) | join(","))]"' \
                "$RECON_DIR/httpx-results.json" > "$RECON_DIR/httpx-results.txt" 2>/dev/null || true
        fi
    fi

    echo "  [Phase 2 Complete]"
    echo ""
fi

# ── Phase 3: Technology Fingerprinting ──
echo "[Phase 3] Fingerprinting..."

if [[ -n "${GRIMNIR_PROXY:-}" ]]; then
    echo "  [-] whatweb skipped (cannot ride the program's egress proxy)"
elif command -v whatweb &>/dev/null; then
    echo "  [+] whatweb..."
    whatweb "$TARGET" --log-json="$RECON_DIR/whatweb.json" --color=never 2>"$LOG_DIR/whatweb.log" || true
fi

if command -v wafw00f &>/dev/null; then
    echo "  [+] wafw00f..."
    wafw00f "$TARGET" ${GRIMNIR_PROXY:+-p "$GRIMNIR_PROXY"} -o "$RECON_DIR/waf-detection.txt" 2>"$LOG_DIR/wafw00f.log" || true
fi

# Response headers
echo "  [+] Response headers..."
curl -sI -L ${CURL_HDR[@]+"${CURL_HDR[@]}"} "$TARGET" -o "$RECON_DIR/response-headers.txt" 2>"$LOG_DIR/curl-headers.log" || true

# TLS certificate
if [[ -n "${GRIMNIR_PROXY:-}" ]]; then
    echo "  [-] TLS certificate skipped (openssl s_client cannot ride the program's egress proxy)"
elif [[ "$TARGET" =~ ^https:// ]]; then
    echo "  [+] TLS certificate..."
    echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | \
        openssl x509 -noout -text > "$RECON_DIR/certificate.txt" 2>/dev/null || true
fi

echo "  [Phase 3 Complete]"
echo ""

# ── Phase 4: Endpoint & Content Discovery ──
if [[ "$SKIP_ACTIVE" == "false" ]]; then
    echo "[Phase 4] Endpoint Discovery..."

    if command -v katana &>/dev/null; then
        echo "  [+] katana crawl..."
        # -kf requires a value (all|robotstxt|sitemapxml); the bare "-kf -fs" form
        # consumed "-fs" as its value and aborted the whole crawl.
        timeout 60 katana -u "$TARGET" -d 3 -silent -jc -kf all -fs fqdn -aff \
            ${KATANA_HDR[@]+"${KATANA_HDR[@]}"} ${PROXY_ARGS[@]+"${PROXY_ARGS[@]}"} \
            -rate-limit "$RATE_LIMIT" -o "$RECON_DIR/crawl-katana.txt" 2>"$LOG_DIR/katana.log" || true
    fi

    # JS analysis (delegated to dedicated multi-phase pipeline)
    if [[ "$SKIP_JS" == "false" ]]; then
        echo "  [+] JS analysis pipeline (collect → download → beautify → extract)..."
        HEADER_ARG=()
        [[ -n "${HEADER:-}" ]] && HEADER_ARG=(--header "$HEADER")
        bash "$(dirname "$0")/js-pipeline.sh" --project-dir "$PROJECT_DIR" --target "$TARGET" \
            "${HEADER_ARG[@]}" 2>"$LOG_DIR/js-pipeline.log" || true
    fi

    echo "  [Phase 4 Complete]"
    echo ""
fi

# ── Phase 5: API Path Probe ──
if [[ "$API_PROBE" == "true" ]]; then
    echo "[Phase 5] API Path Probe..."
    APIOUT="$RECON_DIR/api-paths.txt"
    : > "$APIOUT"
    BASE="${TARGET%/}"
    DELAY=$(awk "BEGIN{r=$RATE_LIMIT; if(r<1)r=1; printf \"%.2f\", 1.0/r}" 2>/dev/null || echo 0.2)
    for p in / /v1 /v2 /api /api/v1 /graphql /openapi.json /swagger.json \
             /swagger/v1/swagger.json /api-docs /.well-known/openid-configuration \
             /health /status /robots.txt; do
        line=$(curl -s -o /dev/null -w '%{http_code} %{content_type}' --max-time 10 \
            ${CURL_HDR[@]+"${CURL_HDR[@]}"} "$BASE$p" 2>/dev/null || echo "000 -")
        echo "$line  $BASE$p" >> "$APIOUT"
        sleep "$DELAY" 2>/dev/null || true
    done
    LIVE=$(grep -cE '^(2|3|401|403)' "$APIOUT" 2>/dev/null || echo 0)
    echo "  [=] $LIVE responsive API path(s)"
    echo "  [Phase 5 Complete]"
    echo ""
fi

echo "=== Recon Pipeline Complete ==="
echo "Raw data saved to: $RECON_DIR/"
echo ""
echo "Next: Run huginn/scripts/asset-map.sh to build the asset map"
echo "  bash huginn/scripts/asset-map.sh --project-dir \"$PROJECT_DIR\" --target \"$TARGET\""
