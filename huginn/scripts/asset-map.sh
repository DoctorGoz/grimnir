#!/bin/bash
set -euo pipefail

# HUGINN Asset Map Builder
# Parses raw recon output and produces structured asset-map.json

usage() {
    cat <<'EOF'
Usage: huginn/scripts/asset-map.sh [OPTIONS]

Options:
  --project-dir DIR      Absolute path to project directory (required)
  --target TARGET        Primary target (required)
  -h, --help             Show this help

Reads:   $PROJECT_DIR/recon/*
Writes:  $PROJECT_DIR/asset-map.json
EOF
    exit 0
}

PROJECT_DIR=""
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir) PROJECT_DIR="$2"; shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$PROJECT_DIR" ]] && { echo "Error: --project-dir required" >&2; exit 1; }
[[ -z "$TARGET" ]] && { echo "Error: --target required" >&2; exit 1; }

RECON="$PROJECT_DIR/recon"
OUTPUT="$PROJECT_DIR/asset-map.json"

echo "Building asset map from $RECON..."

# Start with base structure
ASSET_MAP=$(jq -n \
    --arg target "$TARGET" \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        target: $target,
        generated_at: $ts,
        generated_by: "huginn",
        hosts: [],
        subdomains: [],
        technologies: [],
        endpoints: [],
        auth_mechanisms: [],
        ai_indicators: [],
        waf: { detected: false },
        certificates: [],
        js_analysis: { files_analyzed: 0, api_endpoints_found: [], secrets_found: [], interesting_strings: [] },
        attack_surface_summary: "",
        routing_recommendations: { specter: [], artemis: [], hunter: [] }
    }')

# ── Parse subdomains ──
# NOTE: large wildcard subdomain lists (thousands of entries, e.g. per-tenant
# storefront subdomains) can produce a JSON blob over the kernel's
# MAX_ARG_STRLEN (128KB single-argv limit, independent of ARG_MAX). Passing
# that via `jq --argjson subs "$SUBS"` fails with "Argument list too long"
# even though the total argv+envp is nowhere near ARG_MAX. Route the payload
# through a tmpfile + --slurpfile instead, which reads via fd, not argv.
if [[ -f "$RECON/subdomains.txt" && -s "$RECON/subdomains.txt" ]]; then
    SUBS_FILE=$(mktemp)
    trap 'rm -f "$SUBS_FILE"' RETURN
    while IFS= read -r sub; do
        jq -n --arg fqdn "$sub" '{ fqdn: $fqdn }'
    done < "$RECON/subdomains.txt" | jq -s '.' > "$SUBS_FILE"
    ASSET_MAP=$(echo "$ASSET_MAP" | jq --slurpfile subs "$SUBS_FILE" '.subdomains = $subs[0]')
    echo "  [+] $(jq length "$SUBS_FILE") subdomains"
    rm -f "$SUBS_FILE"
fi

# ── Parse httpx results ──
if [[ -f "$RECON/httpx-results.json" && -s "$RECON/httpx-results.json" ]]; then
    # Extract technologies from httpx JSON
    TECHS=$(jq -r '.tech // [] | .[]' "$RECON/httpx-results.json" 2>/dev/null | sort -u | while IFS= read -r tech; do
        [[ -z "$tech" ]] && continue
        jq -n --arg name "$tech" --arg cat "other" '{ name: $name, category: $cat, source: "httpx" }'
    done | jq -s '.' 2>/dev/null || echo '[]')
    [[ "$TECHS" != "[]" ]] && ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson techs "$TECHS" '.technologies += $techs')
    echo "  [+] Technologies from httpx"
fi

# ── Parse whatweb ──
if [[ -f "$RECON/whatweb.json" && -s "$RECON/whatweb.json" ]]; then
    echo "  [+] WhatWeb fingerprints"
fi

# ── Parse WAF detection ──
if [[ -f "$RECON/waf-detection.txt" && -s "$RECON/waf-detection.txt" ]]; then
    WAF_LINE=$(grep -i "is behind" "$RECON/waf-detection.txt" 2>/dev/null | head -1 || true)
    if [[ -n "$WAF_LINE" ]]; then
        WAF_NAME=$(echo "$WAF_LINE" | sed -E 's/.*is behind (.+)/\1/' | tr -d '\n')
        ASSET_MAP=$(echo "$ASSET_MAP" | jq --arg waf "$WAF_NAME" '.waf = { detected: true, product: $waf }')
        echo "  [+] WAF detected: $WAF_NAME"
    fi
fi

# ── Parse certificate ──
if [[ -f "$RECON/certificate.txt" && -s "$RECON/certificate.txt" ]]; then
    ISSUER=$(grep "Issuer:" "$RECON/certificate.txt" 2>/dev/null | head -1 | sed 's/.*Issuer: //' || true)
    SUBJECT=$(grep "Subject:" "$RECON/certificate.txt" 2>/dev/null | head -1 | sed 's/.*Subject: //' || true)
    SANS=$(grep -A1 "Subject Alternative Name" "$RECON/certificate.txt" 2>/dev/null | tail -1 | tr ',' '\n' | sed 's/.*DNS://' | tr -d ' ' || true)
    NOT_AFTER=$(grep "Not After" "$RECON/certificate.txt" 2>/dev/null | head -1 | sed 's/.*Not After : //' || true)

    CERT=$(jq -n \
        --arg host "$TARGET" \
        --arg issuer "$ISSUER" \
        --arg subject "$SUBJECT" \
        --arg not_after "$NOT_AFTER" \
        '{ host: $host, issuer: $issuer, subject: $subject, not_after: $not_after, san: [] }')

    if [[ -n "$SANS" ]]; then
        SAN_ARRAY=$(echo "$SANS" | jq -R . | jq -s '.')
        CERT=$(echo "$CERT" | jq --argjson sans "$SAN_ARRAY" '.san = $sans')
    fi

    ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson cert "[$CERT]" '.certificates = $cert')
    echo "  [+] Certificate parsed"
fi

# ── Parse crawl results (endpoints) ──
if [[ -f "$RECON/crawl-katana.txt" && -s "$RECON/crawl-katana.txt" ]]; then
    ENDPOINTS=$(head -200 "$RECON/crawl-katana.txt" | while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        jq -n --arg url "$url" '{ url: $url, source: "katana" }'
    done | jq -s '.' 2>/dev/null || echo '[]')
    ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson eps "$ENDPOINTS" '.endpoints += $eps')
    EP_COUNT=$(echo "$ENDPOINTS" | jq length)
    echo "  [+] $EP_COUNT endpoints from katana"
fi

# ── Parse JS analysis (full pipeline output) ──
if [[ -f "$RECON/js-urls-count.txt" && -s "$RECON/js-urls-count.txt" ]]; then
    JS_COUNT=$(cat "$RECON/js-urls-count.txt")
    ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson c "$JS_COUNT" '.js_analysis.files_analyzed = $c')
    echo "  [+] $JS_COUNT JS files analyzed"
fi

if [[ -f "$RECON/js-endpoints.txt" && -s "$RECON/js-endpoints.txt" ]]; then
    JS_EPS=$(head -200 "$RECON/js-endpoints.txt" | grep -v '^\[' | grep -v '^\s*$' | jq -R . | jq -s '.')
    ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson eps "$JS_EPS" '.js_analysis.api_endpoints_found = $eps')
    echo "  [+] $(echo "$JS_EPS" | jq length) JS endpoints"
fi

if [[ -f "$RECON/js-secrets.txt" && -s "$RECON/js-secrets.txt" ]]; then
    JS_SECRETS=$(head -50 "$RECON/js-secrets.txt" | grep -v '^\[' | grep -v '^\s*$' | jq -R . | jq -s '.')
    ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson s "$JS_SECRETS" '.js_analysis.secrets_found = $s')
    echo "  [+] $(echo "$JS_SECRETS" | jq length) potential secrets"
fi

if [[ -f "$RECON/js-interesting.txt" && -s "$RECON/js-interesting.txt" ]]; then
    JS_INTERESTING=$(head -100 "$RECON/js-interesting.txt" | jq -R . | jq -s '.')
    ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson s "$JS_INTERESTING" '.js_analysis.interesting_strings = $s')
    echo "  [+] $(echo "$JS_INTERESTING" | jq length) interesting strings"
fi

# ── Parse response headers for technologies ──
if [[ -f "$RECON/response-headers.txt" && -s "$RECON/response-headers.txt" ]]; then
    HEADER_TECHS='[]'

    # Server header
    SERVER=$(grep -i "^server:" "$RECON/response-headers.txt" 2>/dev/null | head -1 | sed 's/[Ss]erver: //' | tr -d '\r\n' || true)
    [[ -n "$SERVER" ]] && HEADER_TECHS=$(echo "$HEADER_TECHS" | jq --arg s "$SERVER" '. += [{ name: $s, category: "server", source: "headers" }]')

    # X-Powered-By
    POWERED=$(grep -i "^x-powered-by:" "$RECON/response-headers.txt" 2>/dev/null | head -1 | sed 's/[Xx]-[Pp]owered-[Bb]y: //' | tr -d '\r\n' || true)
    [[ -n "$POWERED" ]] && HEADER_TECHS=$(echo "$HEADER_TECHS" | jq --arg p "$POWERED" '. += [{ name: $p, category: "framework", source: "headers" }]')

    ASSET_MAP=$(echo "$ASSET_MAP" | jq --argjson ht "$HEADER_TECHS" '.technologies += $ht')
    echo "  [+] Header-based fingerprinting"
fi

# ── Write asset map ──
echo "$ASSET_MAP" | jq '.' > "$OUTPUT"

# ── Merge the full recon corpus into endpoints[] / hosts[] / auth_mechanisms[] ──
# The katana parse above is capped at 200 lines and ignores the JS crawl, archive URLs, OpenAPI
# specs and httpx hosts, which left most engagements with an empty endpoints[] (and so zero lanes
# downstream). corpus-build.py merges those on top, scope-gated, without touching what is above.
# It runs BEFORE the tagging passes below so they see the merged endpoints. Non-fatal.
if python3 "$(dirname "${BASH_SOURCE[0]}")/corpus-build.py" --project-dir "$PROJECT_DIR"; then
    ASSET_MAP=$(jq '.' "$OUTPUT")
else
    echo "  [!] corpus-build skipped (non-fatal)" >&2
fi

# ── Tag server-side-fetch surfaces ──
# The SSRF playbook family is split by WHERE the fetch lives, and playbook.py selects those
# lanes from signal tokens. Without this pass nothing emits them, so the surface-specific
# lanes could only match on the bare word "ssrf" appearing somewhere in the engagement text
# -- which fired all of them on every target at a critical ceiling. Runs on the written map
# so it is also re-runnable standalone over an existing engagement.
if python3 "$(dirname "${BASH_SOURCE[0]}")/fetch-surface.py" --asset-map "$OUTPUT" --write 2>/dev/null; then
    :
else
    echo "  [!] fetch-surface tagging skipped (non-fatal)"
fi

# ── Tag money / limit endpoints for the race-limit-overrun playbook ──
# playbook.py match selects the race lane from endpoints[].tags. Without this pass the race
# playbook could only match on a bare keyword happening to appear in the raw engagement text,
# which is fragile (plural/boundary misses). Substring-match each endpoint URL against the
# money/limit vocabulary and emit the CANONICAL signal token (a `/coupons/redeem` path -> tags
# coupon, redeem) so the match is deterministic and inspectable. Merges (never clobbers existing
# tags); idempotent + re-runnable over an existing map.
RACE_TAG_FILTER='
.endpoints = ((.endpoints // []) | map(
  if type == "object" then
    ((.url // .path // .endpoint // "") | ascii_downcase) as $l
    | ( [ ["coupon","coupon"],["promo","promo"],["voucher","voucher"],["gift","gift_card"],
          ["referr","referral"],["redeem","redeem"],["redemption","redeem"],["withdraw","withdraw"],
          ["payout","withdraw"],["transfer","transfer"],["balance","balance"],["wallet","wallet"],
          ["faucet","faucet"],["checkout","checkout"],["purchase","purchase"],["payment","payment"],
          ["credit","credit"],["topup","topup"],["top-up","topup"],["top_up","topup"],["quota","quota"] ]
        | map(. as $p | select($l | contains($p[0])) | $p[1]) | unique ) as $rt
    | if ($rt | length) > 0 then . + {tags: (((.tags // []) + $rt) | unique)} else . end
  else . end))'
if RACE_TAGGED=$(jq "$RACE_TAG_FILTER" "$OUTPUT" 2>/dev/null); then
    echo "$RACE_TAGGED" > "$OUTPUT"
    RACE_N=$(echo "$RACE_TAGGED" | jq '[.endpoints[]? | select((.tags // []) | any(. as $t | ["coupon","promo","voucher","gift_card","referral","redeem","withdraw","transfer","balance","wallet","faucet","checkout","purchase","payment","credit","topup","quota"] | index($t)))] | length')
    [[ "${RACE_N:-0}" -gt 0 ]] && echo "  [+] Tagged $RACE_N money/limit endpoint(s) for race-limit-overrun"
else
    echo "  [!] race-signal tagging skipped (non-fatal)"
fi

echo ""
echo "Asset map written to: $OUTPUT"
echo "Entries: $(echo "$ASSET_MAP" | jq '{
    subdomains: (.subdomains | length),
    technologies: (.technologies | length),
    endpoints: (.endpoints | length),
    certificates: (.certificates | length)
}')"
