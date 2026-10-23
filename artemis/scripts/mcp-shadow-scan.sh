#!/usr/bin/env bash
# mcp-shadow-scan.sh — MCP09 shadow-server discovery (path fuzz + JS-bundle grep).
#
# Finds undeclared / forgotten MCP endpoints: probes a host for common MCP paths
# with a real `initialize`, and greps HUGINN's collected JS bundles for MCP client
# URLs. Any path that answers `initialize` like MCP is a candidate — feed it to
# mcp-enum.sh. Designed to slot into HUGINN recon (MCP09 is HUGINN-led).
#
# Usage:
#   bash scripts/mcp-shadow-scan.sh <host-or-origin> [options]
#     e.g.  mcp-shadow-scan.sh https://target.example
#           mcp-shadow-scan.sh target.example --js-dir "$PROJECT_DIR/recon/js"
#
# Options:
#   --paths FILE       Path list (default: wordlists/mcp-shadow-paths.txt)
#   --js-dir DIR       Grep these JS bundles for MCP client URLs (HUGINN output)
#   --auth "<H: v>"    Auth header (repeatable)
#   --proxy URL        curl proxy
#   --project-dir DIR  Write under $DIR/artemis/recon/
#   --out DIR          Explicit output dir
#   --timeout SECONDS  Per-request timeout (default: 12)
#   --insecure         curl -k
#
# Exit: 0 always (see report); 2 usage.

set -uo pipefail

BASE="${1:-}"
if [[ -z "$BASE" || "$BASE" == "-h" || "$BASE" == "--help" ]]; then
    sed -n '2,24p' "$0"; exit 2
fi
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATHS_FILE="$SCRIPT_DIR/../wordlists/mcp-shadow-paths.txt"
JS_DIR=""; HEADER_ARGS=(); PROXY=""; PROJECT_DIR=""; OUT=""; TIMEOUT=12; INSECURE=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --paths)       PATHS_FILE="$2"; shift 2 ;;
        --js-dir)      JS_DIR="$2"; shift 2 ;;
        --auth|-H)     HEADER_ARGS+=(-H "$2"); shift 2 ;;
        --proxy)       PROXY="$2"; shift 2 ;;
        --project-dir) PROJECT_DIR="$2"; shift 2 ;;
        --out)         OUT="$2"; shift 2 ;;
        --timeout)     TIMEOUT="$2"; shift 2 ;;
        --insecure)    INSECURE=(-k); shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 2; }

# egress-layer:begin
# The program's egress proxy (roe.json / GRIMNIR_PROXY) is the only way out: it replaces any
# --proxy, and an unusable one refuses rather than connecting directly. Optional: a tree without
# scripts/egress-env.sh falls back to --proxy, else $GRIMNIR_PROXY.
EGRESS_SH="$SCRIPT_DIR/../../scripts/egress-env.sh"
if [[ -f "$EGRESS_SH" ]]; then
    source "$EGRESS_SH"
    egress_init "${PROJECT_DIR:-}" || exit 4
    PROXY="$(egress_effective_proxy "$PROXY")"
fi
PROXY="${PROXY:-${GRIMNIR_PROXY:-}}"
# egress-layer:end
[[ -f "$PATHS_FILE" ]] || { echo "paths file not found: $PATHS_FILE" >&2; exit 2; }

# Normalize BASE to an origin (scheme://host[:port]).
[[ "$BASE" =~ ^https?:// ]] || BASE="https://$BASE"
ORIGIN="$(python3 -c 'import sys
from urllib.parse import urlparse, urlunparse
u = urlparse(sys.argv[1]); print(urlunparse((u.scheme, u.netloc, "", "", "", "")))' "$BASE")"

TS="$(date +%Y%m%d-%H%M%S)"
if [[ -z "$OUT" ]]; then
    if [[ -n "$PROJECT_DIR" ]]; then OUT="$PROJECT_DIR/artemis/recon/mcp-shadow-$TS"; else OUT="reports/mcp-shadow-$TS"; fi
fi
mkdir -p "$OUT"
REPORT="$OUT/shadow-report.md"
HITS="$OUT/shadow-hits.jsonl"
: > "$HITS"

PROXY_ARGS=(); [[ -n "$PROXY" ]] && PROXY_ARGS=(--proxy "$PROXY")
INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"grimnir-shadow","version":"0.1"}}}'

echo "=== MCP09 Shadow-Server Scan ==="
echo "Origin: $ORIGIN"
echo ""

CANDIDATES=0
while IFS= read -r path; do
    p="$(printf '%s' "$path" | sed 's/#.*//' | xargs || true)"
    [[ -z "$p" ]] && continue
    url="$ORIGIN$p"
    resp="$(curl -sS -m "$TIMEOUT" "${INSECURE[@]}" "${PROXY_ARGS[@]}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        "${HEADER_ARGS[@]}" -w '\n__HTTP_%{http_code}__' -d "$INIT_BODY" "$url" 2>/dev/null || true)"
    code="$(printf '%s' "$resp" | grep -o '__HTTP_[0-9]*__' | tr -dc '0-9' || echo 0)"
    body="$(printf '%s' "$resp" | sed 's/__HTTP_[0-9]*__$//')"
    verdict=""
    if printf '%s' "$body" | grep -qiE '"serverInfo"|"protocolVersion"|"capabilities"'; then
        verdict="mcp-open"
    elif printf '%s' "$body" | grep -qiE 'jsonrpc|mcp-session|"method"|modelcontext'; then
        verdict="mcp-like"
    elif [[ "$code" == "401" || "$code" == "403" ]] && printf '%s' "$body" | grep -qiE 'auth|token|unauthor'; then
        verdict="auth-gated?"
    fi
    if [[ -n "$verdict" ]]; then
        CANDIDATES=$((CANDIDATES+1))
        echo "  [$verdict] $url (HTTP $code)"
        printf '{"url":"%s","http":%s,"verdict":"%s"}\n' "$url" "${code:-0}" "$verdict" >> "$HITS"
    fi
done < "$PATHS_FILE"

# ── JS-bundle grep for MCP client URLs ──
JS_HITS="$OUT/js-mcp-refs.txt"
: > "$JS_HITS"
if [[ -n "$JS_DIR" && -d "$JS_DIR" ]]; then
    echo ""
    echo "[js] grepping $JS_DIR for MCP client URLs..."
    grep -rEoi \
        'https?://[a-z0-9._-]+(/[a-z0-9._/-]*)?(mcp|/sse|modelcontextprotocol)[a-z0-9._/-]*|["'"'"'`]/(mcp|sse|message)s?["'"'"'`]|modelcontextprotocol|McpClient|new Client\(' \
        "$JS_DIR" 2>/dev/null | sort -u | tee "$JS_HITS" | sed 's/^/  /' | head -40 || true
fi

# ── Report ──
{
    echo "# MCP09 Shadow-Server Scan"
    echo ""
    echo "**Origin:** $ORIGIN  "
    echo "**Date:** $(date -u +%Y-%m-%dT%H:%M:%SZ)  "
    echo "**Candidate endpoints:** $CANDIDATES"
    echo ""
    if [[ "$CANDIDATES" -gt 0 ]]; then
        echo "## Candidate MCP endpoints"
        echo ""
        echo "| URL | HTTP | Verdict |"
        echo "|-----|------|---------|"
        python3 -c 'import json,sys
for ln in open(sys.argv[1]):
    ln=ln.strip()
    if not ln: continue
    r=json.loads(ln); print(f"| {r[\"url\"]} | {r[\"http\"]} | {r[\"verdict\"]} |")' "$HITS" 2>/dev/null || true
        echo ""
        echo "_Enumerate each: \`bash scripts/mcp-enum.sh <url> --auth \"Authorization: Bearer <t>\" --project-dir \"\$PROJECT_DIR\"\`_"
        echo "_An unauth/default-cred reachable server with usable tools is MCP09 High/Critical._"
    else
        echo "_No candidate MCP endpoints on the probed paths._"
    fi
    if [[ -s "$JS_HITS" ]]; then
        echo ""
        echo "## MCP client URLs referenced in JS bundles"
        echo ""
        sed 's/^/- /' "$JS_HITS" | head -60
    fi
} > "$REPORT"

echo ""
echo "=== Shadow Scan Complete ==="
echo "Candidates: $CANDIDATES"
echo "Report:     $REPORT"
