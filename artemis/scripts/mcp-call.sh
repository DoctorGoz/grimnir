#!/usr/bin/env bash
# mcp-call.sh — invoke a single MCP tool (the active companion to mcp-enum.sh)
#
# Runs the streamable-HTTP MCP handshake and calls ONE tool with JSON arguments:
#   initialize -> notifications/initialized -> tools/call <tool> <args>
# curl-based, so traffic flows through your proxy (Caido) and stays visible for
# later analysis. SSE + JSON responses are both handled.
#
# This is the active-testing primitive: mcp-enum.sh reads the surface (read-only),
# mcp-call.sh exercises one tool. For systematic MCP05/MCP02 fuzzing use
# mcp-probe.sh (which drives this transport in a loop); to CONFIRM a finding for
# the evidence gate use scripts/confirm/mcp-confirm.py.
#
# Usage:
#   bash scripts/mcp-call.sh <MCP_ENDPOINT_URL> --tool <name> --args '<json>' [options]
#   bash scripts/mcp-call.sh <MCP_ENDPOINT_URL> --resource <uri> [options]
#   bash scripts/mcp-call.sh <MCP_ENDPOINT_URL> --prompt <name> --args '<json>' [options]
#
# Action (exactly ONE of):
#   --tool NAME              Call a tool      (tools/call)
#   --resource URI           Read a resource  (resources/read) — MCP01/MCP10 secret+scoping checks
#   --prompt NAME            Fetch a prompt   (prompts/get); --args carries the prompt arguments
#
# Options:
#   --args JSON              JSON object of arguments for --tool/--prompt (default: {})
#   --auth "<Header: value>" Auth header (repeatable). e.g. "Authorization: Bearer X"
#   -H "<Header: value>"     Extra header (repeatable)
#   --proxy URL              Route curl through a proxy (e.g. http://127.0.0.1:8080)
#   --protocol-version VER   MCP protocol version (default: 2025-06-18)
#   --timeout SECONDS        Per-request timeout (default: 30)
#   --insecure               curl -k (self-signed TLS)
#   --raw                    Print the raw JSON-RPC response, not just the text content
#
# Exit: 0 if the tool returned a result; 1 if it returned a JSON-RPC error or
#       isError; 3 if initialize failed (not MCP / auth-gated); 2 on usage.

set -uo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
    sed -n '2,35p' "$0"; exit 2
fi
shift

TOOL=""
RESOURCE_URI=""
PROMPT_NAME=""
ARGS_JSON="{}"
HEADER_ARGS=()
PROXY=""
PROTOCOL_VERSION="2025-06-18"
TIMEOUT=30
INSECURE=()
RAW=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool)             TOOL="$2"; shift 2 ;;
        --resource)         RESOURCE_URI="$2"; shift 2 ;;
        --prompt)           PROMPT_NAME="$2"; shift 2 ;;
        --args)             ARGS_JSON="$2"; shift 2 ;;
        --auth|-H)          HEADER_ARGS+=(-H "$2"); shift 2 ;;
        --proxy)            PROXY="$2"; shift 2 ;;
        --protocol-version) PROTOCOL_VERSION="$2"; shift 2 ;;
        --timeout)          TIMEOUT="$2"; shift 2 ;;
        --insecure)         INSECURE=(-k); shift ;;
        --raw)              RAW=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# Exactly one action selector.
MODE=""; SEL=0
[[ -n "$TOOL" ]]         && { MODE="tool";     SEL=$((SEL+1)); }
[[ -n "$RESOURCE_URI" ]] && { MODE="resource"; SEL=$((SEL+1)); }
[[ -n "$PROMPT_NAME" ]]  && { MODE="prompt";   SEL=$((SEL+1)); }
[[ "$SEL" -ne 1 ]] && { echo "error: provide exactly ONE of --tool NAME | --resource URI | --prompt NAME" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 2; }

# egress-layer:begin
# The program's egress proxy (roe.json / GRIMNIR_PROXY) is the only way out: it replaces any
# --proxy, and an unusable one refuses rather than connecting directly. Optional: a tree without
# scripts/egress-env.sh falls back to --proxy, else $GRIMNIR_PROXY.
EGRESS_SH="$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
if [[ -f "$EGRESS_SH" ]]; then
    source "$EGRESS_SH"
    egress_init "" || exit 4
    PROXY="$(egress_effective_proxy "$PROXY")"
fi
PROXY="${PROXY:-${GRIMNIR_PROXY:-}}"
# egress-layer:end

# Validate the args JSON early so a typo doesn't masquerade as a server error.
if ! printf '%s' "$ARGS_JSON" | python3 -c 'import sys,json;json.loads(sys.stdin.read())' 2>/dev/null; then
    echo "error: --args is not valid JSON: $ARGS_JSON" >&2; exit 2
fi

TMPDIR_CALL="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_CALL"' EXIT
HDR_TMP="$TMPDIR_CALL/headers"
NORMALIZER="$TMPDIR_CALL/normalize.py"
cat > "$NORMALIZER" <<'PY'
import sys, json, re
raw = sys.stdin.read()
# curl -w appends a trailer we use to recover the HTTP status even when the
# body is empty/non-JSON (e.g. a transport-layer 403 with Content-Length:0) --
# otherwise an out-of-scope call silently normalizes to "{}" and looks like an
# empty-but-successful result instead of a denial (MCP07 false-negative risk).
http_status = None
m = re.search(r'___HTTP_STATUS:(\d+)___\s*$', raw)
if m:
    http_status = int(m.group(1))
    raw = raw[:m.start()]
msg = None
if 'data:' in raw and ('event:' in raw or raw.lstrip().startswith('data:')):
    datas = [ln[5:].lstrip() for ln in raw.splitlines() if ln.rstrip('\r').startswith('data:')]
    payload = '\n'.join(datas).strip()
    try:
        msg = json.loads(payload)
    except Exception:
        msg = None
if msg is None:
    try:
        msg = json.loads(raw)
    except Exception:
        if http_status and http_status >= 400:
            print(json.dumps({"error": {"code": -1, "message": f"HTTP {http_status} at MCP transport layer (non-JSON/empty body)", "http_status": http_status, "body_snippet": raw[:300]}}))
        else:
            print(json.dumps({"__error__": "unparseable", "http_status": http_status, "raw": raw[:800]}))
        sys.exit(0)
if http_status is not None and isinstance(msg, dict):
    msg.setdefault("__http_status__", http_status)
print(json.dumps(msg))
PY

PROXY_ARGS=(); [[ -n "$PROXY" ]] && PROXY_ARGS=(--proxy "$PROXY")
SESSION_ID=""
SEND_PROTO_HDR=0

rpc() {  # rpc <method> <params-json> [id]   (omit id for a notification)
    local method="$1" params="${2:-{\}}" id="${3:-}"
    local body extra=()
    if [[ -n "$id" ]]; then
        body=$(printf '{"jsonrpc":"2.0","id":%s,"method":"%s","params":%s}' "$id" "$method" "$params")
    else
        body=$(printf '{"jsonrpc":"2.0","method":"%s","params":%s}' "$method" "$params")
    fi
    [[ -n "$SESSION_ID" ]] && extra+=(-H "Mcp-Session-Id: $SESSION_ID")
    [[ "$SEND_PROTO_HDR" == "1" ]] && extra+=(-H "MCP-Protocol-Version: $PROTOCOL_VERSION")
    curl -sS -m "$TIMEOUT" "${INSECURE[@]}" "${PROXY_ARGS[@]}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        "${HEADER_ARGS[@]}" "${extra[@]}" \
        -D "$HDR_TMP" -d "$body" -w '\n___HTTP_STATUS:%{http_code}___' "$TARGET" 2>/dev/null | python3 "$NORMALIZER"
}

# ── Handshake ──
INIT_PARAMS=$(printf '{"protocolVersion":"%s","capabilities":{},"clientInfo":{"name":"grimnir-artemis-mcp-call","version":"0.1"}}' "$PROTOCOL_VERSION")
INIT_RESP=$(rpc "initialize" "$INIT_PARAMS" 1)
if [[ -f "$HDR_TMP" ]]; then
    SESSION_ID=$(grep -i '^mcp-session-id:' "$HDR_TMP" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' || true)
fi
SEND_PROTO_HDR=1
IS_MCP=$(printf '%s' "$INIT_RESP" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print("yes" if isinstance(d,dict) and isinstance(d.get("result"),dict) and any(k in d["result"] for k in ("serverInfo","capabilities","protocolVersion")) else "no")
except Exception: print("no")' 2>/dev/null || echo "no")
if [[ "$IS_MCP" != "yes" ]]; then
    echo "[!] initialize did not return an MCP result (not MCP / wrong path / auth-gated):" >&2
    printf '%s\n' "$INIT_RESP" | head -c 600 >&2; echo >&2
    exit 3
fi
rpc "notifications/initialized" "{}" >/dev/null 2>&1 || true

# ── Call (tools/call | resources/read | prompts/get) ──
case "$MODE" in
    tool)     CALL_METHOD="tools/call"
              CALL_PARAMS=$(NAME="$TOOL" A="$ARGS_JSON" python3 -c 'import os,json;print(json.dumps({"name":os.environ["NAME"],"arguments":json.loads(os.environ["A"])}))') ;;
    resource) CALL_METHOD="resources/read"
              CALL_PARAMS=$(URI="$RESOURCE_URI" python3 -c 'import os,json;print(json.dumps({"uri":os.environ["URI"]}))') ;;
    prompt)   CALL_METHOD="prompts/get"
              CALL_PARAMS=$(NAME="$PROMPT_NAME" A="$ARGS_JSON" python3 -c 'import os,json;print(json.dumps({"name":os.environ["NAME"],"arguments":json.loads(os.environ["A"])}))') ;;
esac
RESP=$(rpc "$CALL_METHOD" "$CALL_PARAMS" 2)

RAW="$RAW" printf '%s' "$RESP" | RAW="$RAW" python3 -c '
import sys, os, json
raw = sys.stdin.read()
try:
    m = json.loads(raw)
except Exception:
    print(raw[:4000]); sys.exit(1)
if os.environ.get("RAW") == "1":
    print(json.dumps(m, indent=2)); sys.exit(0 if "result" in m else 1)
if "error" in m:
    print("ERROR:", json.dumps(m["error"])[:1500]); sys.exit(1)
res = m.get("result", {})
rc = 0
if isinstance(res, dict) and "content" in res:            # tools/call
    for c in res.get("content", []):
        if c.get("type") == "text":
            print(c.get("text", "")[:4000])
        else:
            print(json.dumps(c)[:1500])
    if res.get("isError"):
        print("  [isError=true]"); rc = 1
elif isinstance(res, dict) and "contents" in res:         # resources/read
    for c in res.get("contents", []):
        label, mime = c.get("uri", ""), c.get("mimeType", "")
        if c.get("text") is not None:
            print(f"# {label} ({mime})")
            print(str(c["text"])[:4000])
        elif c.get("blob") is not None:
            blob = c.get("blob") or ""
            print(f"# {label} ({mime}) [blob: {len(blob)} base64 chars]")
        else:
            print(json.dumps(c)[:1500])
elif isinstance(res, dict) and "messages" in res:         # prompts/get
    desc = res.get("description")
    if desc:
        print("# " + str(desc))
    for msg in res.get("messages", []):
        role, cont = msg.get("role", "?"), msg.get("content", {})
        if isinstance(cont, dict):
            txt = cont.get("text", json.dumps(cont)[:1500])
        elif isinstance(cont, list):
            txt = " ".join(x.get("text", json.dumps(x)) if isinstance(x, dict) else str(x) for x in cont)[:4000]
        else:
            txt = str(cont)[:4000]
        print(f"[{role}] {txt}")
else:
    print(json.dumps(res)[:4000])
sys.exit(rc)
'
exit $?
