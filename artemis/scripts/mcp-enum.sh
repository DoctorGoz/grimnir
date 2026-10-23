#!/usr/bin/env bash
# mcp-enum.sh — Remote MCP (Model Context Protocol) server enumerator
#
# Speaks the streamable-HTTP MCP transport directly over curl (so traffic flows
# through your proxy) and runs the read-only handshake:
#   initialize -> notifications/initialized -> tools/list -> resources/list -> prompts/list
# Dumps every tool description + input schema, flags tool-description poisoning
# heuristically (borrowing mcp-scan's static-analysis idea), and writes an
# asset-map fragment plus per-item OWASP MCP Top-10 hints.
#
# Dependency-light: curl + python3 stdlib + jq. No MCP SDK required.
#
# Usage:
#   bash scripts/mcp-enum.sh <MCP_ENDPOINT_URL> [options]
#
# Options:
#   --auth "<Header: value>"   Auth header (repeatable). e.g. "Authorization: Bearer X"
#   -H "<Header: value>"       Extra header (repeatable)
#   --project-dir DIR          Write under $DIR/artemis/recon/ (GRIMNIR engagement dir)
#   --out DIR                  Explicit output dir (default: reports/mcp-enum-<ts>)
#   --proxy URL               Route curl through a proxy (e.g. http://127.0.0.1:8080)
#   --protocol-version VER    MCP protocol version (default: 2025-06-18)
#   --timeout SECONDS         Per-request timeout (default: 30)
#   --insecure                curl -k (self-signed TLS)
#   --fallback-host HOST      Retry the same path on this host if the primary is not
#                             MCP (repeatable). A valid-token 403 on one host while a
#                             sibling serves 200 is an edge-misroute, not a dead end.
#   --transport MODE          auto | streamable | sse  (default: auto — try streamable
#                             HTTP, then fall back to the legacy HTTP+SSE transport)
#
# Exit: 0 if the server responded to initialize; 2 on usage; 3 if not an MCP server.

set -uo pipefail

# ── Args ─────────────────────────────────────────────────────────────────────
TARGET="${1:-}"
if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
    sed -n '2,29p' "$0"; exit 2
fi
shift

HEADER_ARGS=()
PROJECT_DIR=""
OUT=""
PROXY=""
PROTOCOL_VERSION="2025-06-18"
TIMEOUT=30
INSECURE=()
FALLBACK_HOSTS=()
TRANSPORT="auto"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auth|-H)          HEADER_ARGS+=(-H "$2"); shift 2 ;;
        --project-dir)      PROJECT_DIR="$2"; shift 2 ;;
        --out)              OUT="$2"; shift 2 ;;
        --proxy)            PROXY="$2"; shift 2 ;;
        --protocol-version) PROTOCOL_VERSION="$2"; shift 2 ;;
        --timeout)          TIMEOUT="$2"; shift 2 ;;
        --insecure)         INSECURE=(-k); shift ;;
        --fallback-host)    FALLBACK_HOSTS+=("$2"); shift 2 ;;
        --transport)        TRANSPORT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

case "$TRANSPORT" in auto|streamable|sse) ;; *) echo "error: --transport must be auto|streamable|sse" >&2; exit 2 ;; esac

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 2; }

# egress-layer:begin
# The program's egress proxy (roe.json / GRIMNIR_PROXY) is the only way out: it replaces any
# --proxy, and an unusable one refuses rather than connecting directly. Optional: a tree without
# scripts/egress-env.sh falls back to --proxy, else $GRIMNIR_PROXY.
EGRESS_SH="$(dirname "${BASH_SOURCE[0]}")/../../scripts/egress-env.sh"
if [[ -f "$EGRESS_SH" ]]; then
    source "$EGRESS_SH"
    egress_init "${PROJECT_DIR:-}" || exit 4
    PROXY="$(egress_effective_proxy "$PROXY")"
fi
PROXY="${PROXY:-${GRIMNIR_PROXY:-}}"
# egress-layer:end

# ── Output layout ────────────────────────────────────────────────────────────
TS="$(date +%Y%m%d-%H%M%S)"
if [[ -z "$OUT" ]]; then
    if [[ -n "$PROJECT_DIR" ]]; then
        OUT="$PROJECT_DIR/artemis/recon/mcp-enum-$TS"
    else
        OUT="reports/mcp-enum-$TS"
    fi
fi
mkdir -p "$OUT"

RAW="$OUT/mcp-raw.jsonl"
HDR_TMP="$OUT/.headers.tmp"
LOG="$OUT/curl.log"
REPORT="$OUT/mcp-inventory.md"
ASSETS="$OUT/mcp-assets.json"
: > "$RAW"; : > "$LOG"

# Normalizer + recorder live in files so a piped curl body reaches their stdin
# (a heredoc on `python3 -` would consume stdin for the script itself).
NORMALIZER="$OUT/.normalize.py"
cat > "$NORMALIZER" <<'PY'
import sys, json
raw = sys.stdin.read()
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
        print(json.dumps({"__error__": "unparseable", "raw": raw[:800]}))
        sys.exit(0)
print(json.dumps(msg))
PY

RECORDER="$OUT/.record-raw.py"
cat > "$RECORDER" <<'PY'
import sys, json
method = sys.argv[1]
resp = sys.stdin.read().strip()
try:
    parsed = json.loads(resp) if resp else None
except Exception:
    parsed = {"__error__": "record_parse_failed", "raw": resp[:400]}
print(json.dumps({"method": method, "response": parsed}))
PY

# Legacy HTTP+SSE client (used only as a fallback). Opens the GET event stream,
# reads the announced POST endpoint, then drives initialize/tools/resources/prompts,
# collecting JSON-RPC replies off the stream. Writes $RAW in the same shape as
# record_raw so the analysis block below is transport-agnostic. Prints yes|no.
SSE_CLIENT="$OUT/.sse-client.py"
cat > "$SSE_CLIENT" <<'PY'
import os, sys, json, ssl, time, threading, queue, urllib.request
from urllib.parse import urljoin

SSE_URL = os.environ["SSE_URL"]; RAW = os.environ["RAW"]
HEADERS = [h for h in os.environ.get("HEADERS", "").splitlines() if h.strip()]
PROXY = os.environ.get("PROXY", ""); INSECURE = os.environ.get("INSECURE", "") == "1"
TIMEOUT = int(os.environ.get("TIMEOUT", "30")); PROTO = os.environ.get("PROTOCOL", "2025-06-18")

ctx = ssl.create_default_context()
if INSECURE:
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
handlers = [urllib.request.HTTPSHandler(context=ctx)]
# egress-layer-py:begin
# egress.opener speaks socks5/socks5h as well as http(s), and raises (never goes direct) when the
# proxy cannot be used. Optional: without it, a plain http(s) proxy handler.
try:
    sys.path.insert(0, os.environ.get("EGRESS_DIR", ""))
    import egress
    opener = egress.opener(*handlers, proxy=PROXY)
except ImportError:
    if PROXY:
        handlers.append(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    opener = urllib.request.build_opener(*handlers)
# egress-layer-py:end

def hdr_dict():
    d = {}
    for h in HEADERS:
        if ":" in h:
            k, v = h.split(":", 1); d[k.strip()] = v.strip()
    return d

msgs = queue.Queue(); endpoint_q = queue.Queue()

def reader():
    try:
        req = urllib.request.Request(SSE_URL, headers={**hdr_dict(), "Accept": "text/event-stream"})
        resp = opener.open(req, timeout=TIMEOUT)
    except Exception as e:
        endpoint_q.put(("__err__", str(e))); return
    event = None; data = []
    for raw in resp:
        line = raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
        if line == "":
            if data:
                payload = "\n".join(data)
                if event == "endpoint":
                    endpoint_q.put(("endpoint", payload))
                else:
                    try: msgs.put(json.loads(payload))
                    except Exception: pass
            event = None; data = []
            continue
        if line.startswith(":"): continue
        if line.startswith("event:"): event = line[6:].strip()
        elif line.startswith("data:"): data.append(line[5:].lstrip())

threading.Thread(target=reader, daemon=True).start()
try:
    kind, val = endpoint_q.get(timeout=TIMEOUT)
except queue.Empty:
    print("no"); sys.exit(0)
if kind == "__err__":
    print("no"); sys.exit(0)
post_url = urljoin(SSE_URL, val)

def post(method, params, mid=None):
    body = {"jsonrpc": "2.0", "method": method, "params": params}
    if mid is not None: body["id"] = mid
    try:
        req = urllib.request.Request(post_url, data=json.dumps(body).encode(),
              headers={**hdr_dict(), "Content-Type": "application/json"}, method="POST")
        opener.open(req, timeout=TIMEOUT).read()
    except Exception:
        pass

def wait_for(mid, t=None):
    end = time.time() + (t or TIMEOUT)
    while time.time() < end:
        try: m = msgs.get(timeout=max(0.1, end - time.time()))
        except Exception: break
        if isinstance(m, dict) and m.get("id") == mid: return m
    return None

records = []
post("initialize", {"protocolVersion": PROTO, "capabilities": {},
     "clientInfo": {"name": "grimnir-artemis-mcp-enum", "version": "0.1"}}, 1)
init = wait_for(1)
records.append({"method": "initialize", "response": init})
ok = isinstance(init, dict) and isinstance(init.get("result"), dict) and \
     any(k in init["result"] for k in ("serverInfo", "capabilities", "protocolVersion"))
if ok:
    post("notifications/initialized", {})
    post("tools/list", {}, 2);     records.append({"method": "tools/list",     "response": wait_for(2)})
    post("resources/list", {}, 3); records.append({"method": "resources/list", "response": wait_for(3)})
    post("prompts/list", {}, 4);   records.append({"method": "prompts/list",   "response": wait_for(4)})
with open(RAW, "w") as f:
    for r in records:
        f.write(json.dumps(r) + "\n")
print("yes" if ok else "no")
PY

PROXY_ARGS=(); [[ -n "$PROXY" ]] && PROXY_ARGS=(--proxy "$PROXY")

SESSION_ID=""
SEND_PROTO_HDR=0   # only send MCP-Protocol-Version after initialize

# ── Transport helpers ────────────────────────────────────────────────────────

# Normalize an HTTP body (JSON or SSE `data:` framing) to one compact JSON line.
normalize_json() {
    python3 "$NORMALIZER"
}

# rpc <method> <params-json> [id]   (omit id for a notification)
rpc() {
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
        -D "$HDR_TMP" \
        -d "$body" \
        "${URL:-$TARGET}" 2>>"$LOG" | normalize_json
}

# HTTP status of the most recent rpc() call (from the dumped response headers).
last_http_status() {
    [[ -f "$HDR_TMP" ]] || { echo 0; return; }
    grep -m1 -iE '^HTTP/' "$HDR_TMP" 2>/dev/null | awk '{print $2}' | tr -d '\r' || echo 0
}

# Swap the host[:port] of a URL, preserving scheme/path/query (for --fallback-host).
swap_host() {
    python3 -c 'import sys
from urllib.parse import urlparse, urlunparse
u = urlparse(sys.argv[1]); print(urlunparse(u._replace(netloc=sys.argv[2])))' "$1" "$2"
}

record_raw() {  # record_raw <method>  (reads compact JSON response from stdin — pipe-safe)
    python3 "$RECORDER" "$1" >> "$RAW" 2>/dev/null || true
}

# ── Handshake ────────────────────────────────────────────────────────────────
echo "=== ARTEMIS MCP Enumeration ==="
echo "Target: $TARGET"
[[ ${#HEADER_ARGS[@]} -gt 0 ]] && echo "Auth:   (provided)" || echo "Auth:   (none — testing unauthenticated)"
[[ ${#FALLBACK_HOSTS[@]} -gt 0 ]] && echo "Fallback hosts: ${FALLBACK_HOSTS[*]}"
echo "Transport: $TRANSPORT"
echo ""

INIT_PARAMS=$(printf '{"protocolVersion":"%s","capabilities":{},"clientInfo":{"name":"grimnir-artemis-mcp-enum","version":"0.1"}}' "$PROTOCOL_VERSION")
IS_MCP="no"
WON_URL="$TARGET"
INIT_STATUS=0
TRANSPORT_USED="streamable-http"
EXTRA_HINTS=""

# Run the streamable-HTTP handshake against one URL. Resets $RAW, populates
# records, and sets IS_MCP/SESSION_ID/INIT_STATUS/WON_URL. Returns 0 on success.
try_streamable() {
    URL="$1"; SESSION_ID=""; SEND_PROTO_HDR=0
    : > "$RAW"
    echo "[streamable] initialize -> $URL"
    local resp ismcp
    resp=$(rpc "initialize" "$INIT_PARAMS" 1)
    INIT_STATUS="$(last_http_status)"
    printf '%s\n' "$resp" | record_raw "initialize"
    if [[ -f "$HDR_TMP" ]]; then
        SESSION_ID=$(grep -i '^mcp-session-id:' "$HDR_TMP" 2>/dev/null | head -1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r' || true)
    fi
    SEND_PROTO_HDR=1
    ismcp=$(printf '%s' "$resp" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print("yes" if isinstance(d,dict) and isinstance(d.get("result"),dict) and any(k in d["result"] for k in ("serverInfo","capabilities","protocolVersion")) else "no")
except Exception: print("no")' 2>/dev/null || echo "no")
    if [[ "$ismcp" != "yes" ]]; then
        echo "  [!] not an MCP result on $URL (HTTP ${INIT_STATUS:-?})"
        return 1
    fi
    echo "  [+] MCP server responded${SESSION_ID:+ (session $SESSION_ID)}"
    rpc "notifications/initialized" "{}" >/dev/null 2>&1 || true
    echo "  tools/list..."     ; rpc "tools/list" "{}" 2     | record_raw "tools/list"
    echo "  resources/list..." ; rpc "resources/list" "{}" 3 | record_raw "resources/list"
    echo "  prompts/list..."   ; rpc "prompts/list" "{}" 4   | record_raw "prompts/list"
    IS_MCP="yes"; WON_URL="$URL"
    return 0
}

if [[ "$TRANSPORT" != "sse" ]]; then
    CANDIDATES=("$TARGET")
    for h in "${FALLBACK_HOSTS[@]:-}"; do
        [[ -n "$h" ]] && CANDIDATES+=("$(swap_host "$TARGET" "$h")")
    done
    for u in "${CANDIDATES[@]}"; do
        try_streamable "$u" && break
        # Edge-misroute signal: a valid-token 403 on one host while a sibling may
        # serve 200 is a routing quirk, not a dead end (the mercadopago S3 case).
        if [[ ${#HEADER_ARGS[@]} -gt 0 && "${INIT_STATUS:-0}" == "403" ]]; then
            EXTRA_HINTS+="MCP07/edge: authed 403 on $u (possible valid-token edge misroute). Try a sibling host with --fallback-host."$'\n'
        fi
    done
fi

# Legacy HTTP+SSE transport fallback (older servers: GET stream announces a POST
# endpoint; JSON-RPC replies arrive as `event: message` on the stream).
if [[ "$IS_MCP" != "yes" && "$TRANSPORT" != "streamable" ]]; then
    echo "[sse] streamable did not yield MCP — trying legacy HTTP+SSE transport on $TARGET"
    : > "$RAW"
    SSE_OK=$(EGRESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../scripts" && pwd)" \
        SSE_URL="$TARGET" RAW="$RAW" PROTOCOL="$PROTOCOL_VERSION" TIMEOUT="$TIMEOUT" \
        PROXY="$PROXY" INSECURE="$([[ ${#INSECURE[@]} -gt 0 ]] && echo 1 || echo 0)" \
        HEADERS="$(printf '%s\n' "${HEADER_ARGS[@]:-}" | grep -v '^-H$' || true)" \
        python3 "$OUT/.sse-client.py" 2>>"$LOG" || echo "no")
    if [[ "$SSE_OK" == "yes" ]]; then
        echo "  [+] MCP server responded over HTTP+SSE"
        IS_MCP="yes"; TRANSPORT_USED="http-sse"; WON_URL="$TARGET"
        EXTRA_HINTS+="MCP: server uses the legacy HTTP+SSE transport (GET stream + POST endpoint)."$'\n'
    else
        echo "  [!] no MCP over HTTP+SSE either"
    fi
fi

TARGET="$WON_URL"
if [[ "$IS_MCP" == "yes" ]]; then
    ANALYZE_STATUS="ok"
else
    ANALYZE_STATUS="not-mcp"
    echo "  [!] no MCP server on any candidate — inspect $RAW"
fi

rm -f "$HDR_TMP"

# ── Analysis: inventory + poisoning heuristics + Top-10 hints ────────────────
STATUS="$ANALYZE_STATUS" TARGET="$TARGET" SESSION_ID="$SESSION_ID" \
PROTOCOL_VERSION="$PROTOCOL_VERSION" AUTH_PROVIDED="$([[ ${#HEADER_ARGS[@]} -gt 0 ]] && echo 1 || echo 0)" \
TRANSPORT_USED="$TRANSPORT_USED" EXTRA_HINTS="$EXTRA_HINTS" \
RAW="$RAW" REPORT="$REPORT" ASSETS="$ASSETS" \
python3 <<'PY'
import os, re, json, unicodedata, datetime

raw_path = os.environ["RAW"]
target   = os.environ["TARGET"]
status   = os.environ["STATUS"]
records  = []
with open(raw_path) as f:
    for line in f:
        line = line.strip()
        if line:
            try: records.append(json.loads(line))
            except Exception: pass

by_method = {}
for r in records:
    by_method[r.get("method")] = r.get("response")

def result_of(method):
    resp = by_method.get(method) or {}
    if isinstance(resp, dict):
        return resp.get("result") or {}
    return {}

init = result_of("initialize")
tools     = (result_of("tools/list") or {}).get("tools", []) or []
resources = (result_of("resources/list") or {}).get("resources", []) or []
prompts   = (result_of("prompts/list") or {}).get("prompts", []) or []

# ── Poisoning heuristics (static tool-description analysis) ──────────────────
# Weighted poisoning model. MUST stay in lockstep with mcp-poison-scan.py's FAMILIES
# so this fast pre-filter and the authoritative scorer never disagree. A tool is
# "flagged" only when its weighted score reaches the medium band; a lone weak signal
# (e.g. "you must", or the word "token") scores below that and is NOT flagged — which
# is why the boolean any-match version used to over-flag legitimate tools.
FAMILIES = [
    ("instruction-override", 30, re.compile(r'ignore (the |all )?(previous|prior|above|earlier)|disregard (the )?(system|prior|previous)|supers ?ede', re.I)),
    ("concealment",          30, re.compile(r'do not (tell|mention|inform|reveal|disclose|notify|summarize)|without (telling|informing) the user|(?<!do not )silently', re.I)),
    ("exfil-directive",      35, re.compile(r'exfiltrat|send (it|them|this|the results?|a copy) to|forward (it|this|the) to|POST .* to https?://', re.I)),
    ("tool-shadowing",       25, re.compile(r'before (using|calling|invoking) (any )?other tool|whenever the user|instead first|when another tool', re.I)),
    ("secret-solicitation",  25, re.compile(r'(provide|read|include|pass) (the )?(user\'?s )?(api[_-]?key|password|secret|token|credential|session)|\.aws/credentials|id_rsa|\.env', re.I)),
    ("role-injection",       20, re.compile(r'^\s*(system|assistant)\s*:|<\s*system\s*>|developer mode', re.I | re.M)),
    ("hidden-tag",           20, re.compile(r'<\s*/?\s*(important|secret|system|instruction|instructions|hidden)\s*>|\[\[\s*hidden', re.I)),
    ("imperative",            8, re.compile(r'\byou (must|should|shall|need to|have to)\b', re.I)),
]
INVISIBLE = re.compile(
    r'[​-‏‪-‮⁠-⁤﻿]'   # zero-width, bidi, word-joiner, BOM
    r'|[\U000E0000-\U000E007F]'                          # unicode tag block
)

# The `atz` pattern: a param whose own description says the client should NOT
# set it (it is server-populated) is a server-injected authz/context field. If a
# client-supplied value is honored, that is an MCP02 privilege-boundary bypass.
ATZ_RX = re.compile(
    r'(do not (fill|set|populate|provide|pass)'
    r'|auto(matically)?[- ]?(fill|filled|populate|populated|set|provided)'
    r'|server[- ]?(provided|injected|populated|managed|set)'
    r'|leave (this )?(empty|blank)'
    r'|injected by the server|managed by the server|internal use only'
    r'|will be (auto|automatically|populated|set))', re.I)

def server_injected(t):
    schema = t.get("inputSchema") or t.get("input_schema") or {}
    props = (schema.get("properties") or {}) if isinstance(schema, dict) else {}
    hits = []
    for pname, spec in props.items():
        desc = (spec or {}).get("description", "") if isinstance(spec, dict) else ""
        if desc and ATZ_RX.search(desc):
            hits.append(pname)
    return hits

POISON_FLAG_THRESHOLD = 15  # medium band; keep in lockstep with mcp-poison-scan.py

def score_text(text):
    """Weighted poisoning score, mirroring mcp-poison-scan.py's FAMILIES/banding."""
    fams, score = [], 0
    if text:
        for label, weight, rx in FAMILIES:
            if rx.search(text):
                fams.append(label)
                score += weight
        if INVISIBLE.search(text):
            fams.append("invisible-unicode")
            score += 40
    score = min(100, score)
    band = ("critical" if score >= 60 else "high" if score >= 35
            else "medium" if score >= POISON_FLAG_THRESHOLD else "clean")
    return score, band, sorted(set(fams))

def tool_blob(t):
    # same surface the scorer reads: name + description + property descriptions + schema
    parts = [t.get("name", "") or "", t.get("description", "") or ""]
    schema = t.get("inputSchema") or t.get("input_schema") or {}
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    for _, spec in (props or {}).items():
        if isinstance(spec, dict) and spec.get("description"):
            parts.append(spec["description"])
    try:
        parts.append(json.dumps(schema))
    except Exception:
        pass
    return "\n".join(parts)

poison = []
tool_out = []
server_injected_all = []
for t in tools:
    name = t.get("name", "?")
    score, band, flags = score_text(tool_blob(t))
    sinj = server_injected(t)
    tool_out.append({
        "name": name,
        "description": t.get("description", ""),
        "input_schema": t.get("inputSchema") or t.get("input_schema") or {},
        "annotations": t.get("annotations", {}),
        "flags": flags,
        "poison_score": score,
        "poison_band": band,
        "server_injected_params": sinj,
    })
    if band != "clean":
        poison.append({"tool": name, "flags": flags, "score": score, "band": band})
    for p in sinj:
        server_injected_all.append({"tool": name, "param": p})

# ── Top-10 hints ────────────────────────────────────────────────────────────
hints = []
if status != "ok":
    hints.append("initialize failed -> retry with/without --auth; try /mcp, /sse, /message paths (MCP09)")
else:
    if os.environ.get("AUTH_PROVIDED") == "0":
        hints.append("MCP07/MCP09: server enumerated WITHOUT auth — test unauth tools/call for real effect")
    if tools:
        hints.append(f"MCP05: {len(tools)} tools — fuzz string params for command/SSRF injection: "
                     f"mcp-probe.sh --assets <this>/mcp-assets.json --oob-base http://<ip>:18080 [top lane]")
        hints.append("MCP02: tools with id/account/org/path params -> mcp-confirm.py authz (4-way BOLA/BFLA)")
        admin = [t['name'] for t in tool_out if re.search(r'admin|delete|write|create|update|exec|config|grant|impersonat', (t['name'] or '')+' '+(t['description'] or ''), re.I)]
        if admin:
            hints.append("MCP02(BFLA): privileged-looking tools -> " + ", ".join(admin[:8]))
    if server_injected_all:
        pairs = ", ".join(f"{s['tool']}.{s['param']}" for s in server_injected_all[:8])
        hints.append(f"MCP02(atz): server-injected authz/context param(s) -> {pairs}. "
                     f"Override test: set them to another id; if honored = privilege bypass.")
    if poison:
        hints.append(f"MCP03: {len(poison)} tool description(s) flagged for poisoning — review raw bytes (mcp-poison-scan.py)")
    if resources:
        hints.append(f"MCP01/MCP10: {len(resources)} resources — read for secrets + cross-user scoping")
for _h in os.environ.get("EXTRA_HINTS", "").splitlines():
    if _h.strip():
        hints.append(_h.strip())

assets = {
    "target": target,
    "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "transport": os.environ.get("TRANSPORT_USED", "streamable-http"),
    "protocol_version": os.environ.get("PROTOCOL_VERSION"),
    "session_id": os.environ.get("SESSION_ID") or None,
    "auth_provided": os.environ.get("AUTH_PROVIDED") == "1",
    "is_mcp": status == "ok",
    "server_info": init.get("serverInfo", {}),
    "server_capabilities": init.get("capabilities", {}),
    "tools": tool_out,
    "resources": resources,
    "prompts": prompts,
    "poisoning_flags": poison,
    "server_injected_params": server_injected_all,
    "top10_hints": hints,
}
with open(os.environ["ASSETS"], "w") as f:
    json.dump(assets, f, indent=2)

# ── Markdown report ─────────────────────────────────────────────────────────
def esc(s): return str(s).replace("|", "¦").replace("\n", " ")
L = []
L.append("# MCP Server Inventory")
L.append("")
L.append(f"**Target:** {target}  ")
L.append(f"**Date:** {assets['generated']}  ")
L.append(f"**MCP server:** {'yes' if assets['is_mcp'] else 'NO (see raw)'}  ")
si = assets["server_info"]
if si:
    L.append(f"**Server:** {si.get('name','?')} {si.get('version','')}  ")
L.append(f"**Auth provided:** {assets['auth_provided']} | **Session:** {assets['session_id'] or '-'}")
L.append("")
if poison:
    L.append("## ⚠ Tool Poisoning Flags")
    L.append("")
    for p in poison:
        L.append(f"- **{esc(p['tool'])}** [{p['band']} {p['score']}] -> {', '.join(p['flags'])}")
    L.append("")
    L.append("_Score/band mirror mcp-poison-scan.py (>=15 medium). Inspect the raw (unrendered) "
             "description bytes; confirm an attacker can introduce/alter it (MCP03)._")
    L.append("")
if server_injected_all:
    L.append("## Server-injected (atz) params — MCP02 override candidates")
    L.append("")
    for s in server_injected_all:
        L.append(f"- **{esc(s['tool'])}.{esc(s['param'])}** — description says the client should not set it")
    L.append("")
    L.append("_These are populated server-side (identity/context). Set them to another id via a tool "
             "call; if the server honors the client value it is a privilege-boundary bypass (mcp-confirm.py authz)._")
    L.append("")
L.append(f"## Tools ({len(tool_out)})")
L.append("")
if tool_out:
    L.append("| Tool | Poisoning | Description |")
    L.append("|------|-----------|-------------|")
    for t in tool_out:
        pz = (f"{t['poison_band']} ({t['poison_score']}): {', '.join(t['flags'])}"
              if t['poison_band'] != "clean" else "-")
        L.append(f"| {esc(t['name'])} | {esc(pz)} | {esc((t['description'] or '')[:120])} |")
else:
    L.append("_none returned_")
L.append("")
L.append(f"## Resources ({len(resources)})")
L.append("")
for r in resources[:200]:
    L.append(f"- `{esc(r.get('uri', r.get('name','?')))}` — {esc((r.get('description','') or '')[:100])}")
if not resources: L.append("_none returned_")
L.append("")
L.append(f"## Prompts ({len(prompts)})")
L.append("")
for p in prompts[:200]:
    L.append(f"- `{esc(p.get('name','?'))}` — {esc((p.get('description','') or '')[:100])}")
if not prompts: L.append("_none returned_")
L.append("")
L.append("## OWASP MCP Top-10 Hints")
L.append("")
for h in hints:
    L.append(f"- {h}")
L.append("")
L.append("_Next: read `artemis/references/owasp-mcp-top10.md` and route per the ownership table._")
with open(os.environ["REPORT"], "w") as f:
    f.write("\n".join(L) + "\n")

# console summary
print("")
print(f"  server:    {si.get('name','?')} {si.get('version','') if si else ''}".rstrip())
print(f"  tools:     {len(tool_out)}   resources: {len(resources)}   prompts: {len(prompts)}")
if poison:
    print(f"  ⚠ poisoning flags on {len(poison)} tool(s)")
for h in hints:
    print(f"  hint: {h}")
PY

echo ""
echo "=== Enumeration Complete ==="
echo "Inventory: $REPORT"
echo "Assets:    $ASSETS"
echo "Raw:       $RAW"
[[ "$ANALYZE_STATUS" == "ok" ]] && exit 0 || exit 3
