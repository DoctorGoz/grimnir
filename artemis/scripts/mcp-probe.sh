#!/usr/bin/env bash
# mcp-probe.sh — systematic MCP05 (command / SSRF / traversal) fuzz driver.
#
# The force multiplier for the highest-yield MCP lane: takes an enumerated MCP
# surface, walks every string tool parameter, fires an injection payload set at
# each, and triages the responses. Out-of-band aware — with --oob-base it weaves
# a per-fire callback URL into the payloads so BLIND command/SSRF execution is
# caught by scripts/confirm/oob-listener.py (not just reflected output).
#
# Every HTTP call shells out to curl, so traffic flows through your proxy (Caido)
# and stays visible for later analysis. Read-first: it never fires at tools whose
# name/description looks destructive (delete/drop/revoke/...) unless --include-write.
#
# Pipeline: mcp-enum.sh (read the surface) -> mcp-probe.sh (find candidates) ->
#           scripts/confirm/mcp-confirm.py (produce the evidence-gate artifact).
#
# Usage:
#   # auto: derive tool+param pairs from a prior enum's mcp-assets.json
#   bash scripts/mcp-probe.sh <MCP_URL> --assets <mcp-assets.json> \
#        --auth "Authorization: Bearer <t>" --oob-base http://<ip>:18080 \
#        --project-dir "$PROJECT_DIR" --proxy "$PROXY"
#
#   # explicit: one tool/param, supplying the tool's other args
#   bash scripts/mcp-probe.sh <MCP_URL> --tool fetch --param url \
#        --base-args '{}' --mode ssrf --oob-base http://<ip>:18080 --auth "..."
#
# Options:
#   --assets FILE        mcp-assets.json from mcp-enum.sh (auto tool/param selection)
#   --tool NAME          Explicit single tool (with --param)
#   --param NAME         The parameter to inject (explicit mode)
#   --base-args JSON     Constant args for the tool; the injected param is overwritten
#   --mode M             cmdinj | ssrf | traversal | all   (default: all)
#   --payloads FILE      Use this payload file instead of the built-in wordlists
#   --oob-base URL       OOB listener base http://<ip>:<port> (enables blind confirm)
#   --include-write      Also probe destructive-looking tools (default: skip them)
#   --max-calls N        Cap total tool calls (default: 400)
#   --auth "<H: v>" / -H  Auth / extra header (repeatable)
#   --proxy URL          Proxy for curl (e.g. http://127.0.0.1:8080)
#   --project-dir DIR    Write under $DIR/artemis/recon/
#   --out DIR            Explicit output dir
#   --protocol-version / --timeout / --insecure
#
# Exit: 0 normal (see report for hits); 2 usage; 3 initialize failed.

set -uo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
    sed -n '2,45p' "$0"; exit 2
fi
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WL_DIR="$SCRIPT_DIR/../wordlists"

ASSETS=""; TOOL=""; PARAM=""; BASE_ARGS="{}"; MODE="all"; PAYLOADS_FILE=""
OOB_BASE=""; INCLUDE_WRITE=0; MAX_CALLS=400
HEADER_ARGS=(); PROXY=""; PROJECT_DIR=""; OUT=""
PROTOCOL_VERSION="2025-06-18"; TIMEOUT=30; INSECURE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --assets)           ASSETS="$2"; shift 2 ;;
        --tool)             TOOL="$2"; shift 2 ;;
        --param)            PARAM="$2"; shift 2 ;;
        --base-args)        BASE_ARGS="$2"; shift 2 ;;
        --mode)             MODE="$2"; shift 2 ;;
        --payloads)         PAYLOADS_FILE="$2"; shift 2 ;;
        --oob-base)         OOB_BASE="$2"; shift 2 ;;
        --include-write)    INCLUDE_WRITE=1; shift ;;
        --max-calls)        MAX_CALLS="$2"; shift 2 ;;
        --auth|-H)          HEADER_ARGS+=("$2"); shift 2 ;;
        --proxy)            PROXY="$2"; shift 2 ;;
        --project-dir)      PROJECT_DIR="$2"; shift 2 ;;
        --out)              OUT="$2"; shift 2 ;;
        --protocol-version) PROTOCOL_VERSION="$2"; shift 2 ;;
        --timeout)          TIMEOUT="$2"; shift 2 ;;
        --insecure)         INSECURE=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

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
[[ -z "$ASSETS" && -z "$TOOL" ]] && { echo "error: provide --assets FILE or --tool NAME --param NAME" >&2; exit 2; }
[[ -n "$TOOL" && -z "$PARAM" ]] && { echo "error: --tool requires --param" >&2; exit 2; }

# ── Resolve payload files by mode ──
PAYLOAD_FILES=()
if [[ -n "$PAYLOADS_FILE" ]]; then
    PAYLOAD_FILES=("$PAYLOADS_FILE")
else
    case "$MODE" in
        cmdinj)    PAYLOAD_FILES=("$WL_DIR/mcp-command-injection.txt") ;;
        ssrf)      PAYLOAD_FILES=("$WL_DIR/mcp-ssrf.txt") ;;
        traversal) PAYLOAD_FILES=("$WL_DIR/mcp-path-traversal.txt") ;;
        all)       PAYLOAD_FILES=("$WL_DIR/mcp-command-injection.txt" "$WL_DIR/mcp-ssrf.txt" "$WL_DIR/mcp-path-traversal.txt") ;;
        *) echo "error: --mode must be cmdinj|ssrf|traversal|all" >&2; exit 2 ;;
    esac
fi
for f in "${PAYLOAD_FILES[@]}"; do
    [[ -f "$f" ]] || { echo "error: payload file not found: $f" >&2; exit 2; }
done

TS="$(date +%Y%m%d-%H%M%S)"
if [[ -z "$OUT" ]]; then
    if [[ -n "$PROJECT_DIR" ]]; then OUT="$PROJECT_DIR/artemis/recon/mcp-probe-$TS"; else OUT="reports/mcp-probe-$TS"; fi
fi
mkdir -p "$OUT"

# ── Hand off to the python driver (curl-transported, so proxy stays in play) ──
export GN_TARGET="$TARGET" GN_ASSETS="$ASSETS" GN_TOOL="$TOOL" GN_PARAM="$PARAM"
export GN_BASE_ARGS="$BASE_ARGS" GN_OOB_BASE="$OOB_BASE" GN_INCLUDE_WRITE="$INCLUDE_WRITE"
export GN_MAX_CALLS="$MAX_CALLS" GN_PROXY="$PROXY" GN_PROTOCOL="$PROTOCOL_VERSION"
export GN_TIMEOUT="$TIMEOUT" GN_INSECURE="$INSECURE" GN_OUT="$OUT"
export GN_HEADERS="$(printf '%s\n' "${HEADER_ARGS[@]:-}")"
export GN_PAYLOAD_FILES="$(printf '%s\n' "${PAYLOAD_FILES[@]}")"

python3 <<'PY'
import os, re, sys, json, time, secrets, subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

TARGET   = os.environ["GN_TARGET"]
OUT      = os.environ["GN_OUT"]
PROXY    = os.environ.get("GN_PROXY", "")
PROTO    = os.environ.get("GN_PROTOCOL", "2025-06-18")
TIMEOUT  = os.environ.get("GN_TIMEOUT", "30")
INSECURE = os.environ.get("GN_INSECURE", "0") == "1"
OOB_BASE = os.environ.get("GN_OOB_BASE", "").rstrip("/")
INCLUDE_WRITE = os.environ.get("GN_INCLUDE_WRITE", "0") == "1"
MAX_CALLS = int(os.environ.get("GN_MAX_CALLS", "400"))
HEADERS  = [h for h in os.environ.get("GN_HEADERS", "").splitlines() if h.strip()]
PAYLOAD_FILES = [f for f in os.environ.get("GN_PAYLOAD_FILES", "").splitlines() if f.strip()]

DESTRUCTIVE = re.compile(r'(delete|destroy|remove|drop|purge|revoke|wipe|reset|terminate|deactivate|cancel|uninstall)', re.I)
# Tools that carry a message to people (a feedback form, a support ticket, an email): a canary fired
# there lands in someone's inbox, so they are skipped like destructive ones.
OUTBOUND = re.compile(r'(feedback|contact|message|mail|notify|submit|report|comment|ticket|support|invite|share|publish|reply)', re.I)
# A caller's floor (the read-only broker sets it): skipped regardless of --include-write or a
# server-supplied readOnlyHint, which the server under test controls.
SKIP_FLOOR = re.compile(os.environ["GN_SKIP_RE"], re.I) if os.environ.get("GN_SKIP_RE") else None


def skip_reason(name, annotations):
    if SKIP_FLOOR and SKIP_FLOOR.search(name):
        return "matches the caller's write floor"
    if not INCLUDE_WRITE and not annotations.get("readOnlyHint") and (DESTRUCTIVE.search(name) or OUTBOUND.search(name)):
        return "destructive or outbound-looking (use --include-write to force)"
    return ""
# Strong indicators that a payload actually did something server-side.
HIT_SIGS = [
    (re.compile(r'root:.*:0:0:'), "unix-passwd"),
    (re.compile(r'uid=\d+\([^)]+\)\s+gid=\d+'), "id-output"),
    (re.compile(r'(ami-id|instance-id|iam/security-credentials|instance-identity)'), "cloud-imds"),
    (re.compile(r'"?(AccessKeyId|SecretAccessKey|SessionToken)"?', re.I), "aws-creds"),
    (re.compile(r'-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----'), "private-key"),
    (re.compile(r'\[core\]\s'), "git-config"),
    (re.compile(r'ssh-rsa AAAA'), "ssh-pubkey"),
]

def load_payloads():
    out = []
    for f in PAYLOAD_FILES:
        with open(f, errors="ignore") as fh:
            for ln in fh:
                ln = ln.rstrip("\n")
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                out.append(s)
    return out

def needs_oob(p):
    return "{{OOB}}" in p or "{{OOBHOST}}" in p or "{{NONCE}}" in p

def subst(p, nonce):
    if not OOB_BASE:
        return p, None
    if not any(marker in p for marker in ("{{OOB}}", "{{OOBHOST}}", "{{NONCE}}")):
        # Static payload (no OOB placeholder) — nothing to correlate, so don't tag it
        # with a nonce/oob_url. Without this check every non-OOB payload (IMDS/loopback/
        # etc. literals) gets falsely counted as an "OOB fire" candidate in the report,
        # since the caller treats any non-None oob_url as "poll to confirm".
        return p, None
    oob_url = f"{OOB_BASE}/h/{nonce}"
    host = urlparse(OOB_BASE).netloc or OOB_BASE
    return (p.replace("{{OOB}}", oob_url).replace("{{OOBHOST}}", host).replace("{{NONCE}}", nonce), oob_url)

# ── curl transport (proxy-visible) ──
_session = {"id": None}
def _curl(body):
    cmd = ["curl", "-sS", "-m", TIMEOUT,
           "-H", "Content-Type: application/json",
           "-H", "Accept: application/json, text/event-stream",
           "-D", os.path.join(OUT, ".hdr")]
    if INSECURE: cmd.append("-k")
    if PROXY: cmd += ["--proxy", PROXY]
    for h in HEADERS: cmd += ["-H", h]
    if _session["id"]: cmd += ["-H", f"Mcp-Session-Id: {_session['id']}"]
    cmd += ["-d", body, TARGET]
    try:
        raw = subprocess.run(cmd, capture_output=True, text=True, timeout=int(TIMEOUT) + 5).stdout
    except Exception as e:
        return {"__error__": f"curl:{e}"}, ""
    # capture session id if the server just issued one
    try:
        for line in open(os.path.join(OUT, ".hdr"), errors="ignore"):
            if line.lower().startswith("mcp-session-id:"):
                _session["id"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return _normalize(raw), raw

def _normalize(raw):
    if "data:" in raw and ("event:" in raw or raw.lstrip().startswith("data:")):
        datas = [ln[5:].lstrip() for ln in raw.splitlines() if ln.rstrip("\r").startswith("data:")]
        try:
            return json.loads("\n".join(datas).strip())
        except Exception:
            pass
    try:
        return json.loads(raw)
    except Exception:
        return {"__error__": "unparseable", "raw": raw[:400]}

def rpc(method, params, mid=None):
    b = {"jsonrpc": "2.0", "method": method, "params": params}
    if mid is not None: b["id"] = mid
    return _curl(json.dumps(b))

def result_text(msg):
    """Flatten a tools/call result to text + whether it was an error."""
    if not isinstance(msg, dict): return "", True
    if "error" in msg: return json.dumps(msg["error"]), True
    res = msg.get("result", {})
    if isinstance(res, dict):
        is_err = bool(res.get("isError"))
        parts = []
        for c in res.get("content", []) or []:
            if c.get("type") == "text": parts.append(c.get("text", ""))
            else: parts.append(json.dumps(c))
        if not parts: parts.append(json.dumps(res))
        return "\n".join(parts), is_err
    return json.dumps(res), False

# ── Handshake ──
init, _ = rpc("initialize", {"protocolVersion": PROTO, "capabilities": {},
              "clientInfo": {"name": "grimnir-artemis-mcp-probe", "version": "0.1"}}, 1)
if not (isinstance(init, dict) and isinstance(init.get("result"), dict)
        and any(k in init["result"] for k in ("serverInfo", "capabilities", "protocolVersion"))):
    print("[!] initialize failed — not MCP / wrong path / auth-gated:", json.dumps(init)[:300], file=sys.stderr)
    sys.exit(3)
rpc("notifications/initialized", {})

# ── Build the (tool, param, schema) work list ──
def string_params(schema):
    props = (schema or {}).get("properties", {}) or {}
    out = []
    for name, spec in props.items():
        t = spec.get("type")
        if t == "string" or (isinstance(t, list) and "string" in t) or ("enum" in spec):
            out.append(name)
    return out

def default_for(spec):
    if "enum" in spec and spec["enum"]: return spec["enum"][0]
    t = spec.get("type")
    if isinstance(t, list): t = t[0] if t else "string"
    return {"string": "grimnir-probe", "integer": 1, "number": 1, "boolean": False,
            "array": [], "object": {}}.get(t, "grimnir-probe")

worklist = []  # (tool_name, param, schema_props, base_args)
assets_path = os.environ.get("GN_ASSETS", "")
if assets_path:
    assets = json.load(open(assets_path))
    for t in assets.get("tools", []):
        name = t.get("name", "")
        desc = t.get("description", "") or ""
        annotations = t.get("annotations", {}) or {}
        why = skip_reason(name, annotations)
        if why:
            print(f"  [skip] tool '{name}': {why}")
            continue
        schema = t.get("input_schema") or t.get("inputSchema") or {}
        props = (schema.get("properties", {}) or {})
        for p in string_params(schema):
            worklist.append((name, p, props))
else:
    name = os.environ["GN_TOOL"]; param = os.environ["GN_PARAM"]
    if SKIP_FLOOR and SKIP_FLOOR.search(name):
        print(f"refused: tool '{name}' matches the caller's write floor", file=sys.stderr)
        sys.exit(3)
    base = json.loads(os.environ.get("GN_BASE_ARGS") or "{}")
    props = {k: {"type": "string"} for k in base}  # unknown schema; treat base as given
    worklist.append((name, param, props, base))

payloads = load_payloads()
if not OOB_BASE:
    skipped = [p for p in payloads if needs_oob(p)]
    payloads = [p for p in payloads if not needs_oob(p)]
    if skipped:
        print(f"  [note] --oob-base not set: skipping {len(skipped)} blind OOB payload(s); running reflected/target payloads only")

results = []
nonces = []
calls = 0
capped = False

def build_args(props, param, value, explicit_base=None):
    args = dict(explicit_base) if explicit_base is not None else {}
    if explicit_base is None:
        for k, spec in props.items():
            if k == param: continue
            if isinstance(spec, dict) and spec.get("required_default") is not None:
                args[k] = spec["required_default"]
            else:
                args[k] = default_for(spec if isinstance(spec, dict) else {})
    args[param] = value
    return args

for item in worklist:
    if len(item) == 4:
        tool, param, props, explicit_base = item
    else:
        tool, param, props = item; explicit_base = None
    # per (tool,param) benign baseline for length-diff triage
    base_args = build_args(props, param, "grimnir-benign-baseline", explicit_base)
    bmsg, _ = rpc("tools/call", {"name": tool, "arguments": base_args}, 2); calls += 1
    btext, _ = result_text(bmsg)
    blen = len(btext)
    for p in payloads:
        if calls >= MAX_CALLS:
            capped = True; break
        nonce = "gn" + secrets.token_hex(6)
        val, oob_url = subst(p, nonce)
        args = build_args(props, param, val, explicit_base)
        msg, _ = rpc("tools/call", {"name": tool, "arguments": args}, 3); calls += 1
        text, is_err = result_text(msg)
        sigs = [label for rx, label in HIT_SIGS if rx.search(text)]
        ldiff = len(text) - blen
        verdict = "rejected" if is_err else ("SIGNAL" if sigs else ("anomaly" if abs(ldiff) > max(40, blen * 0.5) else "returned"))
        rec = {"tool": tool, "param": param, "payload": p, "sent": val,
               "nonce": nonce if oob_url else None, "oob_url": oob_url,
               "is_error": is_err, "signals": sigs, "len_diff": ldiff,
               "verdict": verdict, "snippet": text[:300]}
        results.append(rec)
        if oob_url: nonces.append(nonce)
    if capped: break

# ── Write outputs ──
with open(os.path.join(OUT, "probe-results.jsonl"), "w") as f:
    for r in results:
        f.write(json.dumps(r) + "\n")
try: os.remove(os.path.join(OUT, ".hdr"))
except OSError: pass

signals = [r for r in results if r["verdict"] == "SIGNAL"]
anomalies = [r for r in results if r["verdict"] == "anomaly"]
rejected = sum(1 for r in results if r["verdict"] == "rejected")

L = ["# MCP05 Probe Results", "",
     f"**Target:** {TARGET}  ",
     f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ",
     f"**Calls:** {calls}{' (capped)' if capped else ''} | **params probed:** {len(worklist)} | "
     f"**payloads/param:** {len(payloads)}  ",
     f"**OOB:** {OOB_BASE or 'disabled (reflected-only)'}", ""]
if signals:
    L += ["## SIGNAL — response carried an execution/exfil indicator", ""]
    for r in signals:
        L.append(f"- **{r['tool']}({r['param']})** sigs={r['signals']} payload=`{r['payload']}`")
        L.append(f"  - sent: `{r['sent']}`")
        L.append(f"  - snippet: `{r['snippet'][:160]}`")
    L.append("")
if nonces:
    L += ["## Blind OOB fires — poll the listener to confirm", "",
          "Each payload carried a unique callback nonce. Confirm any that called back:", "",
          "```",
          f"# fired {len(nonces)} OOB nonce(s); poll a hit and mint the evidence artifact:",
          "python3 scripts/confirm/oob-client.py poll <nonce> 60",
          "```",
          "Nonces: " + ", ".join(nonces[:40]) + (" ..." if len(nonces) > 40 else ""), ""]
if anomalies:
    L += [f"## Anomalies — response length diverged from baseline ({len(anomalies)})", ""]
    for r in anomalies[:30]:
        L.append(f"- {r['tool']}({r['param']}) len_diff={r['len_diff']} payload=`{r['payload']}`")
    L.append("")
L += ["## Summary", "",
      f"- SIGNAL (strong): {len(signals)}",
      f"- OOB fires (poll to confirm): {len(nonces)}",
      f"- anomalies (length diff): {len(anomalies)}",
      f"- rejected (input validated): {rejected}",
      f"- total results: {len(results)}", "",
      "_Confirm a SIGNAL/OOB hit with `scripts/confirm/mcp-confirm.py` to produce the "
      "evidence-gate artifact (verdict.json / authz.json), then promote with validate-finding.sh._"]
open(os.path.join(OUT, "probe-report.md"), "w").write("\n".join(L) + "\n")

print("")
print(f"  calls: {calls}{' (capped)' if capped else ''}  results: {len(results)}")
print(f"  SIGNAL: {len(signals)}   OOB fires: {len(nonces)}   anomaly: {len(anomalies)}   rejected: {rejected}")
for r in signals[:10]:
    print(f"  [SIGNAL] {r['tool']}({r['param']}) {r['signals']}  <- {r['payload']}")
if nonces:
    print(f"  [OOB] poll to confirm blind execution: python3 scripts/confirm/oob-client.py poll {nonces[0]} 60")
print(f"\n  report: {os.path.join(OUT, 'probe-report.md')}")
PY

echo ""
echo "=== Probe Complete ==="
echo "Report:  $OUT/probe-report.md"
echo "Results: $OUT/probe-results.jsonl"
