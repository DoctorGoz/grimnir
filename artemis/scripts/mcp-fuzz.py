#!/usr/bin/env python3
"""mcp-fuzz.py - small schema-driven fuzz of an MCP server's tools. Reports CANDIDATES only.

For each tool's inputSchema, sends a fixed payload set per string parameter: path traversal,
command injection, SSRF to your local callback listener, template injection, one oversized value
and a few type-confusion values. At most --max-per-tool calls per tool (default 40), rate limited.
A signal here is a lead, not a finding: promote it with scripts/confirm/mcp-confirm.py.

THIS CALLS THE SERVER'S TOOLS. It refuses to run without --i-understand-this-calls-tools, and
skips tools that look destructive or outbound (by name, description or destructiveHint) unless
--include-destructive is given. A server's readOnlyHint is not trusted.

  mcp-fuzz.py <url> --i-understand-this-calls-tools [--tool NAME] [--auth "H: v"]
              [--oob-base http://127.0.0.1:18080] [--rate 5] [--max-per-tool 40] [--out DIR]
              [--project-dir DIR]
With --project-dir (a Grimnir engagement) the run honors the program's rules of engagement: it
refuses when roe.json bans automated scanning, paces every request through roe.py, sends the
required headers, rides the program's egress proxy, and writes under DIR/artemis/recon/.
SSRF cases need --oob-base pointing at the OOB listener; without it they are skipped.
"""
import argparse
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.request

# roe-import-layer:begin
# Rules-of-engagement and egress layer (optional): present in a Grimnir tree, absent from a
# standalone copy of this script.
_SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts")
try:
    sys.path.insert(0, _SCRIPTS)
    import egress as _egress
    import roe as _roe
except ImportError:
    _egress = _roe = None
# roe-import-layer:end

PROTO = "2025-06-18"
DESTRUCTIVE = re.compile(r"(delete|destroy|remove|drop|purge|revoke|wipe|reset|terminate|deactivate|cancel|uninstall|"
                         r"create|update|write|insert|send|transfer|pay\b|grant|deploy|install|disable|rotate|overwrite|"
                         r"feedback|contact|message|mail|notify|submit|report|comment|ticket|support|invite|share|"
                         r"publish|reply|book|order|purchase|subscribe|register|upload)", re.I)
SIGNALS = [  # (label, regex) applied to the tool response text
    ("passwd-content", re.compile(r"root:[^\n]*:0:0:")),
    ("id-output", re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+")),
    ("cmd-evaluated", re.compile(r"mtprobe42")),
    ("template-evaluated", re.compile(r"1787569")),
    ("cloud-metadata", re.compile(r"(ami-id|instance-id|iam/security-credentials|AccessKeyId)")),
    ("error-leak", re.compile(r"(Traceback \(most recent|\bat [\w.$<>]+ \([^)]*:\d+:\d+\)|panic:|SQL syntax|"
                              r"ORA-\d{4,5}|OverflowError|RangeError|stack trace)", re.I)),
]


class Client:
    def __init__(self, url, headers, proxy, timeout, insecure, pace=None):
        self.url, self.headers, self.timeout, self.session, self.pace = url, headers, timeout, None, pace
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        hs = [urllib.request.HTTPSHandler(context=ctx)]
        if _egress:   # egress-layer: socks-capable, and refuses rather than connecting directly
            self.opener = _egress.opener(*hs, proxy=proxy)
        else:
            hs.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}) if proxy else urllib.request.ProxyHandler({}))
            self.opener = urllib.request.build_opener(*hs)

    def rpc(self, method, params, mid=None):
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if mid is not None:
            body["id"] = mid
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", **self.headers}
        if self.session:
            h["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, json.dumps(body).encode(), h, method="POST")
        if self.pace:
            self.pace()
        try:
            r = self.opener.open(req, timeout=self.timeout)
            raw = r.read().decode("utf-8", "replace")
            self.session = r.headers.get("Mcp-Session-Id") or self.session
        except urllib.error.HTTPError as e:
            return {"__error__": f"http {e.code}"}
        except Exception as e:
            return {"__error__": type(e).__name__}
        if "data:" in raw and raw.lstrip().startswith(("data:", "event:")):
            raw = "\n".join(l[5:].lstrip() for l in raw.splitlines() if l.startswith("data:"))
        try:
            return json.loads(raw) if raw.strip() else {}
        except ValueError:
            return {"__error__": "unparseable"}


def text_of(msg):
    if not isinstance(msg, dict):
        return "", True
    if "__error__" in msg:
        return msg["__error__"], True
    if "error" in msg:
        return json.dumps(msg["error"]), True
    res = msg.get("result") or {}
    parts = [c.get("text", "") if c.get("type") == "text" else json.dumps(c) for c in res.get("content", []) or []]
    return "\n".join(parts) or json.dumps(res), bool(res.get("isError"))


def cases(oob_base):
    """Fixed per-parameter payload set: (class, label, value, needs_nonce)."""
    c = [("traversal", "dotdot", "../../../../etc/passwd", False),
         ("traversal", "dotdot-encoded", "..%2f..%2f..%2f..%2fetc%2fpasswd", False),
         ("traversal", "absolute", "/etc/passwd", False),
         ("cmdinj", "semicolon", "x; echo mtprobe$((6*7))", False),
         ("cmdinj", "subshell", "$(echo mtprobe$((6*7)))", False),
         ("cmdinj", "backtick", "`echo mtprobe$((6*7))`", False),
         ("cmdinj", "pipe-id", "x | id", False),
         ("template", "jinja", "{{1337*1337}}", False),
         ("template", "dollar", "${1337*1337}", False),
         ("template", "erb", "<%= 1337*1337 %>", False)]
    if oob_base:
        c.append(("ssrf", "oob-callback", oob_base.rstrip("/") + "/h/{nonce}", True))
    c.append(("oversized", "10k", "A" * 10000, False))
    for label, v in (("int", 0), ("array", ["a"]), ("object", {"a": 1}), ("null", None)):
        c.append(("type-confusion", label, v, False))
    return c


def default_for(spec):
    t = spec.get("type") if isinstance(spec, dict) else None
    t = t[0] if isinstance(t, list) and t else t
    if isinstance(spec, dict) and spec.get("enum"):
        return spec["enum"][0]
    return {"integer": 1, "number": 1, "boolean": False, "array": [], "object": {}}.get(t, "grimnir-benign")


def string_params(schema):
    props = (schema or {}).get("properties") or {}
    return [n for n, s in props.items() if isinstance(s, dict) and (s.get("type") == "string" or
            (isinstance(s.get("type"), list) and "string" in s["type"])) and not s.get("enum")]


def skip_reason(tool, include_destructive):
    if include_destructive:
        return ""
    ann = tool.get("annotations") or {}
    if ann.get("destructiveHint"):
        return "destructiveHint"
    if DESTRUCTIVE.search(tool.get("name", "")):
        return "name looks destructive/outbound"
    if DESTRUCTIVE.search(tool.get("description", "") or ""):
        return "description looks destructive/outbound"
    return ""


def oob_hits(nonce):
    log = os.path.expanduser(os.environ.get("GRIMNIR_OOB_LOG", "~/.grimnir/oob/hits.jsonl"))
    n = 0
    if os.path.exists(log):
        for l in open(log, errors="ignore"):
            if nonce in l:
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("url")
    ap.add_argument("--i-understand-this-calls-tools", action="store_true", dest="ack")
    ap.add_argument("--include-destructive", action="store_true")
    ap.add_argument("--tool", default="")
    ap.add_argument("--auth", "-H", action="append", default=[], dest="headers")
    ap.add_argument("--oob-base", default=os.environ.get("GRIMNIR_OOB_BASE", ""))
    ap.add_argument("--rate", type=float, default=5.0, help="max calls per second (default 5)")
    ap.add_argument("--max-per-tool", type=int, default=40)
    ap.add_argument("--proxy", default=os.environ.get("GRIMNIR_PROXY", ""))
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out", default="")
    ap.add_argument("--project-dir", default="", help="Grimnir engagement dir: apply its roe.json")
    a = ap.parse_args()
    if not a.ack:
        print("refusing to run: fuzzing calls the server's tools with attack payloads.\n"
              "Only use it on servers you own or are authorized to test, then pass "
              "--i-understand-this-calls-tools.", file=sys.stderr)
        return 2
    pace = None
    headers = {}
    # roe-layer:begin
    if a.project_dir and _roe:
        roe = _roe.load(a.project_dir)
        if roe.get("automated_scanning_banned"):
            print("refusing to run: this program's roe.json bans automated scanning, and a fuzz "
                  "is exactly that. Test by hand, or have the operator change roe.json.", file=sys.stderr)
            return 4
        for line in _roe.required_header_lines(a.project_dir):
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
        pace = lambda: _roe.pace(a.project_dir, a.url, roe)   # noqa: E731  per-host rate across processes
    if _egress:
        _egress.init(a.project_dir or None)
        try:
            a.proxy = a.proxy or _egress.proxy()   # an explicit --proxy wins over roe.json
            _egress.opener(proxy=a.proxy)           # raises on an unusable proxy: refuse, never go direct
        except _egress.EgressError as e:
            print(f"refusing to run: {e}", file=sys.stderr)
            return 4
    # roe-layer:end
    for h in a.headers:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    cl = Client(a.url, headers, a.proxy, a.timeout, a.insecure, pace)
    init = cl.rpc("initialize", {"protocolVersion": PROTO, "capabilities": {},
                                 "clientInfo": {"name": "grimnir-mcp-fuzz", "version": "0.2"}}, 1)
    if not isinstance(init.get("result"), dict):
        print("initialize failed (not MCP / auth-gated)", file=sys.stderr)
        return 3
    cl.rpc("notifications/initialized", {})
    tools = ((cl.rpc("tools/list", {}, 2).get("result") or {}).get("tools")) or []
    out = a.out or time.strftime("mcp-fuzz-%Y%m%d-%H%M%S")
    if not a.out:
        out = os.path.join(a.project_dir, "artemis", "recon", out) if a.project_dir else os.path.join("reports", out)
    os.makedirs(out, exist_ok=True)
    gap, last, calls, results, skipped = 1.0 / max(a.rate, 0.1), 0.0, 0, [], []
    fired = []  # (record, nonce) awaiting OOB check
    for t in tools:
        name = t.get("name", "")
        if a.tool and name != a.tool:
            continue
        why = skip_reason(t, a.include_destructive)
        if why:
            skipped.append({"tool": name, "reason": why})
            continue
        schema = t.get("inputSchema") or t.get("input_schema") or {}
        props = schema.get("properties") or {}
        n = 0
        for p in string_params(schema):
            for cls, label, val, needs_nonce in cases(a.oob_base):
                if n >= a.max_per_tool:
                    break
                nonce = "mt" + secrets.token_hex(6) if needs_nonce else None
                if nonce:
                    val = val.replace("{nonce}", nonce)
                args = {k: default_for(s) for k, s in props.items()}
                args[p] = val
                wait = gap - (time.time() - last)
                if wait > 0:
                    time.sleep(wait)
                last = time.time()
                txt, is_err = text_of(cl.rpc("tools/call", {"name": name, "arguments": args}, 3))
                n += 1
                calls += 1
                sigs = [l for l, rx in SIGNALS if rx.search(txt)]
                rec = {"tool": name, "param": p, "class": cls, "case": label,
                       "sent": (val if not isinstance(val, str) or len(val) < 80 else val[:40] + f"...({len(val)} chars)"),
                       "is_error": is_err, "signals": sigs, "snippet": txt[:200], "nonce": nonce}
                results.append(rec)
                if nonce:
                    fired.append(rec)
    if fired:
        time.sleep(2)  # allow a slow callback to land
        for rec in fired:
            if oob_hits(rec["nonce"]):
                rec["signals"].append("oob-callback")
    cands = [r for r in results if r["signals"]]
    with open(os.path.join(out, "fuzz-results.jsonl"), "w") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")
    L = ["# MCP fuzz candidates", "",
         f"**Target:** {a.url}  ", f"**Calls:** {calls} | **candidates:** {len(cands)} | **tools skipped:** {len(skipped)}", "",
         "_Candidates are leads only. Confirm each with scripts/confirm/mcp-confirm.py (with a negative control) before reporting._", ""]
    for r in cands:
        L.append(f"- **{r['tool']}({r['param']})** {r['class']}/{r['case']}: {', '.join(r['signals'])}  sent=`{r['sent']}`")
    for s in skipped:
        L.append(f"- skipped `{s['tool']}`: {s['reason']}")
    open(os.path.join(out, "fuzz-report.md"), "w").write("\n".join(L) + "\n")
    print(f"calls: {calls}  candidates: {len(cands)}  skipped tools: {len(skipped)}")
    for r in cands:
        print(f"  [candidate] {r['tool']}({r['param']}) {r['class']}/{r['case']} -> {r['signals']}")
    for s in skipped:
        print(f"  [skip] {s['tool']}: {s['reason']}")
    print(f"report: {os.path.join(out, 'fuzz-report.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
