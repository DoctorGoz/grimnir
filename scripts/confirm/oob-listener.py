#!/usr/bin/env python3
"""
oob-listener.py — self-hosted out-of-band interaction recorder (Grimnir confirmation harness).

Catches HTTP callbacks from a target's backend to CONFIRM blind vulnerabilities (SSRF,
injection-with-callback, IMDS-over-HTTP). IP-based: no domain needed — the target calls
http://<public-ip>:<port>/h/<nonce>. The per-test <nonce> is the correlation + isolation, so one
always-on listener serves every engagement without collision.

Routes (everything else -> 404, to stay quiet under internet scan noise):
  GET|POST /h/<nonce>            record a callback (proof a blind request reached us)
  GET      /r/<nonce>?to=<url>   record + 302 to <url>  (2-hop port/filter-bypass proof:
                                 hop1 on an allowed port -> 302 -> hop2 on a NON-allowed port)
  ANY      /s/<secs>/<nonce>     record, then stall <secs> before answering (timing oracle:
                                 a caller whose own response stalls with us fetched inline)

Evidence: one JSON line per hit appended to $GRIMNIR_OOB_LOG (default ~/.grimnir/oob/hits.jsonl).
Mechanism ONLY — verdict logic lives in oob-client.py (autonomy-ready; see
ROADMAP-confirmation-harness.md §8: mechanism/policy split).

Env:
  GRIMNIR_OOB_PORTS  comma list of ports to listen on   (default "18080,18081")
  GRIMNIR_OOB_LOG    evidence JSONL path                 (default ~/.grimnir/oob/hits.jsonl)
  GRIMNIR_OOB_BASE   public base shown at startup        (informational)
"""
import http.server
import json
import os
import socketserver
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

LOG = os.path.expanduser(os.environ.get("GRIMNIR_OOB_LOG", "~/.grimnir/oob/hits.jsonl"))
PORTS = [int(p) for p in os.environ.get("GRIMNIR_OOB_PORTS", "18080,18081").split(",") if p.strip()]
os.makedirs(os.path.dirname(LOG), exist_ok=True)
_lock = threading.Lock()

# headers worth keeping for correlation (the target's own trace ids self-confirm the callback)
TRACE_HEADERS = ("traceparent", "x-request-id", "x-amzn-trace-id", "x-honeycomb-trace",
                 "x-forwarded-for", "x-forwarded-host", "x-real-ip", "via", "user-agent", "host")


def record(port, handler, body, **extra):
    u = urlparse(handler.path)
    parts = u.path.strip("/").split("/")
    if len(parts) >= 3 and parts[0] == "s":
        nonce = parts[2]              # /s/<seconds>/<nonce>
    elif len(parts) >= 2 and parts[0] in ("h", "r"):
        nonce = parts[1]
    else:
        nonce = parts[0] if parts and parts[0] else ""
    hdrs = {k.lower(): v for k, v in handler.headers.items() if k.lower() in TRACE_HEADERS}
    rec = {
        "schema": 1,
        "ts": datetime.now(timezone.utc).isoformat(),
        "nonce": nonce,
        "port": port,
        "src_ip": handler.client_address[0],
        "method": handler.command,
        "path": handler.path,
        "headers": hdrs,
        "body": (body[:512].decode("utf-8", "replace") if body else ""),
    }
    rec.update(extra)
    with _lock:
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
    return rec, u


class H(http.server.BaseHTTPRequestHandler):
    server_version = "nginx"      # bland banner; don't advertise the tool
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):    # quiet; everything goes to the JSONL
        pass

    def _body(self):
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    def _handle(self):
        # /s/<seconds>/<nonce>  — slow response (sleep N seconds before responding). Used to
        # prove the target's fetch is SYNCHRONOUS: if the caller's own response stalls with us,
        # the request is inline. That is a timing oracle, so it has to leave an evidence row
        # like every other route -- recording only the fast paths meant a timing-confirmed
        # finding had nothing in the journal to point a triager at.
        seg = self.path.strip("/").split("/")
        if len(seg) >= 3 and seg[0] == "s":
            try:
                delay = max(0, min(int(seg[1]), 120))   # bounded: never hold a socket forever
            except ValueError:
                delay = 0
            record(self.server.server_address[1], self, self._body(), slow_seconds=delay)
            time.sleep(delay)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        body = self._body()
        rec, u = record(self.server.server_address[1], self, body)
        seg = u.path.strip("/").split("/")
        if seg and seg[0] == "r":                      # redirect hop
            to = parse_qs(u.query).get("to", [""])[0]
            if to:
                self.send_response(int(parse_qs(u.query).get("code",["302"])[0]))
                self.send_header("Location", to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
        if seg and seg[0] == "h":                      # primary callback
            payload = b"ok " + rec["nonce"].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    base = os.environ.get("GRIMNIR_OOB_BASE", "")
    print(f"[oob] logging -> {LOG}")
    for p in PORTS:
        threading.Thread(target=lambda port=p: Server(("0.0.0.0", port), H).serve_forever(),
                         daemon=True).start()
        print(f"[oob] listening 0.0.0.0:{p}  callback: {base or 'http://<public-ip>'}:{p}/h/<nonce>")
    print("[oob] ready (Ctrl-C to stop)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[oob] bye")


if __name__ == "__main__":
    main()
