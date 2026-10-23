#!/usr/bin/env python3
"""
TLS out-of-band listener — proves an SSRF fetch reached us over https://.

The problem this solves: a plain-HTTP OOB listener is useless when the target
only dials `https://` URLs. The TLS handshake fails before any HTTP request is
written, so nothing is ever logged and a real SSRF looks like a negative.

The insight: you do NOT need a valid handshake to prove SSRF. A TCP connection
arriving on 443 already proves the target resolved your hostname and dialed it.
Parsing the TLS ClientHello's SNI extension additionally proves WHICH hostname
it used — which is exactly what distinguishes a filter bypass (e.g. the target
dialed `127.0.0.1.nip.io`) from incidental traffic.

So this listener records three escalating levels of proof:
  1. TCP_CONNECT  — something dialed us. Enough to de-blind an SSRF.
  2. TLS_SNI      — the ClientHello named a hostname. Proves the exact bypass.
  3. HTTP_REQUEST — the peer accepted our self-signed cert and sent a request.
                    Only happens when the client skips verification, but when it
                    does you get headers, method, and path for free.

Every event is appended to a JSONL journal and echoed to stdout.

Usage:
    sudo python3 tls-oob-listener.py --port 443 --journal /path/to/oob.jsonl
    sudo python3 tls-oob-listener.py --port 443 --token my-unique-tag
"""

import argparse
import datetime
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _rung  # noqa: E402  (sibling module; see its docstring for why the path nudge)

JOURNAL_LOCK = threading.Lock()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def record(journal, event):
    event["ts"] = now()
    line = json.dumps(event, sort_keys=True)
    with JOURNAL_LOCK:
        if journal:
            with open(journal, "a") as fh:
                fh.write(line + "\n")
    print(line, flush=True)


def parse_client_hello_sni(data):
    """Extract the SNI hostname from a raw TLS ClientHello.

    Returns None on anything unexpected — this is best-effort evidence
    gathering, not a TLS implementation. We walk the record layer, then the
    handshake body, skipping the fixed-size fields to reach the extension
    block, then look for extension type 0x0000 (server_name).
    """
    try:
        # TLS record: type(1) version(2) length(2)
        if len(data) < 5 or data[0] != 0x16:  # 0x16 = handshake
            return None
        pos = 5

        # Handshake: type(1) length(3) version(2) random(32)
        if len(data) < pos + 38 or data[pos] != 0x01:  # 0x01 = client_hello
            return None
        pos += 38

        # session_id
        if len(data) < pos + 1:
            return None
        pos += 1 + data[pos]

        # cipher_suites
        if len(data) < pos + 2:
            return None
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")

        # compression_methods
        if len(data) < pos + 1:
            return None
        pos += 1 + data[pos]

        # extensions
        if len(data) < pos + 2:
            return None
        ext_end = pos + 2 + int.from_bytes(data[pos:pos + 2], "big")
        pos += 2

        while pos + 4 <= min(ext_end, len(data)):
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            body = pos + 4
            if ext_type == 0x0000:  # server_name
                # server_name_list: length(2), then entries of type(1) len(2) host
                if body + 5 <= len(data):
                    name_len = int.from_bytes(data[body + 3:body + 5], "big")
                    host = data[body + 5:body + 5 + name_len]
                    return host.decode("utf-8", "replace")
                return None
            pos = body + ext_len
    except Exception:
        return None
    return None


def ensure_cert():
    """Generate a throwaway self-signed cert. Verification failing is fine —
    we already have our proof by the time the peer rejects it."""
    d = tempfile.mkdtemp(prefix="tls-oob-")
    key = os.path.join(d, "key.pem")
    crt = os.path.join(d, "cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", crt, "-days", "7",
         "-subj", "/CN=oob-listener"],
        check=True, capture_output=True,
    )
    return crt, key


def handle(conn, addr, ctx, journal, token):
    peer = f"{addr[0]}:{addr[1]}"
    try:
        conn.settimeout(10)

        # Level 1 + 2: peek at the ClientHello before the handshake consumes it.
        try:
            head = conn.recv(4096, socket.MSG_PEEK)
        except Exception:
            head = b""

        sni = parse_client_hello_sni(head) if head else None
        record(journal, {
            "event": "TLS_SNI" if sni else "TCP_CONNECT",
            "peer": addr[0],
            "peer_port": addr[1],
            "sni": sni,
            "token": token,
            "proof": ("ClientHello names this host — proves the target resolved "
                      "and dialed it" if sni else
                      "TCP connection received — proves the target dialed us"),
        })

        if not head:
            return

        # Level 3: try the handshake. Fails on any verifying client; that is
        # expected and costs us nothing since levels 1-2 already landed.
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            record(journal, {
                "event": "TLS_HANDSHAKE_REJECTED",
                "peer": addr[0],
                "sni": sni,
                "detail": str(exc)[:200],
                "note": ("Peer verified our cert and refused it. The connection "
                         "itself is still valid SSRF proof."),
            })
            return

        try:
            raw = tls.recv(8192)
        except Exception:
            raw = b""

        if raw:
            text = raw.decode("utf-8", "replace")
            first = text.split("\r\n")[0]
            headers = {}
            for ln in text.split("\r\n")[1:]:
                if not ln:
                    break
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            record(journal, {
                "event": "HTTP_REQUEST",
                "peer": addr[0],
                "sni": sni,
                "request_line": first,
                "headers": headers,
                "token": token,
                "proof": "Full request received over TLS — peer did not verify our cert",
            })
            body = json.dumps({"ok": True, "token": token, "ts": now()}).encode()
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"X-OOB-Token: " + (token or "none").encode() + b"\r\n\r\n" + body
            )
        try:
            tls.close()
        except Exception:
            pass
    except Exception as exc:  # never let one connection kill the listener
        record(journal, {"event": "ERROR", "peer": peer, "detail": str(exc)[:200]})
    finally:
        try:
            conn.close()
        except Exception:
            pass


#: Peers we dialed ourselves, or that dialed from this host. Never proof of anything --
#: a loopback self-test shows only that SNI parsing works, which is exactly the mistake
#: that once faked an SSRF negative for a whole session. See hunting Rule 30.
SELF_PEERS = ("127.0.0.1", "::1", "localhost")


def cmd_verdict(args):
    """Turn a journal into the same verdict.json every other confirm primitive emits.

    Without this the listener's proof is invisible to the rest of the harness: the
    evidence gate in validate-finding.sh and poc-export.py both look for a verdict
    record, so a finding confirmed by real TLS callbacks still exported an empty PoC
    bundle. The journal was never the problem; not speaking the common format was.
    """
    events = []
    try:
        with open(args.journal) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        continue
    except OSError as exc:
        print(f"cannot read journal: {exc}", file=sys.stderr)
        return 1

    dialed = [e for e in events
              if e.get("event") in ("TCP_CONNECT", "TLS_SNI", "HTTP_REQUEST")
              and (e.get("peer") or "") not in SELF_PEERS]
    if args.peer:
        dialed = [e for e in dialed if e.get("peer") in args.peer]

    sni = sorted({e["sni"] for e in dialed if e.get("sni")})
    peers = sorted({e["peer"] for e in dialed if e.get("peer")})
    named = [e for e in dialed if e.get("event") == "TLS_SNI"]

    rec = {
        "schema": 1,
        "finding_id": args.finding_id,
        "vuln_class": args.vuln_class,
        # WHAT CAME BACK, not that the request fired (hunting Rule 32). A TLS callback
        # proves reach; on its own that is the blind rung, and the gate caps it at medium.
        # Without this field every https-only SSRF confirmed here was capped by default.
        "channel_rung": _rung.normalize(args.channel_rung) or "blind",
        # A ClientHello naming our host is the strong form: it proves WHICH name the
        # target resolved. A bare TCP connect still de-blinds, but cannot attribute.
        "verdict": "confirmed" if named else ("inconclusive" if dialed else "refuted"),
        "transport": "tls",
        "sni_names": sni,
        "peer_ips": peers,
        "connections": len(dialed),
        "ts": now(),
        "evidence": dialed[: args.max_evidence],
        "journal": os.path.abspath(args.journal),
        "reproducer": (
            "configure the target to fetch https://<listener-host>/<path>, trigger the "
            "event, then re-run: tls-oob-listener.py verdict --journal <journal>"
        ),
        "note": (
            "Self-originated peers (%s) are excluded: a same-host curl proves the listener "
            "parses SNI, never that it was reachable from the internet." % ", ".join(SELF_PEERS)
        ),
    }

    pdir = args.project_dir or os.environ.get("PROJECT_DIR")
    if pdir and args.finding_id:
        d = os.path.join(pdir, "evidence", args.finding_id)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "verdict.json")
        with open(path, "w") as fh:
            json.dump(rec, fh, indent=2)
        print(f"wrote {path}")

    print(json.dumps({k: rec[k] for k in
                      ("finding_id", "vuln_class", "verdict", "channel_rung",
                       "connections", "peer_ips", "sni_names")}, indent=2))
    return 0 if rec["verdict"] == "confirmed" else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")

    v = sub.add_parser("verdict", help="derive verdict.json from an existing journal")
    v.add_argument("--journal", required=True)
    v.add_argument("--finding-id", required=True)
    v.add_argument("--vuln-class", default="ssrf")
    _rung.add_argument(v)
    v.add_argument("--project-dir", default=None,
                   help="writes evidence/<finding-id>/verdict.json (or set PROJECT_DIR)")
    v.add_argument("--peer", action="append",
                   help="only count these peer IPs; repeatable. Use to scope the verdict "
                        "to the target's documented egress addresses.")
    v.add_argument("--max-evidence", type=int, default=50)

    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--journal", default=None, help="JSONL path to append events to")
    ap.add_argument("--token", default=None, help="correlation tag echoed in responses")
    ap.add_argument("--cert", default=None)
    ap.add_argument("--key", default=None)
    args = ap.parse_args()

    if args.cmd == "verdict":
        return cmd_verdict(args)

    if args.cert and args.key:
        crt, key = args.cert, args.key
    else:
        crt, key = ensure_cert()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(128)

    record(args.journal, {
        "event": "LISTENER_START",
        "bind": f"{args.bind}:{args.port}",
        "cert": crt,
        "token": args.token,
    })

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(
                target=handle,
                args=(conn, addr, ctx, args.journal, args.token),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        record(args.journal, {"event": "LISTENER_STOP"})
    finally:
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
