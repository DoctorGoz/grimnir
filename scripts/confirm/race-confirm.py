#!/usr/bin/env python3
"""
race-confirm.py — confirm a race-condition / limit-overrun (TOCTOU, double-spend, faucet,
coupon/voucher reuse, quota bypass) for the Grimnir confirmation harness.

A limit is a check-then-act: read a counter/balance/one-time flag, then act on it. Fire N
copies of the *same* state-changing request so their check-then-act windows overlap, and the
limit is applied once while the action runs N times. This tool fires that concurrent burst and
decides, deterministically, whether more attempts succeeded than the limit should ever allow.

  race-confirm.py --finding-id SPE-004 --project-dir ~/workspace/prog \
     --method POST --url 'https://api.x/v1/coupons/redeem' \
     -H 'Authorization: Bearer TOKEN' --body '{"code":"PROMO50"}' \
     --count 30 --expected-max 1 --success-marker '"redeemed":true' \
     [--sequential-control] [--insecure]

Verdict (writes evidence/<id>/race.json, the artifact the gate consumes):
  confirmed     successes > --expected-max. subtype:
                  race              a sequential control stayed within the limit but the
                                    concurrent burst broke it (a genuine TOCTOU window)
                  no-limit          the sequential control ALSO overran (no working limit at all)
                  overrun-concurrent  burst overran; no control was run to tell the two apart
  negative      successes <= --expected-max: the limit held under concurrency
  inconclusive  0 successes: positive control failed (wrong auth/params, or the resource was
                already exhausted) — a limit that never allowed one success cannot be judged

WHY IN-PROCESS SOCKETS (not curl like the other primitives): a race needs the N requests to
leave the host together. Spawning N curl processes adds process-start + TLS-handshake jitter
that is wider than many race windows. Here every connection is opened and TLS-handshaked BEFORE
a threading.Barrier, so the barrier releases into request bytes, not into connection setup.
This is coarse single-packet alignment; a true HTTP/2 single-packet attack is a future upgrade.

STATE-CHANGING BY NATURE: every arm mutates server state (spends, redeems, transfers). This is
NEVER an auto-fire lane — the calling harness forces a race lane to human (--operator-override), and
the operator points it only at a throwaway / reversible resource on their own account.
"""
import argparse
import hashlib
import http.client
import json
import os
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import egress as _egress  # noqa: E402  the program's egress proxy: raw sockets ride it or refuse


def _parse_headers(pairs):
    out = {}
    for h in pairs:
        if ":" in h:
            k, _, v = h.partition(":")
            out[k.strip()] = v.strip()
    return out


def _one_request(url, method, headers, body, timeout, insecure, connect=None):
    """Open + TLS-handshake a single connection (the expensive part). Returns (conn, send_fn).
    send_fn() performs the request/response and returns a result dict. Splitting the two lets the
    caller pay setup cost before the barrier and time only the send. `connect` is a
    socks_connect_factory: the socket (DNS + TCP) is built through the program's proxy."""
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if parts.scheme == "https":
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    if connect is not None:
        def _via_proxy(address, timeout=timeout, source_address=None):
            return connect(address, timeout)
        conn._create_connection = _via_proxy
    conn.connect()  # DNS + TCP + TLS paid here, before the barrier

    def send():
        t0 = time.monotonic()
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(65536)
            status = resp.status
        except Exception as e:  # noqa: BLE001 — a failed arm is data, not a crash
            return {"status": 0, "len": 0, "sha": "", "snip": f"error:{e}",
                    "body": "", "sent_at": t0}
        finally:
            try:
                conn.close()
            except Exception:
                pass
        return {"status": status, "len": len(raw),
                "sha": hashlib.sha256(raw).hexdigest()[:16],
                "snip": raw[:200].decode("utf-8", "replace"),
                "body": raw.decode("utf-8", "replace"), "sent_at": t0}

    return conn, send


def _burst(url, method, headers, body, count, timeout, insecure, connect=None):
    """Open `count` connections, align them on a barrier, fire together. Returns the response
    dicts in completion order plus the send-time spread in ms (how tight the burst actually was)."""
    conns, sends, open_errors = [], [], 0
    for _ in range(count):
        try:
            conn, send = _one_request(url, method, headers, body, timeout, insecure, connect)
            conns.append(conn)
            sends.append(send)
        except Exception as e:  # noqa: BLE001
            open_errors += 1
            sends.append(lambda e=e: {"status": 0, "len": 0, "sha": "",
                                      "snip": f"connect-error:{e}", "body": "",
                                      "sent_at": time.monotonic()})
    barrier = threading.Barrier(len(sends))
    results, lock = [], threading.Lock()

    def worker(fn):
        try:
            barrier.wait(timeout=timeout + 5)
        except threading.BrokenBarrierError:
            pass
        r = fn()
        with lock:
            results.append(r)

    threads = [threading.Thread(target=worker, args=(fn,)) for fn in sends]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 10)
    sent = [r["sent_at"] for r in results if r.get("sent_at")]
    spread_ms = round((max(sent) - min(sent)) * 1000, 2) if len(sent) > 1 else 0.0
    return results, spread_ms, open_errors


def _sequential(url, method, headers, body, count, timeout, insecure, delay, connect=None):
    """The control: the same requests one at a time. On a resource whose limit is real, this stays
    within the limit; only concurrency breaks it. Meaningful only for a REPLENISHABLE limit (a rate
    cap, a refilling faucet, a multi-use code) — for a strict single-use resource it just consumes
    it, so it is opt-in."""
    out = []
    for _ in range(count):
        _, send = _one_request(url, method, headers, body, timeout, insecure, connect)
        out.append(send())
        if delay:
            time.sleep(delay)
    return out


def _is_success(r, success_status, success_marker):
    if r["status"] not in success_status:
        return False
    return (not success_marker) or (success_marker in r["body"])


def classify_race_verdict(successes, expected_max, count, control_successes=None):
    """Pure verdict from the success counts. `control_successes` is the sequential control's
    success count (None if no control ran). See the module docstring for the ladder."""
    if count <= 0:
        return "inconclusive", "no-requests", "no requests were sent"
    if successes <= 0:
        return "inconclusive", "no-success", (
            f"0/{count} attempts succeeded — positive control failed (wrong auth/params, or the "
            f"resource was already exhausted). A limit that never allowed one success cannot be judged.")
    if successes > expected_max:
        if control_successes is None:
            return "confirmed", "overrun-concurrent", (
                f"{successes}/{count} concurrent attempts succeeded (> expected max {expected_max}) — "
                f"limit overrun under concurrency. Add --sequential-control to separate a TOCTOU race "
                f"from a missing limit.")
        if control_successes <= expected_max:
            return "confirmed", "race", (
                f"{successes}/{count} concurrent succeeded but the sequential control allowed only "
                f"{control_successes}/{count} (<= {expected_max}) — a true TOCTOU race: the limit "
                f"holds sequentially and breaks under concurrency.")
        return "confirmed", "no-limit", (
            f"{successes}/{count} concurrent AND {control_successes}/{count} sequential attempts "
            f"succeeded (both > {expected_max}) — the operation has no working limit at all "
            f"(a missing check, not a race).")
    return "negative", "limit-held", (
        f"{successes}/{count} concurrent attempts succeeded (<= expected max {expected_max}) — the "
        f"limit held under concurrency.")


def _histogram(results):
    h = {}
    for r in results:
        k = str(r["status"])
        h[k] = h.get(k, 0) + 1
    return dict(sorted(h.items()))


def main():
    ap = argparse.ArgumentParser(description="Confirm a race / limit-overrun via a concurrent burst.")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--url", required=True)
    ap.add_argument("--body", default=None, help="Request body (state-changing lanes usually need one).")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--count", type=int, default=20, help="Concurrent attempts in the burst (default 20).")
    ap.add_argument("--expected-max", type=int, default=1,
                    help="Max successes the limit should ever allow (default 1 = single-use).")
    ap.add_argument("--success-status", default="200,201",
                    help="Comma list of status codes that count as a success (default 200,201).")
    ap.add_argument("--success-marker", default="",
                    help="String that must appear in a successful body (strengthens the count; "
                         "avoids counting a 200 error page as a success).")
    ap.add_argument("--sequential-control", action="store_true",
                    help="Also fire the same N requests sequentially, to tell a TOCTOU race from a "
                         "missing limit. Consumes the resource — for REPLENISHABLE limits only.")
    ap.add_argument("--control-delay", type=float, default=0.0,
                    help="Seconds between sequential-control requests (default 0).")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification (staging/self-signed).")
    a = ap.parse_args()

    headers = _parse_headers(a.headers)
    if a.body is not None and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    success_status = {int(s) for s in a.success_status.split(",") if s.strip().isdigit()}

    # Egress: the burst opens its own connections (that is what keeps the race window tight), so it
    # cannot shell out to curl. A SOCKS proxy is honored by riding socks.socksocket; anything else
    # this client cannot route through refuses (exit 2) rather than firing around the proxy.
    try:
        proxy = _egress.proxy(a.project_dir)
    except _egress.EgressError as e:
        print(f"race-confirm.py: refusing to run — {e}", file=sys.stderr)
        sys.exit(2)
    connect = None
    if proxy:
        try:
            connect = _egress.socks_connect_factory(proxy)
        except _egress.EgressError as e:
            print(f"race-confirm.py: {e}", file=sys.stderr)
            _egress.refuse_if_proxied("race-confirm.py", proxy)   # exits 2

    # Optional sequential control FIRST (a fresh/replenished resource), then the concurrent burst.
    control_successes = None
    control_rec = None
    if a.sequential_control:
        cres = _sequential(a.url, a.method, headers, a.body, a.count, a.timeout, a.insecure,
                           a.control_delay, connect=connect)
        control_successes = sum(1 for r in cres if _is_success(r, success_status, a.success_marker))
        control_rec = {"count": a.count, "successes": control_successes,
                       "status_histogram": _histogram(cres)}

    results, spread_ms, open_errors = _burst(
        a.url, a.method, headers, a.body, a.count, a.timeout, a.insecure, connect=connect)
    successes = sum(1 for r in results if _is_success(r, success_status, a.success_marker))
    verdict, subtype, why = classify_race_verdict(successes, a.expected_max, a.count, control_successes)

    responses = [{"status": r["status"], "len": r["len"], "sha": r["sha"], "snip": r["snip"],
                  "success": _is_success(r, success_status, a.success_marker)}
                 for r in results[:40]]
    rec = {
        "schema": 1, "finding_id": a.finding_id, "vuln_class": "race",
        "verdict": verdict, "subtype": subtype, "why": why,
        "ts": datetime.now(timezone.utc).isoformat(),
        "burst": {"count": a.count, "successes": successes, "expected_max": a.expected_max,
                  "success_status": sorted(success_status), "success_marker": a.success_marker,
                  "send_spread_ms": spread_ms, "open_errors": open_errors,
                  "status_histogram": _histogram(results)},
        "sequential_control": control_rec,
        "responses": responses,
        "responses_truncated": len(results) > 40,
        "negative_control": (
            f"concurrent burst of {a.count} vs expected-max {a.expected_max}: {successes} succeeded "
            f"(spread {spread_ms}ms). {why}"),
    }
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    json.dump(rec, open(os.path.join(d, "race.json"), "w"), indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "subtype", "why")}, indent=2))
    print(f"wrote {d}/race.json")
    if successes == 0:
        print(f"  ! positive control weak: 0/{a.count} succeeded — establish a working request first",
              file=sys.stderr)
    elif spread_ms > 50:
        print(f"  ! burst spread {spread_ms}ms is wide — a tighter race window may be missed",
              file=sys.stderr)


if __name__ == "__main__":
    main()
