#!/usr/bin/env python3
"""
authz-confirm.py — automate the 4-way BOLA/IDOR/BFLA differential (Grimnir confirmation harness).

Runs own / cross / nonexistent / malformed with the ATTACKER's credentials against a URL template,
computes the differential, and writes evidence/<id>/authz.json (the negative-control artifact the gate
consumes). Mechanism/policy split: the verdict is machine-readable; gate, operator, and a future
autonomous validator all read the same record.

  authz-confirm.py --finding-id FINDING-003 --project-dir ~/workspace/prog \
     --method GET --url 'https://api.x/users/{id}/card' \
     -H 'Authorization: Bearer ATTACKER' \
     --own-id 1001 --victim-id 1002 --nonexistent-id 999999 [--malformed-id '%2e%2e'] \
     [--victim-marker 'Lucinda']

Verdict:
  confirmed     cross==200 AND contains --victim-marker (definitive victim-data exposure)
  bola-likely   cross==200 AND body distinct from the nonexistent-id response (add a marker to confirm)
  negative      cross mirrors nonexistent (scoped) OR cross == own (caller's data) OR cross is 401/403
                ("mirrors" and "==" compare bodies with each arm's id and per-request noise such as
                CSP nonces normalized out, so a page that ignores the id is not read as distinct)
  inconclusive  empty / ambiguous -> enrich victim data (the bitso "Lucinda" rule)
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module)
import egress as _egress  # noqa: E402  the program's egress proxy: every request rides it or refuses


def fetch(method, url, headers, body=None):
    cmd = ["curl", "-sS", "-g", "-m", "20", "-o", "-", "-w", "\n__HTTP_%{http_code}__", "-X", method]
    cmd += _egress.curl_args(_egress.proxy())
    for h in headers:
        cmd += ["-H", h]
    if body is not None:
        # --data-binary, not --data: --data strips newlines and would silently corrupt a
        # multi-line GraphQL query or any body whose bytes matter.
        cmd += ["--data-binary", body]
        if not any(h.lower().startswith("content-type:") for h in headers):
            cmd += ["-H", "Content-Type: application/json"]
    cmd += [url]
    _pace.before(url)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception as e:
        return {"status": 0, "len": 0, "sha": "", "snip": f"error:{e}", "body": ""}
    status, body = 0, out
    if "\n__HTTP_" in out:
        body, _, tail = out.rpartition("\n__HTTP_")
        status = int(tail.replace("__", "").strip() or 0)
        _pace.after(url, status)
    b = body.encode("utf-8", "replace")
    return {"status": status, "len": len(b), "sha": hashlib.sha256(b).hexdigest()[:16],
            "snip": body[:200], "body": body}


# Per-request noise a server-rendered page carries (CSP nonces, request ids, timestamps, cache
# busters). Two responses that differ only here are the same page.
_NOISE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
                    r"|(?<![A-Za-z0-9])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9])|\d{6,}")
_SPLIT = re.compile(r"[\s<>\"',;:{}\[\]()=]+")
SAME_SIMILARITY = 0.98


def normalize(body: str, own_id: str = "") -> str:
    """The body with the arm's own id replaced (it is reflected per arm) and per-request noise
    collapsed, so a page that ignores the id compares equal across arms."""
    if own_id and len(str(own_id)) >= 2:
        body = body.replace(str(own_id), "\x00ID\x00")
    return _NOISE.sub("\x00N\x00", body)


def similarity(a: str, b: str) -> float:
    ta, tb = Counter(t for t in _SPLIT.split(a) if t), Counter(t for t in _SPLIT.split(b) if t)
    total = sum(ta.values()) + sum(tb.values())
    return 1.0 if not total else 2 * sum((ta & tb).values()) / total


def same(x: dict, y: dict) -> bool:
    """Two arms returned the same thing: same status and the same normalized body (exactly, or
    nearly: a page with a per-request widget still reads as one page)."""
    if x.get("status") != y.get("status"):
        return False
    if x.get("sha") == y.get("sha"):
        return True
    nx, ny = normalize(x.get("body", ""), x.get("id", "")), normalize(y.get("body", ""), y.get("id", ""))
    return nx == ny or similarity(nx, ny) >= SAME_SIMILARITY


def classify_verdict(own, cross, non, victim_marker):
    """Pure verdict from the 4-way differential (own/cross/nonexistent). Each arg is a fetch()
    dict {status, len, sha, snip, body}. Ladder: a victim marker in a cross 200 is definitive;
    a denied cross is negative; a cross 200 distinct from the nonexistent-id control is a likely
    bypass; a cross that mirrors nonexistent or own is scoped/self. See the module docstring.

    Positive-control guard: a "negative"/"bola-likely" is only meaningful if the OWN arm (the
    positive control) actually succeeded. If own != 200 we proved NOTHING about authorization --
    the endpoint / feature / credential is simply unavailable to us -- so a confident "negative"
    would be a FALSE negative that can hide a real bypass behind a broken test setup. Downgrade to
    inconclusive with the reason so the caller fixes access and re-tests. A "confirmed" (a victim
    marker actually returned in a 200) stands regardless -- that is positive evidence in hand."""
    verdict, why = "inconclusive", "ambiguous (empty/identical responses) — enrich victim data and re-test"
    if victim_marker and cross["status"] == 200 and victim_marker in cross["body"]:
        verdict, why = "confirmed", f"cross returned 200 containing victim marker '{victim_marker}'"
    elif cross["status"] in (401, 403):
        verdict, why = "negative", f"cross denied ({cross['status']})"
    elif cross["status"] == 200 and not same(cross, non):
        if same(cross, own):
            verdict, why = "negative", "cross == own response (caller's own data; the id is ignored)"
        else:
            verdict, why = "bola-likely", "cross 200 distinct from nonexistent-id; add --victim-marker to confirm"
    elif same(cross, non):
        verdict, why = ("negative", "cross mirrors nonexistent-id (scoped)") if cross["sha"] == non["sha"] else (
            "negative", "cross mirrors nonexistent-id once ids and per-request noise are normalized "
                        "(the endpoint ignores the id)")

    if verdict in ("negative", "bola-likely") and own["status"] != 200:
        verdict, why = "inconclusive", (
            f"positive control failed: own-id returned {own['status']} (expected 200) — cannot "
            f"conclude authorization; establish working access and re-test")
    return verdict, why


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True, help="URL template with {id}")
    ap.add_argument("--body", default=None,
                    help="Request body template; {id} substitutes here too. Required for the "
                         "lanes where the object reference is not in the URL -- GraphQL is "
                         "POST-only, and write BOLA (PATCH/PUT) outranks read.")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--own-id", required=True)
    ap.add_argument("--victim-id", required=True)
    ap.add_argument("--nonexistent-id", required=True)
    ap.add_argument("--malformed-id", default="%2e%2e%2f")
    ap.add_argument("--victim-marker", default="")
    a = ap.parse_args()
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env

    def U(i):
        return a.url.replace("{id}", str(i))

    def B(i):
        # Same substitution as the URL. The four arms must differ ONLY by the id, or the
        # differential is measuring something other than authorization.
        return None if a.body is None else a.body.replace("{id}", str(i))

    r = {k: fetch(a.method, U(v), a.headers, B(v)) for k, v in
         (("own", a.own_id), ("cross", a.victim_id),
          ("nonexistent", a.nonexistent_id), ("malformed", a.malformed_id))}
    for k, v in (("own", a.own_id), ("cross", a.victim_id), ("nonexistent", a.nonexistent_id),
                 ("malformed", a.malformed_id)):
        r[k]["id"] = str(v)       # each arm's id, normalized out before arms are compared
    own, cross, non = r["own"], r["cross"], r["nonexistent"]

    verdict, why = classify_verdict(own, cross, non, a.victim_marker)

    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "authz",
           "verdict": verdict, "why": why, "ts": datetime.now(timezone.utc).isoformat(),
           "differential": {k: {kk: v[kk] for kk in ("status", "len", "sha", "snip")} for k, v in r.items()},
           "negative_control": f"4-way differential (own/cross/nonexistent/malformed): {why}"}
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    json.dump(rec, open(os.path.join(d, "authz.json"), "w"), indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/authz.json")
    if own["status"] != 200:
        print(f"  ! positive control weak: own-id returned {own['status']} (expected 200)", file=sys.stderr)


if __name__ == "__main__":
    main()
