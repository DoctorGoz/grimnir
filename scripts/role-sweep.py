#!/usr/bin/env python3
"""role-sweep.py — screen every documented read against the roles the docs say it must refuse.

When the target documents who may call each operation (a per-operation "Authorization Requirement"),
that table is a function-level authorization oracle: an operation documented as site-admin-only that
answers a plain user is a candidate, with the program's own docs as the expected result. This tool
turns the table into one cheap request per (operation, denied role), so the expensive differential
(tier-confirm.py: high, low, anon, repeats) runs only on what answered.

Inputs
  --oracle TSV       columns: method, path, and an authorization column (--authz-col, default
                     docs_authz) holding role codes joined by "|" (e.g. "SA|WA"). Rows whose flags
                     column contains a --skip-flag value are never requested.
  --deny CODE=ACCTS  repeatable: the vault accounts that hold NONE of the roles in a row whose code
                     set is exactly CODE ("SA=A1-rdr,A1-fa"). A row is requested only as these.
  --admin ACCT       the high account: resolves {id}-style path parameters by listing the parent
                     collection, and is the positive control the screen compares against.
  --xsite ACCT       optional: a high account in ANOTHER tenant. Its resolved ids are requested
                     with --admin's credentials (cross-tenant object reads), once per {id} operation.
  --base URL         API base the oracle paths hang off (https://host/api/rest/v1).

Every URL passes the engagement scope gate (scope.py) and the RoE pacer (roe.json rate + daily
budget) before it is sent; GET only. Results go to --out as JSONL, one row per request:
  {op, role, url, status, len, items, hit}
A hit is a 2xx carrying data: a non-empty list, or an object. Hits are candidates for tier-confirm,
never findings. Nothing here prints a credential.

  role-sweep.py --project-dir DIR --oracle DIR/huginn/recon/authz-matrix.tsv \
      --base https://site.example.com/api/rest/v1 --admin A1 \
      --deny SA=A1-rdr,A1-fa,A1-ga,A1-wsa,A1-pa --deny 'SA|WA=A1-rdr,A1-fa,A1-ga,A1-pa' \
      --skip-flag AI-BANNED --out DIR/specter/recon/role-sweep-A1.jsonl [--dry-run] [--limit N]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "confirm"))
import egress  # noqa: E402
import roe as _roe  # noqa: E402
import scope as _scope  # noqa: E402

PARAM = re.compile(r"\{([^}]+)\}")


def vault(project_dir: str) -> dict:
    out = {}
    with open(os.path.join(project_dir, "credentials.jsonl")) as fh:
        for line in fh:
            if line.strip():
                r = json.loads(line)
                out[r.get("account")] = r
    return out


def headers_of(rec: dict) -> dict:
    h = {}
    for line in rec.get("auth_headers") or []:
        if isinstance(line, str) and ":" in line:
            k, v = line.split(":", 1)
            h[k.strip()] = v.strip()
    return h


class Sender:
    def __init__(self, project_dir: str, dry: bool):
        self.project_dir = project_dir
        self.dry = dry
        self.roe = _roe.load(project_dir)
        self.scope = _scope.load(project_dir)
        self.opener = egress.opener(proxy=egress.proxy(project_dir))
        self.extra = dict(self.roe.get("required_headers") or {})
        self.sent = 0

    def get(self, url: str, auth: dict) -> tuple[int | None, bytes, str]:
        v = self.scope.check(url)
        if not v.in_scope:
            return None, b"", f"scope: {v.reason}"
        if self.dry:
            return None, b"", "dry-run"
        block = _roe.global_block(self.project_dir, False, self.roe)
        if block:
            return None, b"", block
        _roe.pace(self.project_dir, url, self.roe)
        req = urllib.request.Request(url, method="GET", headers={
            "Accept": "application/json", "User-Agent": "grimnir-role-sweep/1.0", **self.extra, **auth})
        self.sent += 1
        try:
            with self.opener.open(req, timeout=30) as r:
                body = r.read(400_000)
                _roe.note_status(self.project_dir, url, r.status)
                return r.status, body, ""
        except urllib.error.HTTPError as e:
            _roe.note_status(self.project_dir, url, e.code)
            return e.code, e.read(4000), ""
        except Exception as e:  # noqa: BLE001
            return None, b"", f"{type(e).__name__}: {e}"


def shape(body: bytes) -> tuple[int | None, bool]:
    """(items, carries_data) for a JSON body."""
    try:
        d = json.loads(body)
    except ValueError:
        return None, bool(body.strip())
    if isinstance(d, list):
        return len(d), len(d) > 0
    if isinstance(d, dict):
        return None, bool(d) and not d.get("error")
    return None, False


def resolve_hint(path: str, hints: list[tuple[str, str]]) -> str | None:
    """The --resolve value whose prefix is exactly the path before its first parameter."""
    m = PARAM.search(path)
    parent = path[:m.start()].rstrip("/") if m else None
    return next((v for pre, v in hints if parent is not None and parent == pre.rstrip("/")), None)


def first_id(sender: Sender, base: str, path: str, auth: dict, cache: dict) -> str | None:
    """Resolve the first {param} by listing the parent collection (/things/{id}/... -> GET /things)."""
    m = PARAM.search(path)
    parent = path[:m.start()].rstrip("/")
    if not parent or PARAM.search(parent):
        return None
    if parent in cache:
        return cache[parent]
    st, body, _ = sender.get(f"{base}{parent}?per_page=5", auth)
    val = None
    if st and 200 <= st < 300:
        try:
            d = json.loads(body)
            row = d[0] if isinstance(d, list) and d else None
            val = str(row.get("id") or row.get("path") or "") if isinstance(row, dict) else None
        except ValueError:
            pass
    cache[parent] = val or None
    return cache[parent]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--authz-col", default="docs_authz")
    ap.add_argument("--base", required=True)
    ap.add_argument("--admin", required=True)
    ap.add_argument("--xsite")
    ap.add_argument("--deny", action="append", default=[])
    ap.add_argument("--skip-flag", action="append", default=[])
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0, help="stop after N requests (0 = no cap)")
    ap.add_argument("--resolve", action="append", default=[],
                    help="PREFIX=VALUE: fill the first path parameter after PREFIX with VALUE instead of listing "
                         "the parent (/files=docs/a.txt, /history/users=1234). Longest prefix wins.")
    ap.add_argument("--retry-skips", action="store_true",
                    help="re-attempt operations an earlier run skipped for an unresolved path parameter")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    egress.init(a.project_dir)
    v = vault(a.project_dir)
    deny = {}
    for spec in a.deny:
        code, _, accts = spec.partition("=")
        names = [x for x in accts.split(",") if x]
        missing = [x for x in names if x not in v]
        if missing:
            sys.exit(f"--deny {code}: not in the vault: {','.join(missing)}")
        deny[code] = names
    admin = headers_of(v[a.admin])
    xsite = headers_of(v[a.xsite]) if a.xsite else None
    base = a.base.rstrip("/")
    xbase = f"https://{v[a.xsite]['host']}{urllib.parse.urlsplit(base).path}" if a.xsite else None
    s = Sender(a.project_dir, a.dry_run)

    with open(a.oracle) as fh:
        rows = [r for r in csv.DictReader(fh, delimiter="\t")
                if r.get("method", "").upper() == "GET"
                and not any(f in (r.get("flags") or "") for f in a.skip_flag)]
    done = set()
    if os.path.exists(a.out):
        with open(a.out) as fh:
            for line in fh:
                r = json.loads(line)
                if not (a.retry_skips and r.get("skip")):
                    done.add((r["op"], r["role"]))
    cache, xcache = {}, {}
    hints = sorted((tuple(h.split("=", 1)) for h in a.resolve if "=" in h), key=lambda x: -len(x[0]))
    out = open(a.out, "a")
    hits = 0
    for r in rows:
        if a.limit and s.sent >= a.limit:
            break
        path, code = r["path"], (r.get(a.authz_col) or "").strip()
        roles = list(deny.get(code, []))
        if xsite and PARAM.search(path):
            roles.append("xsite")
        if not roles:
            continue
        op = f"GET {path}"
        url = base + path
        if PARAM.search(path):
            val = resolve_hint(path, hints) or first_id(s, base, path, admin, cache)
            if val is None or PARAM.search(path[PARAM.search(path).end():]):
                for role in roles:
                    if (op, role) not in done:
                        out.write(json.dumps({"op": op, "role": role, "url": None, "status": None,
                                              "skip": "unresolved path parameter"}) + "\n")
                continue
            url = base + PARAM.sub(val, path, count=1)
        for role in roles:
            if (op, role) in done or (a.limit and s.sent >= a.limit):
                continue
            target, auth = url, None
            if role == "xsite":
                # the other tenant's id (listed on ITS host with ITS key), asked on OUR host with OUR key
                xval = first_id(s, xbase, path, xsite, xcache) if not a.dry_run else "<xsite-id>"
                if not xval:
                    continue
                target, auth = base + PARAM.sub(xval, path, count=1), admin
            else:
                auth = headers_of(v[role])
            st, body, why = s.get(target, auth)
            items, data = shape(body) if st else (None, False)
            hit = bool(st and 200 <= st < 300 and data)
            hits += hit
            rec = {"op": op, "role": role, "url": target, "status": st, "len": len(body), "items": items,
                   "hit": hit, **({"note": why} if why else {}), "docs_authz": code}
            out.write(json.dumps(rec) + "\n")
            out.flush()
            if hit or a.dry_run:
                print(f"{'HIT ' if hit else '    '} {st} {role:10} {op}")
    out.close()
    print(f"[role-sweep] sent {s.sent}; hits {hits}; results -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
