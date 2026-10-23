#!/usr/bin/env python3
"""caido-export.py — the engagement's proxied traffic as a corpus source.

The requests the operator's browser and apps actually sent are the best map of a target: real
methods, real parameters, the authenticated routes a crawler never reaches. This reads Caido's
history (read-only SQLite, via session.py's reader) for the engagement's in-scope hosts and writes
recon/caido-traffic.jsonl, which huginn/scripts/corpus-build.py ingests as live-seen requests.

  caido-export.py --project-dir DIR [--since-days 30] [--caido-project NAME] [--dry-run]

One record per (method, url) with the newest status: {url, method, status_code, body_fields[],
tags["caido", "authed-traffic"?], accounts{label: newest status}}. `accounts` attributes the request to
the vault accounts that sent it (a stored session token in its Authorization or Cookie header, or a
JWT there whose subject or email names a credentials.jsonl account), so lane synthesis can tell routes
only a privileged account called. Nothing secret is written: header values and bodies are never
copied, only body field NAMES, and query values whose names look secret (token, key, code, sig,
password, session) are blanked. 404s, static files, and out-of-scope hosts are dropped.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import session as S  # noqa: E402
import graphql_ops as G  # noqa: E402

SECRET_PARAM = re.compile(r"token|secret|password|passwd|key|sig|code|session|auth|otp|nonce|ticket", re.I)
OUT = "caido-traffic.jsonl"
GQL_OUT = "graphql-ops.jsonl"
JWT = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]*")


def token_owners(store: dict) -> dict:
    """{stored access token: account} from sessions.json, for opaque tokens a JWT match can't see."""
    out = {}
    for acct, a in (store.get("accounts") or {}).items():
        if acct.startswith("sub:"):          # a subject no vault account claims
            continue
        for e in (a.get("clients") or {}).values():
            tok = e.get("access_token") or ""
            if len(tok) >= 16:
                out[tok] = acct
    return out


def account_of(headers, index, owners: dict) -> str:
    """The vault account a request's credentials belong to, or ""."""
    vals = [v for k, v in headers if k.lower() in ("authorization", "cookie")]
    for v in vals:
        for tok, acct in owners.items():
            if tok in v:
                return acct
    idents = set()
    for v in vals:
        for m in JWT.findall(v):
            c = S.jwt_claims(m) or {}
            idents |= {c.get(k) for k in ("sub", "email", "preferred_username", "uid")}
    return S.match_account(index, idents)


def clean_url(url: str) -> str:
    p = urlsplit(url)
    q = [(k, "" if SECRET_PARAM.search(k) else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), ""))


def _leaf_keys(doc, prefix: str = "", out: set | None = None, depth: int = 0) -> set:
    out = set() if out is None else out
    if depth > 6:
        return out
    if isinstance(doc, dict):
        for k, v in doc.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)) and v:
                _leaf_keys(v, key, out, depth + 1)
            else:
                out.add(key)
    elif isinstance(doc, list):
        for v in doc[:3]:
            _leaf_keys(v, f"{prefix}[]" if prefix else "[]", out, depth + 1)
    return out


def body_fields(body: bytes, ctype: str) -> list[str]:
    """Field NAMES only (dotted paths for JSON), never values."""
    if not body:
        return []
    txt = body.decode("utf-8", "replace")
    if "json" in ctype or txt.lstrip()[:1] in ("{", "["):
        try:
            return sorted(_leaf_keys(json.loads(txt)))[:60]
        except json.JSONDecodeError:
            return []
    if "form" in ctype or ("=" in txt and "\n" not in txt[:2000]):
        return sorted({k for k, _v in parse_qsl(txt, keep_blank_values=True)})[:60]
    return []


def blank_secrets(doc, depth: int = 0):
    """A copy with secret-named values blanked (csrf tokens, keys, passwords) at any depth."""
    if depth > 8:
        return doc
    if isinstance(doc, dict):
        return {k: ("" if SECRET_PARAM.search(str(k)) and isinstance(v, (str, int)) else blank_secrets(v, depth + 1))
                for k, v in doc.items()}
    if isinstance(doc, list):
        return [blank_secrets(v, depth + 1) for v in doc]
    return doc


def graphql_records(url: str, body: bytes, status: int, acct: str, ops: dict) -> None:
    """Fold one GraphQL POST into ops: {(endpoint, operation): record}. A record keeps the read/write
    verdict, the newest status per account, and per account the newest body with secrets blanked,
    which is what a replay as that account starts from."""
    try:
        doc = json.loads(body or b"{}")
    except json.JSONDecodeError:
        return
    endpoint = clean_url(url).split("?")[0]
    for op in (doc if isinstance(doc, list) else [doc]):
        if not isinstance(op, dict):
            continue
        name = G.op_name(op) or ("anon:" + hashlib.sha1(str(op.get("query", "")).encode()).hexdigest()[:10])
        kind, why = G.classify_op(op)
        rec = ops.setdefault((endpoint, name), {"url": endpoint, "operation": name, "kind": kind, "why": why,
                                                 "accounts": {}, "samples": {},
                                                 "blanked": sorted(k for k in op if SECRET_PARAM.search(str(k)))})
        if acct:
            rec["accounts"][acct] = status
            rec["samples"][acct] = blank_secrets(op)


def export(pd: str, projects, since_days: int = 30, gql: dict | None = None) -> tuple[list[dict], dict]:
    sc = S._scope.load(pd) if S._scope is not None else None
    domains = S.scope_domains(pd, S.load(pd)["config"].get("auth_hosts", []))
    since_ms = int((S.now() - since_days * 86400) * 1000)
    rows: dict[tuple, dict] = {}
    stats = {"read": 0, "oos": 0, "not_found": 0, "domains": domains, "attributed": 0}
    index, owners = S.vault_index(pd), token_owners(S.load(pd))
    for _name, pdir in projects:
        for (rid, ms, host, port, tls, method, path, query, status, rq, _rs) in S.iter_exchanges(pdir, domains, since_ms):
            stats["read"] += 1
            url = S._url(host, port, tls, path, query)
            if sc is not None and not sc.check(url).in_scope:
                stats["oos"] += 1
                continue
            if status == 404:
                stats["not_found"] += 1
                continue
            _sl, rqh, rqb = S.parse_http(bytes(rq))
            authed = any(k.lower() == "authorization" for k, _ in rqh) or \
                any(k.lower() == "cookie" and re.search(r"session|token|auth|sid", v, re.I) for k, v in rqh)
            key = (method, clean_url(url))
            rec = rows.get(key) or {"url": key[1], "method": method, "body_fields": [], "tags": ["caido"]}
            rec["status_code"] = status
            rec["body_fields"] = sorted(set(rec["body_fields"]) | set(body_fields(rqb, S.hget(rqh, "content-type"))))
            if authed and "authed-traffic" not in rec["tags"]:
                rec["tags"].append("authed-traffic")
            acct = account_of(rqh, index, owners) if authed else ""
            if acct:
                rec.setdefault("accounts", {})[acct] = status
                stats["attributed"] += 1
            if gql is not None and method == "POST" and G.is_graphql(url, rqb):
                graphql_records(url, rqb, status, acct, gql)
            rows[key] = rec
    return list(rows.values()), stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="caido-export.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--since-days", type=int, default=30)
    ap.add_argument("--caido-dir", default="")
    ap.add_argument("--caido-project", action="append")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    pd = os.path.abspath(os.path.expanduser(a.project_dir))
    if not os.path.isdir(pd):
        print(f"no such project dir {pd}", file=sys.stderr)
        return 2
    projects = S.caido_projects(a.caido_dir or S.caido_data_dir(), a.caido_project)
    if not projects:
        print("no Caido project found", file=sys.stderr)
        return 2
    gql: dict = {}
    recs, st = export(pd, projects, a.since_days, gql)
    if not st["domains"]:
        print("no scope domains: scope.md has no parseable host", file=sys.stderr)
        return 3
    authed = sum("authed-traffic" in r["tags"] for r in recs)
    if a.dry_run:
        print(f"{len(gql)} GraphQL operation(s) seen")
    print(f"read {st['read']} exchanges on {', '.join(st['domains'])}: {len(recs)} distinct requests "
          f"({authed} authenticated, {st['attributed']} exchanges attributed to an account), dropped "
          f"{st['oos']} out of scope and {st['not_found']} 404s")
    if a.dry_run:
        return 0
    os.makedirs(os.path.join(pd, "recon"), exist_ok=True)
    path = os.path.join(pd, "recon", OUT)
    with open(path, "w") as fh:
        for r in sorted(recs, key=lambda r: (r["url"], r["method"])):
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {path}; run huginn/scripts/corpus-build.py to merge it into asset-map.json")
    gpath = os.path.join(pd, "recon", GQL_OUT)
    S._write_private(gpath, "".join(json.dumps(r) + "\n" for r in sorted(gql.values(), key=lambda r: (r["url"], r["operation"]))))
    reads = sum(r["kind"] in ("query", "read-likely") for r in gql.values())
    print(f"wrote {gpath}: {len(gql)} GraphQL operation(s), {reads} read(s) (mode 600: bodies carry ids)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
