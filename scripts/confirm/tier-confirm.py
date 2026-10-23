#!/usr/bin/env python3
"""
tier-confirm.py — replay a privileged account's read as a lower-tier account (Grimnir confirmation
harness: function-level authorization, the tier differential).

A route only a privileged role ever calls (a moderator's queue, an admin's user list, an owner's
billing page) can still answer a lower role: the client hides the link, but the server never
checks. The test replays one of the high-tier account's organic reads, changing only who asks:

  high    the request as captured, with the high-tier account's credentials (positive control)
  low     the same request with the lower-tier account's credentials instead
  anon    the same request with no credentials (is the data public anyway?)
  scoped  the low request with the scope token (the subreddit, org, or project the high account
          administers) swapped for one that does not exist (optional), and the high request on
          that same nonexistent scope: does the privileged page carry the scope's data at all?

  tier-confirm.py --finding-id F --project-dir DIR --url 'https://x/mod/acme/queue' \
     -H 'Cookie: s=HIGH' --low-header 'Cookie: s=LOW' [--marker 'removal reason 7f3a'] \
     [--ident high_username --ident low_username] [--scope-token acme]

  GraphQL reads go as POST with the operation body. A body graphql_ops.py does not judge a read is
  refused. --csrf-field/--csrf-cookie name a double-submit token (a body field that must equal a
  cookie): each arm gets its own fresh value in both, so no arm carries another account's token.

  tier-confirm.py ... --method POST --url https://x/graphql --body '{"operation": "ModQueue", ...}' \
     --csrf-field csrf_token --csrf-cookie csrf_token

Markers are privileged data the high account can see: text only that role's view carries (a
moderation note, a banned user, a config value seeded for the test). A marker in the low response
is definitive, unless the anonymous response or the URL carries it too. Idents are both accounts'
own identifiers (names, ids): each page shows its viewer's, so they are blanked before comparing.

Verdict:
  confirmed    low 2xx carries a privileged marker that high carries and anon does not
  tier-likely  low 2xx matches high (identifiers blanked) while anon gets something else, and the
               page differs for a scope that does not exist
  negative     low denied (401/403/404, or a redirect where high got a 2xx), or low gets a
               different (restricted) view with no privileged marker, or low gets the same page
               as for a scope that does not exist while high does not, or every caller gets the
               same page (public)
  inconclusive high did not succeed, or the high tier's page is the same for a scope that does
               not exist (an app shell whose data loads from another request)

Derived markers: with a scope token, the tokens the high tier's page carries for the real scope and
not for one that does not exist (and that a second high request repeats and anon does not get) are
the scope's own data. A big page whose privileged section is a few kilobytes passes the similarity
bar against its nonexistent-scope twin; the derived markers still see the section. The low tier
carrying most of them is tier-likely, carrying almost none is negative. They are not proof of
privilege (a scope's public title is among them), so they never confirm: a seeded marker does.
"""
import argparse
import hashlib
import secrets
import importlib.util
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import _pace  # noqa: E402
import egress as _egress  # noqa: E402  the program's egress proxy (authz-confirm's fetch honors it)

_spec = importlib.util.spec_from_file_location("authz_confirm", os.path.join(_HERE, "authz-confirm.py"))
_az = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_az)
fetch, same = _az.fetch, _az.same
_spec = importlib.util.spec_from_file_location("authn_confirm", os.path.join(_HERE, "authn-confirm.py"))
_an = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_an)
strip_creds = _an.strip_creds
sys.path.insert(0, os.path.dirname(_HERE))
import graphql_ops as _gq  # noqa: E402


def ok(r):
    """A 2xx that is not a GraphQL error-only answer (GraphQL says "denied" with a 200)."""
    if not 200 <= r["status"] < 300:
        return False
    body = (r.get("body") or "").lstrip()
    if body.startswith("{") and '"errors"' in body[:4000]:
        try:
            doc = json.loads(body)
        except json.JSONDecodeError:
            return True
        if isinstance(doc, dict) and doc.get("errors") and not any((doc.get("data") or {}).values()):
            return False
    return True


def with_csrf(headers, body, field, cookie):
    """(headers, body) with one fresh double-submit token in the body field and the cookie."""
    if not (field and cookie and body):
        return headers, body
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        return headers, body
    if not isinstance(doc, dict):
        return headers, body
    tok = secrets.token_hex(16)
    doc[field] = tok
    out, done = [], False
    for h in headers:
        name, _, val = h.partition(":")
        if name.strip().lower() == "cookie":
            jar = [c for c in val.split(";") if c.strip() and c.strip().split("=", 1)[0] != cookie]
            out.append(f"Cookie: {'; '.join([c.strip() for c in jar] + [f'{cookie}={tok}'])}")
            done = True
        else:
            out.append(h)
    if not done:
        out.append(f"Cookie: {cookie}={tok}")
    return out, json.dumps(doc)


def denied(r):
    """401/403/404, or a redirect (to a login or an error page, in practice)."""
    return r["status"] in (401, 403, 404) or 300 <= r["status"] < 400


def blank(r, idents):
    """The arm with both accounts' identifiers blanked, so each viewer's own name in the page chrome
    does not make two otherwise identical pages differ."""
    body = r.get("body", "")
    for i in sorted((i for i in idents if i and len(i) >= 3), key=len, reverse=True):
        body = re.sub(re.escape(i), "\x00ACCT\x00", body, flags=re.I)
    b = body.encode("utf-8", "replace")
    return {**r, "body": body, "sha": hashlib.sha256(b).hexdigest()[:16], "id": ""}


MIN_DERIVED = 5       # fewer derived markers than this is noise, not the scope's data
CARRIES, MISSES = 0.5, 0.1


def tokens(r, idents=()):
    return {t for t in _az._SPLIT.split(_az.normalize(blank(r, idents)["body"])) if len(t) >= 4}


def derived_markers(high, high_scoped, anon, idents=(), high_again=None, scope_token=""):
    """Tokens of the high tier's page for this scope that its page for a nonexistent scope lacks,
    minus per-request noise (tokens a second identical high request does not repeat), anything the
    anonymous caller gets, and anything naming the scope itself (the low page echoes the URL)."""
    d = tokens(high, idents) - tokens(high_scoped, idents)
    if high_again is not None and ok(high_again):
        d &= tokens(high_again, idents)
    if ok(anon):
        d -= tokens(anon, idents)
    if scope_token:
        d = {t for t in d if scope_token.lower() not in t.lower()}
    return d


def classify(high, low, anon, url, markers=(), idents=(), scoped=None, high_scoped=None,
             high_again=None, scope_token=""):
    """(verdict, why, notes). Pure: each arm is a fetch() dict; scoped, high_scoped (the high tier
    on a scope that does not exist), and high_again (the high request repeated) may be None."""
    if not ok(high):
        return "inconclusive", f"positive control failed: high returned {high['status']}", {}
    if not ok(low):
        if denied(low):
            return "negative", f"low tier denied ({low['status']})", {}
        return "negative", f"low tier got {low['status']}", {}
    usable = [m for m in markers if m and len(m) >= 4 and m not in url and m in high["body"]]
    hit = [m for m in usable if m in low["body"] and not (ok(anon) and m in anon["body"])]
    if hit:
        return "confirmed", f"low tier {low['status']} carries {len(hit)} privileged marker(s) of the high tier's view", \
            {"low_markers": len(hit), "markers_checked": len(usable)}
    notes = {"markers_checked": len(usable)}
    h, lo, an = blank(high, idents), blank(low, idents), blank(anon, idents)
    if high_scoped is not None and ok(high_scoped):
        d = derived_markers(high, high_scoped, anon, idents, high_again, scope_token)
        if len(d) >= MIN_DERIVED:
            got = len(d & tokens(low, idents)) / len(d)
            notes.update(derived_markers=len(d), low_carries=round(got, 2))
            if got >= CARRIES:
                return "tier-likely", (f"low tier carries {got:.0%} of the {len(d)} tokens the high tier's page "
                                       "holds for this scope and not for a nonexistent one; seed a privileged "
                                       "marker to confirm"), notes
            if got <= MISSES:
                return "negative", (f"low tier carries {got:.0%} of the {len(d)} tokens the high tier's page "
                                    "holds for this scope and not for a nonexistent one"), notes
            return "inconclusive", (f"low tier carries {got:.0%} of the {len(d)} scope-specific tokens of the "
                                    "high tier's page: neither its view nor the generic one"), notes
    if high_scoped is not None and ok(high_scoped) and same(blank(high_scoped, idents), h):
        # The privileged page itself carries nothing of the scope: its data comes from another
        # request this replay does not make, so neither a match nor a difference means anything.
        return "inconclusive", ("the high tier's page is the same for a scope that does not exist: an app "
                                "shell whose data loads from another request"), notes
    if not same(lo, h):
        why = "low tier gets a different view"
        why += " without any of the privileged markers" if usable else " (no privileged markers to check)"
        return "negative", why, notes
    if ok(anon) and same(an, h):
        return "negative", "every caller gets the same page, anonymous included (public)", notes
    if scoped is not None and ok(scoped) and same(blank(scoped, idents), lo):
        sc = blank(scoped, idents)
        if _az.normalize(sc["body"]) == _az.normalize(h["body"]):
            return "inconclusive", ("the page is the same for a scope that does not exist: an app shell whose "
                                    "data loads from another request"), notes
        # A large page with a small privileged section passes the similarity bar; the scope that does
        # not exist shows what the low tier really got: the generic view, not the high tier's.
        return "negative", "low tier gets what it gets for a scope that does not exist, not the high tier's view", notes
    return "tier-likely", ("low tier gets the high tier's page while anonymous does not; add a privileged "
                           "marker to confirm"), notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True)
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--low-header", action="append", default=[])
    ap.add_argument("--marker", action="append", default=[])
    ap.add_argument("--ident", action="append", default=[])
    ap.add_argument("--scope-token", default="")
    ap.add_argument("--body", default=None)
    ap.add_argument("--csrf-field", default="")
    ap.add_argument("--csrf-cookie", default="")
    a = ap.parse_args()
    m = a.method.upper()
    if m not in ("GET", "HEAD") and not (m == "POST" and a.body and _gq.is_graphql(a.url, a.body) and _gq.is_read(a.body)):
        why = _gq.classify(a.body or "")[1] if m == "POST" else f"{m} is not a read"
        print(f"tier-confirm replays reads only (GET/HEAD, or a GraphQL read over POST): {why}", file=sys.stderr)
        sys.exit(2)
    if not a.low_header:
        print("no --low-header: the low tier arm needs the lower-tier account's credentials", file=sys.stderr)
        sys.exit(2)
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env
    base = strip_creds(a.headers)

    def go(url, headers, body):
        h, b = with_csrf(headers, body, a.csrf_field, a.csrf_cookie)
        return fetch(a.method, url, h, b)

    high = go(a.url, a.headers, a.body)
    low = go(a.url, base + a.low_header, a.body)
    anon = go(a.url, base, a.body)
    scoped = high_scoped = high_again = None
    tok = a.scope_token
    if tok and len(tok) >= 3 and (tok in a.url or tok in (a.body or "")) and ok(low):
        fake = f"zz{uuid.uuid4().hex[:10]}"
        furl, fbody = a.url.replace(tok, fake), (a.body.replace(tok, fake) if a.body else a.body)
        scoped = go(furl, base + a.low_header, fbody)
        if ok(high):
            high_scoped = go(furl, a.headers, fbody)
            high_again = go(a.url, a.headers, a.body)
    verdict, why, notes = classify(high, low, anon, a.url + " " + (a.body or ""), a.marker, a.ident, scoped,
                                   high_scoped, high_again, tok)

    arms = {"high": high, "low": low, "anon": anon, **({"scoped": scoped} if scoped else {}),
            **({"high_scoped": high_scoped} if high_scoped else {}),
            **({"high_again": high_again} if high_again else {})}
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "tier", "verdict": verdict, "why": why,
           "ts": datetime.now(timezone.utc).isoformat(), "method": a.method.upper(), "url": a.url,
           "differential": {k: {kk: v[kk] for kk in ("status", "len", "sha", "snip")} for k, v in arms.items()},
           **notes,
           "negative_control": f"tier differential (high/low/anon{'/scoped' if scoped else ''}): {why}"}
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "tier.json"), "w") as fh:
        json.dump(rec, fh, indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/tier.json")


if __name__ == "__main__":
    main()
