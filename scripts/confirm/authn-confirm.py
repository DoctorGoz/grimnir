#!/usr/bin/env python3
"""
authn-confirm.py — replay one of our own authenticated requests without its credentials, and with
the second account's (Grimnir confirmation harness).

A route the client only ever calls with a session can still answer without one: the handler
forgot the check, or a gateway in front of it only guards some paths. The test is a replay of an
organic request, changing only who is asking:

  own     the request as captured, with the owning account's credentials (positive control)
  anon    the same request with every credential header removed
  other   the same request with the second account's credentials instead (optional)

  authn-confirm.py --finding-id F --project-dir DIR --url 'https://api.x/v1/me/settings' \
     -H 'Authorization: Bearer OWN' [--other-header 'Authorization: Bearer OTHER'] \
     [--private-marker 'a1@example.com'] [--marker 't2_abc123'] [--own-id a2_xyz]

Markers are the owning account's identifiers. A private marker (email, phone) is data no stranger
should get, so one in the anonymous response is definitive; a public one (user id, handle) only
makes it likely. A marker that is part of the URL proves nothing and is ignored.

Verdict:
  confirmed     anon 2xx carries a private marker the own response carries (missing authentication),
                or other 2xx carries one on a request that names the owner's object (--own-id in
                the URL: cross-account access)
  authn-likely  anon 2xx carries a public marker, or anon matches own while other differs
                (the response is per-account and the anonymous caller got the owner's version)
  negative      anon denied (401/403, or a redirect where own got a 2xx), or anon gets a different
                response with none of the owner's data, or every caller gets the same response
  inconclusive  own did not succeed, or own and anon match with nothing marking the data as
                the owner's and no second account to tell, or anon got a 403 and so did an
                anonymous request for the host root (a wall in front of everything, not the check)
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import _pace  # noqa: E402
import egress as _egress  # noqa: E402  the program's egress proxy (authz-confirm's fetch honors it)

_spec = importlib.util.spec_from_file_location("authz_confirm", os.path.join(_HERE, "authz-confirm.py"))
_az = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_az)
fetch, same = _az.fetch, _az.same

# Header names that carry identity. Everything else (User-Agent, Accept, RoE headers) stays.
CRED_HEADER = re.compile(r"^(authorization|proxy-authorization|cookie|x-api-key|api-key|x-auth[\w-]*|"
                         r"[\w-]*api-?key|[\w-]*-auth|[\w-]*(token|session|csrf|xsrf|jwt|bearer)[\w-]*)$", re.I)


def strip_creds(headers):
    return [h for h in headers if not CRED_HEADER.match(h.split(":", 1)[0].strip())]


def ok(r):
    return 200 <= r["status"] < 300


def denied(r):
    """401/403, or a redirect (to a login page, in practice) where the owner got a 2xx."""
    return r["status"] in (401, 403) or 300 <= r["status"] < 400


def carried(markers, resp, own, url):
    """Markers in both the own response and this one, excluding any the URL itself carries."""
    return [m for m in markers if m and len(m) >= 4 and m not in url and m in own["body"] and m in resp["body"]]


def classify(own, anon, other, url, private=(), public=(), own_ids=(), root=None):
    """(verdict, why, notes). Pure: each arm is a fetch() dict; other and root may be None. root is
    the anonymous host-root control, fetched only when anon got a 403."""
    if not ok(own):
        return "inconclusive", f"positive control failed: own returned {own['status']}", {}
    notes = {}
    names_owner = [i for i in own_ids if i and len(i) >= 3 and i in url]
    if other is not None and ok(other) and names_owner:
        hit = carried(private, other, own, url)
        if hit:
            return "confirmed", (f"the second account read the owner's object ({names_owner[0]}) and its "
                                 f"private data ({len(hit)} marker(s))"), {"cross_markers": len(hit)}
    if ok(anon):
        hit = carried(private, anon, own, url)
        if hit:
            return "confirmed", f"anonymous {anon['status']} carries {len(hit)} private marker(s) of the owner", \
                {"anon_markers": len(hit)}
        pub = carried(public, anon, own, url)
        if pub:
            return "authn-likely", (f"anonymous {anon['status']} carries {len(pub)} identifier(s) of the owner; "
                                    f"check whether the data is meant to be public"), {"anon_public_markers": len(pub)}
        if same(anon, own):
            if other is not None and ok(other):
                if same(other, own):
                    return "negative", "every caller gets the same response (public content)", notes
                return "authn-likely", ("anonymous gets the owner's response while the second account gets a "
                                        "different one: the response is per-account"), notes
            if names_owner and other is not None and denied(other):
                return "authn-likely", ("anonymous gets the owner's response for the owner's object, which the "
                                        "second account is denied"), notes
            return "inconclusive", ("own and anonymous match, but nothing marks the data as the owner's; add "
                                    "markers or a second account"), notes
        return "negative", f"anonymous {anon['status']} differs from own and carries none of the owner's data", notes
    if anon["status"] == 403 and root is not None and root["status"] == 403:
        # A bot wall or WAF that refuses anonymous clients outright answers 403 for public pages
        # too, so this 403 is not the route's auth check (hunting Rule 27: a confounded negative).
        return "inconclusive", "anonymous clients are walled on this host (the root is 403 too)", notes
    if denied(anon):
        return "negative", f"anonymous denied ({anon['status']})", notes
    return "negative", f"anonymous returned {anon['status']}", notes


WALLS = "authn-walls.json"   # evidence/: {host: date} hosts that refuse anonymous clients today


def _walls(project_dir):
    try:
        with open(os.path.join(project_dir, "evidence", WALLS)) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _mark_wall(project_dir, host, day):
    w = {h: d for h, d in _walls(project_dir).items() if d == day}
    w[host] = day
    os.makedirs(os.path.join(project_dir, "evidence"), exist_ok=True)
    with open(os.path.join(project_dir, "evidence", WALLS), "w") as fh:
        json.dump(w, fh)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True)
    ap.add_argument("--body", default=None)
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--other-header", action="append", default=[])
    ap.add_argument("--private-marker", action="append", default=[])
    ap.add_argument("--marker", action="append", default=[])
    ap.add_argument("--own-id", action="append", default=[])
    a = ap.parse_args()
    if a.method.upper() not in ("GET", "HEAD"):
        print("authn-confirm replays reads only (GET/HEAD); a write replay needs the operator", file=sys.stderr)
        sys.exit(2)
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env
    if strip_creds(a.headers) == a.headers:
        print("no credential header to remove: the own arm is already anonymous", file=sys.stderr)
        sys.exit(2)

    base = strip_creds(a.headers)
    host, day = (urlsplit(a.url).hostname or "").lower(), datetime.now(timezone.utc).date().isoformat()
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    if _walls(a.project_dir).get(host) == day:
        # Already seen today: every anonymous request here is refused, so spend nothing.
        rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "authn", "verdict": "inconclusive",
               "why": f"anonymous clients are walled on {host} today (seen on an earlier lane); no requests sent",
               "ts": datetime.now(timezone.utc).isoformat(), "method": a.method.upper(), "url": a.url}
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "authn.json"), "w") as fh:
            json.dump(rec, fh, indent=2)
        print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
        return
    own = fetch(a.method, a.url, a.headers, a.body)
    anon = fetch(a.method, a.url, base, a.body)
    other = fetch(a.method, a.url, base + a.other_header, a.body) if a.other_header else None
    root = None
    if anon["status"] == 403:
        p = urlsplit(a.url)
        root = fetch("GET", urlunsplit((p.scheme, p.netloc, "/", "", "")), base)
    verdict, why, notes = classify(own, anon, other, a.url, a.private_marker, a.marker, a.own_id, root)
    if root is not None and root["status"] == 403:
        _mark_wall(a.project_dir, host, day)

    arms = {"own": own, "anon": anon, **({"other": other} if other else {}), **({"root": root} if root else {})}
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "authn", "verdict": verdict, "why": why,
           "ts": datetime.now(timezone.utc).isoformat(), "method": a.method.upper(), "url": a.url,
           "removed_headers": sorted({h.split(":", 1)[0].strip() for h in a.headers} -
                                     {h.split(":", 1)[0].strip() for h in base}),
           "differential": {k: {kk: v[kk] for kk in ("status", "len", "sha", "snip")} for k, v in arms.items()},
           **notes,
           "negative_control": f"credential-stripped replay (own/anon{'/other' if other else ''}): {why}"}
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "authn.json"), "w") as fh:
        json.dump(rec, fh, indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/authn.json")


if __name__ == "__main__":
    main()
