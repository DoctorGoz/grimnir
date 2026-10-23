#!/usr/bin/env python3
"""graphql-probe.py — introspection-OFF schema recovery via the field-suggestion error oracle.

When a GraphQL server disables introspection, most implementations (graphql-js / Apollo, and any
engine that keeps "Did you mean ...?" validation hints on) still leak the schema through error
messages:

  - an INVALID field yields `Cannot query field "x" on type "T". Did you mean "a", "b", or "c"?`
    — "T" is the type the field was asked on, and a/b/c are REAL neighbouring field names;
  - a REAL object field asked WITHOUT a subselection yields
    `Field "user" of type "User" must have a selection of subfields.` — revealing its return type;
  - a REAL scalar asked WITH a subselection yields `... must not have a selection since type ...`;
  - a field with a required argument yields `Field "f" argument "id" of type "ID!" is required ...`.

This reconstructs a partial schema from those errors — our own bounded, paced, deterministic
replacement for clairvoyance (unmaintained, and it pollutes a shared venv). Zero LLM.

SAFETY — read-only by construction:
  * Every probe is a `query` (or, only with --mutations, a deliberately MANGLED mutation field that
    cannot resolve). We never send a valid mutation, so nothing is written on the target.
  * Bounded by --max-requests and --depth; paced by --delay between requests to honour per-program
    RoE / rate limits. A miss never guesses — it records what the errors actually said.

Output: <out>/schema.json  (default reports/raw/graphql-probe-<ts>/), plus a printed summary.
The recovered schema.json feeds the graphql-audit skill and the authz / infoleak confirm lanes the
same way an introspection dump would.

  graphql-probe.py https://host/graphql [--token T] [-H 'X: y']* [--wordlist FILE] \
     [--max-requests 300] [--depth 2] [--delay 0.2] [--mutations] [--out DIR] [--json]
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# Where this engagement's target traffic leaves the host: the program's egress proxy, fail closed.
# Same contract as scripts/params.py — every probe rides the proxy or the run refuses, never direct.
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.path.join(_REPO, "scripts") not in sys.path:
    sys.path.insert(0, os.path.join(_REPO, "scripts"))
import egress as _egress  # noqa: E402

# ── the error-message oracle (pure, deterministic) ─────────────────────────────
# graphql-js / Apollo canonical phrasings. Kept tolerant (no trailing anchors) so a
# minor engine reword still matches the load-bearing capture groups.
_RE_UNKNOWN_FIELD = re.compile(r'Cannot query field "(?P<field>[^"]+)" on type "(?P<type>[^"]+)"')
_RE_NEEDS_SUBFIELDS = re.compile(
    r'Field "(?P<field>[^"]+)" of type "(?P<type>[^"]+)" must have a selection of subfields')
_RE_NO_SUBSELECTION = re.compile(
    r'Field "(?P<field>[^"]+)" must not have a selection since type "(?P<type>[^"]+)" has no subfields')
_RE_REQUIRED_ARG = re.compile(
    r'Field "(?P<field>[^"]+)" argument "(?P<arg>[^"]+)" of type "(?P<argtype>[^"]+)" is required')
_RE_DIDYOUMEAN = re.compile(r'Did you mean (?P<body>[^?]+)\?')
_NAME_RE = re.compile(r'^[_A-Za-z][_0-9A-Za-z]*$')
_QUOTED = re.compile(r'"([^"]+)"')

# builtin root-verb seeds appended to the wordlist — the names a nouns-only wordlist misses.
_ROOT_SEEDS = ["node", "nodes", "me", "viewer", "search", "query", "get", "list", "current",
               "account", "self", "profile", "search", "feed", "connection", "edges"]


def extract_suggestions(message: str) -> tuple[list[str], bool]:
    """(names, is_type) from a 'Did you mean ...?' clause. is_type is True for the union/interface
    'Did you mean to use an inline fragment on ...' form (the quoted tokens are TYPE names, not
    fields). Tokens that are not bare GraphQL names (e.g. `x { ... }` in a subfield hint) are
    dropped, so only usable identifiers survive."""
    m = _RE_DIDYOUMEAN.search(message or "")
    if not m:
        return [], False
    is_type = "inline fragment" in message
    names = [t for t in _QUOTED.findall(m.group("body")) if _NAME_RE.match(t)]
    # dedup preserving order
    return list(dict.fromkeys(names)), is_type


def classify_field_probe(messages: list[str], field: str) -> dict:
    """Interpret the errors from probing a single `field`. Pure — no I/O.

    exists is False ONLY when the server said 'Cannot query field "<field>"'. Any other outcome
    (a subfields/scalar/required-arg error, a runtime/auth error, or a clean data return) means the
    field passed field-existence validation, so it EXISTS. Suggestions are harvested from every
    message (a probe may surface neighbours regardless of which rule fired)."""
    unknown = False
    container_type = None       # the type <field> was asked on (parent) — names the root/child type
    ret_type = None             # <field>'s own return type, when revealed
    kind = None
    required_args: list[str] = []
    field_suggestions: list[str] = []
    type_suggestions: list[str] = []

    for msg in messages:
        mu = _RE_UNKNOWN_FIELD.search(msg)
        if mu and mu.group("field") == field:
            unknown = True
            container_type = container_type or mu.group("type")
        ms = _RE_NEEDS_SUBFIELDS.search(msg)
        if ms and ms.group("field") == field:
            ret_type, kind = ms.group("type"), "object"
        mn = _RE_NO_SUBSELECTION.search(msg)
        if mn and mn.group("field") == field:
            ret_type, kind = mn.group("type"), "scalar"
        ma = _RE_REQUIRED_ARG.search(msg)
        if ma and ma.group("field") == field:
            required_args.append(ma.group("arg"))
        names, is_type = extract_suggestions(msg)
        (type_suggestions if is_type else field_suggestions).extend(names)

    return {
        "field": field,
        "exists": not unknown,
        "container_type": container_type,
        "type": ret_type,
        "kind": kind,
        "required_args": list(dict.fromkeys(required_args)),
        "field_suggestions": list(dict.fromkeys(field_suggestions)),
        "type_suggestions": list(dict.fromkeys(type_suggestions)),
    }


def strip_type(t: str | None) -> str | None:
    """`[User!]!` -> `User`: drop list/non-null wrappers to the bare type name."""
    if not t:
        return None
    return re.sub(r'[\[\]!]', '', t).strip() or None


def build_query(op: str, path: list[str], leaf: str) -> str:
    """Nest `leaf` under each parent in `path`. op='query' -> '{ a { b { leaf } } }';
    op='mutation' -> 'mutation { leaf }' (path is always empty for mutation probes)."""
    inner = leaf
    for p in reversed(path):
        inner = f"{p} {{ {inner} }}"
    return f"mutation {{ {inner} }}" if op == "mutation" else f"{{ {inner} }}"


def _mangle(name: str) -> str:
    """A near-miss of `name`: invalid (so it can never resolve/execute) but close enough that the
    suggestion engine still surfaces the real neighbour. Used for read-only mutation harvesting."""
    return name + "_zzq"


# ── transport (injectable so the whole session is unit-testable offline) ────────
def http_post(endpoint: str, headers: list[str], timeout: int = 20):
    # Build the opener once: it rides the program's egress proxy when one is configured. An unusable
    # proxy raises EgressError here (caught in main) so the run refuses rather than probing direct.
    opener = _egress.opener(proxy=_egress.proxy())

    def _fn(query: str) -> dict:
        data = json.dumps({"query": query}).encode()
        req = urllib.request.Request(endpoint, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for h in headers:
            k, _, v = h.partition(":")
            if k.strip():
                req.add_header(k.strip(), v.strip())
        try:
            with opener.open(req, timeout=timeout) as r:
                body, status = r.read().decode("utf-8", "replace"), r.status
        except urllib.error.HTTPError as e:          # 400 validation errors carry the useful body
            body, status = e.read().decode("utf-8", "replace"), e.code
        except Exception as e:
            return {"status": 0, "json": None, "text": "", "err": str(e)}
        try:
            j = json.loads(body)
        except Exception:
            j = None
        return {"status": status, "json": j, "text": body}
    return _fn


def messages_of(resp: dict) -> list[str]:
    j = resp.get("json")
    if not isinstance(j, dict):
        return []
    return [str(e.get("message", "")) for e in (j.get("errors") or []) if isinstance(e, dict)]


class Budget:
    def __init__(self, maximum: int):
        self.max, self.used = maximum, 0

    def left(self) -> int:
        return self.max - self.used

    def spend(self) -> None:
        self.used += 1


# ── enumeration ────────────────────────────────────────────────────────────────
def enumerate_on_path(post_fn, op: str, path: list[str], seeds: list[str], budget: Budget,
                      delay: float, *, execute_real: bool) -> tuple[str | None, dict]:
    """BFS-enumerate the fields of the type reached by `path` (empty = the op's root type).
    Returns (container_type_name, {field_name: record}). Suggestions harvested from misses feed
    back into the queue, so a decent wordlist bootstraps the full field set."""
    container = None
    found: dict[str, dict] = {}
    seen: set[str] = set()
    queue = list(dict.fromkeys(seeds))
    while queue and budget.left() > 0:
        cand = queue.pop(0)
        if cand in seen:
            continue
        seen.add(cand)
        probe = cand if execute_real else _mangle(cand)
        resp = post_fn(build_query(op, path, probe))
        budget.spend()
        if delay > 0 and budget.left() > 0:
            time.sleep(delay)
        info = classify_field_probe(messages_of(resp), probe)
        if info["container_type"] and not container:
            container = info["container_type"]
        for s in info["field_suggestions"]:
            if s not in seen:
                queue.append(s)
        if execute_real and info["exists"]:
            found[cand] = {"name": cand, "type": strip_type(info["type"]),
                           "kind": info["kind"], "required_args": info["required_args"]}
        elif not execute_real:
            # mutation harvest: real names appear ONLY as suggestions (we never execute one)
            for s in info["field_suggestions"]:
                found.setdefault(s, {"name": s, "type": None, "kind": None, "required_args": []})
    return container, found


def parse_introspection(schema_json: dict) -> dict:
    """Light introspection -> {TypeName: {fields:[{name,type,kind}]}} so schema.json has one shape
    whether it came from the oracle or a live __schema dump."""
    types: dict[str, dict] = {}
    for t in (((schema_json.get("data") or {}).get("__schema") or {}).get("types") or []):
        if not t.get("name") or t["name"].startswith("__"):
            continue
        fields = []
        for f in (t.get("fields") or []):
            ft = f.get("type") or {}
            # unwrap NON_NULL/LIST ofType chain to the named type
            while ft and not ft.get("name") and ft.get("ofType"):
                ft = ft["ofType"]
            fields.append({"name": f.get("name"), "type": ft.get("name"),
                           "kind": (ft.get("kind") or "").lower() or None,
                           "required_args": [a["name"] for a in (f.get("args") or [])
                                             if (a.get("type") or {}).get("kind") == "NON_NULL"]})
        if fields:
            types[t["name"]] = {"fields": fields}
    return types


INTROSPECTION_QUERY = ('{ __schema { types { name kind fields { name args { name type { kind } } '
                       'type { kind name ofType { kind name ofType { kind name ofType { name } } } } } } } }')


def load_wordlist(path: str | None) -> list[str]:
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wordlists", "graphql-fields.txt")
    p = path or default
    words: list[str] = []
    try:
        with open(p) as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#") and _NAME_RE.match(w):
                    words.append(w)
    except OSError:
        pass
    return words


def run(endpoint: str, headers: list[str], *, wordlist: list[str], max_requests: int, depth: int,
        delay: float, mutations: bool, post_fn=None) -> dict:
    """Full probe: confirm GraphQL, check introspection, then reconstruct the schema (introspection
    dump if enabled, else the error oracle). Returns the schema record."""
    post = post_fn or http_post(endpoint, headers)
    budget = Budget(max_requests)
    notes: list[str] = []
    rec = {"schema": 1, "endpoint": endpoint, "ts": datetime.now(timezone.utc).isoformat(),
           "introspection": "unknown", "root_types": {"query": None, "mutation": None},
           "types": {}, "stats": {}, "notes": notes}

    # 1) confirm it's GraphQL
    resp = post("{ __typename }")
    budget.spend()
    if not (isinstance(resp.get("json"), dict) and (resp["json"].get("data") or
            any("__typename" in m or "Cannot query" in m for m in messages_of(resp)))):
        rec["introspection"] = "not-graphql"
        notes.append("endpoint did not answer a __typename query as GraphQL")
        rec["stats"] = {"requests": budget.used}
        return rec

    # 2) introspection on?
    intro = post(INTROSPECTION_QUERY)
    budget.spend()
    ij = intro.get("json") or {}
    if isinstance(ij, dict) and ((ij.get("data") or {}).get("__schema")):
        rec["introspection"] = "enabled"
        rec["types"] = parse_introspection(ij)
        notes.append("introspection ENABLED — schema parsed directly (oracle not needed)")
        rec["stats"] = {"requests": budget.used, "types_found": len(rec["types"]),
                        "fields_found": sum(len(t["fields"]) for t in rec["types"].values())}
        return rec

    # 3) introspection off -> the error oracle
    rec["introspection"] = "disabled"
    seeds = list(dict.fromkeys(wordlist + _ROOT_SEEDS))
    q_container, q_fields = enumerate_on_path(post, "query", [], seeds, budget, delay, execute_real=True)
    q_container = q_container or "Query"
    rec["root_types"]["query"] = q_container
    types: dict[str, dict] = {q_container: {"fields": list(q_fields.values())}}

    # 4) one level of descent per --depth into no-required-args object fields
    if depth >= 2:
        for f in list(q_fields.values()):
            if budget.left() <= 0:
                break
            if f["kind"] == "object" and not f["required_args"]:
                child_container, child_fields = enumerate_on_path(
                    post, "query", [f["name"]], seeds, budget, delay, execute_real=True)
                tname = f["type"] or child_container
                if tname and child_fields:
                    existing = types.setdefault(tname, {"fields": []})
                    have = {x["name"] for x in existing["fields"]}
                    existing["fields"].extend(v for k, v in child_fields.items() if k not in have)
            if depth < 2:
                break

    # 5) optional read-only mutation-root harvest
    if mutations and budget.left() > 0:
        m_container, m_fields = enumerate_on_path(post, "mutation", [], seeds, budget, delay, execute_real=False)
        rec["root_types"]["mutation"] = m_container or "Mutation"
        if m_fields:
            types[rec["root_types"]["mutation"]] = {"fields": list(m_fields.values())}
            notes.append("mutation names harvested read-only from suggestions (types not resolved — never executed)")

    rec["types"] = types
    rec["stats"] = {"requests": budget.used, "types_found": len(types),
                    "fields_found": sum(len(t["fields"]) for t in types.values())}
    if budget.left() <= 0:
        notes.append(f"request budget ({max_requests}) exhausted — schema may be partial")
    return rec


# ── selftest (offline; drives the pure oracle against canned graphql-js errors) ──
def selftest() -> int:
    ok = True

    def check(label, cond):
        nonlocal ok
        print(("  ok   " if cond else "  FAIL ") + label)
        ok = ok and cond

    i = classify_field_probe(
        ['Cannot query field "usr" on type "Query". Did you mean "user", "users", or "viewer"?'], "usr")
    check("unknown field -> exists False, container Query, 3 suggestions",
          i["exists"] is False and i["container_type"] == "Query"
          and i["field_suggestions"] == ["user", "users", "viewer"])

    i = classify_field_probe(['Field "user" of type "User" must have a selection of subfields.'], "user")
    check("object field -> exists True, type User, kind object",
          i["exists"] and i["type"] == "User" and i["kind"] == "object")

    i = classify_field_probe(
        ['Field "email" must not have a selection since type "String" has no subfields.'], "email")
    check("scalar field -> exists True, kind scalar", i["exists"] and i["kind"] == "scalar")

    i = classify_field_probe(
        ['Field "user" argument "id" of type "ID!" is required, but it was not provided.'], "user")
    check("required arg captured, field exists", i["exists"] and i["required_args"] == ["id"])

    names, is_type = extract_suggestions(
        'Cannot query field "x" on type "Node". Did you mean to use an inline fragment on "User" or "Org"?')
    check("inline-fragment suggestions flagged as types", is_type and names == ["User", "Org"])

    names, _ = extract_suggestions('Field "u" of type "User" must have a selection of subfields. '
                                   'Did you mean "u { ... }"?')
    check("subfield hint yields no bogus field name", names == [])

    check("strip_type unwraps list/non-null", strip_type("[User!]!") == "User")
    check("build_query nests path", build_query("query", ["me"], "email") == "{ me { email } }")

    # a scripted end-to-end reconstruction against a fake introspection-off server
    schema = {"Query": {"user": ["email", "role"], "viewer": []}, "User": {"email": None, "role": None}}

    def fake(query: str) -> dict:
        q = query.replace(" ", "")
        if "__typename" in q:
            return {"status": 200, "json": {"data": {"__typename": "Query"}}}
        if "__schema" in q:
            return {"status": 200, "json": {"errors": [{"message": "GraphQL introspection is not allowed"}]}}
        # innermost {leaf}: find the deepest single token
        m = re.findall(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', q)
        leaf = m[-1] if m else ""
        parent = None
        pm = re.findall(r'([A-Za-z_][A-Za-z0-9_]*)\{', q)
        if pm:
            parent = pm[-1]
        container = "Query"
        fields = schema["Query"]
        if parent == "user":
            container, fields = "User", schema["User"]
        if leaf in fields:
            if fields[leaf]:      # object with children -> needs subfields
                return {"status": 400, "json": {"errors": [
                    {"message": f'Field "{leaf}" of type "User" must have a selection of subfields.'}]}}
            return {"status": 400, "json": {"errors": [
                {"message": f'Field "{leaf}" must not have a selection since type "String" has no subfields.'}]}}
        near = ", ".join(f'"{k}"' for k in fields)
        return {"status": 400, "json": {"errors": [
            {"message": f'Cannot query field "{leaf}" on type "{container}". Did you mean {near}?'}]}}

    r = run("http://fake/graphql", [], wordlist=["user", "viewer", "zzz"], max_requests=100,
            depth=2, delay=0, mutations=False, post_fn=fake)
    qf = {f["name"] for f in r["types"].get("Query", {}).get("fields", [])}
    uf = {f["name"] for f in r["types"].get("User", {}).get("fields", [])}
    check("reconstructs Query fields (user, viewer)", {"user", "viewer"} <= qf)
    check("descends into User (email, role)", {"email", "role"} <= uf)
    check("introspection reported disabled", r["introspection"] == "disabled")

    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="graphql-probe.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("endpoint", nargs="?", help="GraphQL endpoint URL")
    ap.add_argument("--token", help="bearer token (added as Authorization: Bearer <token>)")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--wordlist", help="field wordlist (default specter/wordlists/graphql-fields.txt)")
    ap.add_argument("--max-requests", type=int, default=300)
    ap.add_argument("--depth", type=int, default=2, help="1=root fields only, 2=+one level of descent")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests (RoE pacing)")
    ap.add_argument("--mutations", action="store_true", help="also harvest mutation names (read-only)")
    ap.add_argument("--out", help="output dir (default reports/raw/graphql-probe-<ts>)")
    ap.add_argument("--json", action="store_true", help="print the schema JSON to stdout")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()
    if not a.endpoint:
        ap.error("endpoint is required (or use --selftest)")

    headers = list(a.headers)
    if a.token:
        headers.append(f"Authorization: Bearer {a.token}")

    try:
        rec = run(a.endpoint, headers, wordlist=load_wordlist(a.wordlist), max_requests=a.max_requests,
                  depth=a.depth, delay=a.delay, mutations=a.mutations)
    except _egress.EgressError as e:
        print(f"graphql-probe.py: refusing to run — {e}", file=sys.stderr)
        return 4

    out = a.out or os.path.join("reports", "raw", "graphql-probe-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "schema.json")
    with open(path, "w") as fh:
        json.dump(rec, fh, indent=2)

    st = rec["stats"]
    print(f"===== GraphQL probe: {a.endpoint} =====")
    print(f"  introspection: {rec['introspection']}")
    if rec["introspection"] == "disabled":
        print(f"  root query type: {rec['root_types']['query']}")
    print(f"  types: {st.get('types_found', 0)}  fields: {st.get('fields_found', 0)}  "
          f"requests: {st.get('requests', 0)}")
    for n in rec["notes"]:
        print(f"  note: {n}")
    print(f"  wrote {path}")
    if a.json:
        print(json.dumps(rec, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
