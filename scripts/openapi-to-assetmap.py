#!/usr/bin/env python3
"""
OpenAPI -> asset-map.endpoints[]  (corpus auto-population for API targets)
=========================================================================
The authed-corpus chain fires off `asset-map.endpoints[]`. For a cookie-web
target `authed-crawl.py` fills that array by driving a browser. For an API target
the operator usually has something better than a crawl: a published OpenAPI /
Swagger spec that enumerates EVERY operation, including the ones organic traffic
never exercises (`/export`, `/raw_sign`, admin-only org routes) -- exactly the
"endpoints others miss" edge. This converts such a spec into the SAME
`endpoints[]` records `authed-crawl` emits, so the identical downstream chain
runs with zero further change.

WHAT IT EMITS  (one record per operation, mirroring request_to_endpoint):
    {url, method, source:"openapi", auth_required, tags[],
     parameters[]  (QUERY param names only -- path ids live in the url template),
     body_fields[] (top-level request-body property NAMES only)}
Names only, never example values -- consistent with the masked-corpus decision
(downstream analysis masks before anything reaches a model; this never even reads
values). Path templates keep their native placeholders (`/v1/wallets/{wallet_id}`);
lane synthesis's placeholder regex already treats `{...}` as a definite id position
and normalizes it to `{id}`, so an OpenAPI template and a crawled concrete url
converge on the same lane.

SAFE + DETERMINISTIC: pure parsing, no network beyond optionally fetching the
spec url, no LLM. `--selftest` runs the pure oracles.

USAGE
    # from a local file or a url, merged into the engagement asset-map:
    openapi-to-assetmap.py --spec openapi.json --project-dir "$PROJECT_DIR"
    openapi-to-assetmap.py --spec https://host/api/v1/openapi.json --project-dir DIR
    openapi-to-assetmap.py --spec spec.json --project-dir DIR --json   # summary
    openapi-to-assetmap.py --spec spec.json --dry-run                  # print, no write
    openapi-to-assetmap.py --selftest
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from urllib.parse import urlparse, parse_qsl

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import egress as _egress  # noqa: E402 — the program's egress proxy: a remote --spec fetch rides it or refuses

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_MAX_REF_DEPTH = 8


# ── $ref / schema resolution (local refs only, bounded) ─────────────────────────
def resolve_ref(spec: dict, ref: str) -> dict:
    """Resolve a local '#/a/b/c' JSON-pointer ref against `spec`. Non-local or broken
    refs resolve to {} (fail-open to empty, never crash on a foreign $ref)."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node = spec
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return {}
        node = node[part]
    return node if isinstance(node, dict) else {}


def schema_field_names(spec: dict, schema: dict, depth: int = 0,
                       seen: frozenset[str] | None = None) -> list[str]:
    """Top-level property NAMES of a (possibly composed) object schema. Follows a local
    $ref, and merges the members of allOf/oneOf/anyOf (a best-effort union so a
    discriminated body still surfaces its field names). Values are never read."""
    if not isinstance(schema, dict) or depth > _MAX_REF_DEPTH:
        return []
    seen = seen or frozenset()
    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen:                       # cycle guard
            return []
        return schema_field_names(spec, resolve_ref(spec, ref), depth + 1, seen | {ref})
    names: list[str] = []
    props = schema.get("properties")
    if isinstance(props, dict):
        names.extend(str(k) for k in props.keys())
    # array of objects -> descend into items so a POST of [{...}] still yields field names
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        names.extend(schema_field_names(spec, schema["items"], depth + 1, seen))
    for comb in ("allOf", "oneOf", "anyOf"):
        members = schema.get(comb)
        if isinstance(members, list):
            for m in members:
                if isinstance(m, dict):
                    names.extend(schema_field_names(spec, m, depth + 1, seen))
    # dedupe, preserve first-seen order, cap
    out, s = [], set()
    for n in names:
        if n not in s:
            s.add(n)
            out.append(n)
    return out[:40]


def _json_body_schema(spec: dict, request_body: dict) -> dict:
    """The application/json (or first) body schema from a requestBody object (ref-resolved)."""
    if not isinstance(request_body, dict):
        return {}
    if "$ref" in request_body:
        request_body = resolve_ref(spec, request_body["$ref"])
    content = request_body.get("content")
    if not isinstance(content, dict):
        return {}
    for ct in ("application/json", "application/*+json"):
        if ct in content and isinstance(content[ct], dict):
            return content[ct].get("schema") or {}
    # fall back to any *json content type, then the first content type present
    for ct, media in content.items():
        if "json" in ct and isinstance(media, dict):
            return media.get("schema") or {}
    for media in content.values():
        if isinstance(media, dict):
            return media.get("schema") or {}
    return {}


# ── parameter + security extraction ─────────────────────────────────────────────
def _merged_parameters(spec: dict, path_item: dict, op: dict) -> list[dict]:
    """Path-level + operation-level parameters, each ref-resolved."""
    raw = list(path_item.get("parameters") or []) + list(op.get("parameters") or [])
    out = []
    for p in raw:
        if isinstance(p, dict) and "$ref" in p:
            p = resolve_ref(spec, p["$ref"])
        if isinstance(p, dict) and p.get("name"):
            out.append(p)
    return out


def query_param_names(spec: dict, path_item: dict, op: dict) -> list[str]:
    seen, out = set(), []
    for p in _merged_parameters(spec, path_item, op):
        if p.get("in") == "query":
            n = str(p["name"])
            if n not in seen:
                seen.add(n)
                out.append(n)
    return sorted(out)


def operation_requires_auth(spec: dict, op: dict) -> bool:
    """True unless the operation is explicitly public. An operation `security` overrides
    the global one; `security: []` means public; a global scheme with no override is
    inherited. Empty-object requirements ({}) count as "optional" -> not required."""
    sec = op.get("security")
    if sec is None:
        sec = spec.get("security")
    if not sec:                       # None or [] -> no auth required
        return False
    # sec is a list of requirement objects; a [{}] entry means "optional"
    return any(isinstance(req, dict) and req for req in sec)


# ── server / url ────────────────────────────────────────────────────────────────
def _server_url(spec: dict, path_item: dict, op: dict, override: str | None) -> str:
    if override:
        base = override
    else:
        for src in (op.get("servers"), path_item.get("servers"), spec.get("servers")):
            if isinstance(src, list) and src and isinstance(src[0], dict) and src[0].get("url"):
                base = src[0]["url"]
                break
        else:
            base = ""
    return base.rstrip("/")


# ── the conversion ──────────────────────────────────────────────────────────────
def openapi_to_endpoints(spec: dict, server_override: str | None = None) -> list[dict]:
    """Every operation in an OpenAPI 3.x doc -> asset-map endpoints[] records."""
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    out: list[dict] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        base = _server_url(spec, path_item, path_item, server_override)  # path-level server
        for method in _HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            srv = _server_url(spec, path_item, op, server_override)      # op-level can override
            url = (srv or base) + path
            rec = {
                "url": url,
                "method": method.upper(),
                "source": "openapi",
                "auth_required": operation_requires_auth(spec, op),
                "tags": [str(t) for t in (op.get("tags") or []) if isinstance(t, (str, int))],
            }
            params = query_param_names(spec, path_item, op)
            if params:
                rec["parameters"] = params
            body_fields = schema_field_names(spec, _json_body_schema(spec, op.get("requestBody") or {}))
            if body_fields:
                rec["body_fields"] = body_fields
            out.append(rec)
    return out


# ── merge (mirrors authed-crawl.merge_endpoints; openapi is LOWEST priority) ─────
def canonical(url: str) -> str:
    p = urlparse(url or "")
    keys = ",".join(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    base = f"{p.scheme}://{p.netloc}{p.path or '/'}"
    return f"{base}?{keys}" if keys else base


def merge_endpoints(existing: list[dict], incoming: list[dict]) -> list[dict]:
    """Union `incoming` (openapi) into `existing`, keyed by (METHOD, canonical url). Unions
    parameters/body_fields/tags and OR-s auth_required. A live source (authed-crawl) already
    on a row is authoritative and is never demoted to 'openapi'; a brand-new row keeps its
    openapi source. This makes the converter safe to re-run and safe to run after a crawl."""
    def key(e: dict) -> tuple:
        return (str(e.get("method", "GET")).upper(), canonical(str(e.get("url", ""))))

    merged: dict[tuple, dict] = {}
    order: list[tuple] = []
    for e in (existing or []) + (incoming or []):
        if not isinstance(e, dict) or not e.get("url"):
            continue
        k = key(e)
        if k not in merged:
            merged[k] = dict(e)
            order.append(k)
        else:
            row = merged[k]
            for field in ("parameters", "body_fields", "tags"):
                if e.get(field):
                    row[field] = sorted(set(row.get(field, [])) | set(e[field]))
            if e.get("auth_required"):
                row["auth_required"] = True
            # never overwrite a live-observed source with the static spec
            if e.get("source") and row.get("source") == "openapi" and e.get("source") != "openapi":
                row["source"] = e["source"]
    return [merged[k] for k in order]


def ingest(spec: dict, asset_map: dict, server_override: str | None = None) -> dict:
    """Return a new asset_map with the spec's operations merged into endpoints[]."""
    data = dict(asset_map or {})
    data.setdefault("target", "")
    data.setdefault("generated_by", "huginn")
    eps = openapi_to_endpoints(spec, server_override)
    data["endpoints"] = merge_endpoints(data.get("endpoints") or [], eps)
    return data


# ── spec loading ────────────────────────────────────────────────────────────────
def load_spec(src: str, opener=None) -> dict:
    """Load an OpenAPI doc from a local path or an http(s) url (JSON; YAML if PyYAML present).
    `opener` routes a remote fetch through the program's egress proxy when one is configured."""
    if src.startswith("http://") or src.startswith("https://"):
        import urllib.request
        req = urllib.request.Request(src, headers={"Accept": "application/json",
                                                   "User-Agent": "grimnir-openapi-ingest/1.0"})
        fetch = opener or urllib.request.build_opener()
        with fetch.open(req, timeout=40) as r:  # noqa: S310 (operator-supplied url)
            raw = r.read().decode("utf-8", "replace")
    else:
        with open(src, "r", encoding="utf-8") as fh:
            raw = fh.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        try:
            import yaml  # optional
        except ImportError:
            raise SystemExit("[openapi] spec is not JSON and PyYAML is not installed")
        return yaml.safe_load(raw)


# ── selftest ────────────────────────────────────────────────────────────────────
def _selftest() -> int:
    spec = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://api.example.test"}],
        "security": [{"appSecretAuth": []}],
        "components": {"schemas": {
            "NewWallet": {"type": "object", "properties": {"chain_type": {}, "policy_ids": {}}},
            "Base": {"type": "object", "properties": {"idempotency_key": {}}},
        }},
        "paths": {
            "/v1/wallets/{wallet_id}": {
                "get": {"tags": ["Wallets"]},
                "patch": {"tags": ["Wallets"],
                          "requestBody": {"content": {"application/json": {"schema": {
                              "allOf": [{"$ref": "#/components/schemas/NewWallet"},
                                        {"$ref": "#/components/schemas/Base"}]}}}}},
            },
            "/v1/wallets": {
                "get": {"tags": ["Wallets"],
                        "parameters": [{"name": "cursor", "in": "query"},
                                       {"name": "limit", "in": "query"}]},
                "post": {"tags": ["Wallets"],
                         "requestBody": {"content": {"application/json": {
                             "schema": {"$ref": "#/components/schemas/NewWallet"}}}}},
            },
            "/v1/auth/login": {
                "post": {"tags": ["Client Auth"], "security": []},   # explicitly public
            },
        },
    }
    eps = openapi_to_endpoints(spec)
    by = {(e["method"], e["url"]): e for e in eps}

    # id-bearing GET keeps the native placeholder + inherits global auth
    g = by[("GET", "https://api.example.test/v1/wallets/{wallet_id}")]
    assert g["auth_required"] is True and g["source"] == "openapi" and g["tags"] == ["Wallets"], g

    # composed (allOf of two $refs) body -> union of both schemas' field NAMES, no values
    p = by[("PATCH", "https://api.example.test/v1/wallets/{wallet_id}")]
    assert p["body_fields"] == ["chain_type", "policy_ids", "idempotency_key"], p

    # query params captured (sorted), path has no id so no placeholder
    coll = by[("GET", "https://api.example.test/v1/wallets")]
    assert coll["parameters"] == ["cursor", "limit"] and "body_fields" not in coll, coll

    # $ref body on POST resolves to the schema's field names
    post = by[("POST", "https://api.example.test/v1/wallets")]
    assert post["body_fields"] == ["chain_type", "policy_ids"], post

    # security:[] -> public
    login = by[("POST", "https://api.example.test/v1/auth/login")]
    assert login["auth_required"] is False, login

    # merge: existing huginn row is preserved (source not demoted), fields unioned, re-run idempotent
    existing = [{"url": "https://api.example.test/v1/wallets/{wallet_id}", "method": "GET",
                 "source": "huginn", "tags": ["seed"]}]
    m1 = merge_endpoints(existing, eps)
    row = next(e for e in m1 if e["method"] == "GET" and e["url"].endswith("{wallet_id}"))
    assert row["source"] == "huginn" and set(row["tags"]) == {"seed", "Wallets"}, row
    assert row["auth_required"] is True, row
    # a brand-new openapi row keeps openapi source; count is stable on re-merge
    m2 = merge_endpoints(m1, eps)
    assert len(m1) == len(m2) == len(eps), (len(m1), len(m2), len(eps))
    assert any(e["source"] == "openapi" for e in m2)

    # broken / foreign $ref fails open to no fields (never crashes)
    assert schema_field_names(spec, {"$ref": "#/nope/missing"}) == []
    assert schema_field_names(spec, {"$ref": "https://ext/schema"}) == []
    return 0


# ── cli ─────────────────────────────────────────────────────────────────────────
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Convert an OpenAPI spec into asset-map endpoints[].")
    ap.add_argument("--selftest", action="store_true", help="run pure oracles and exit")
    ap.add_argument("--spec", help="OpenAPI JSON/YAML: local path or http(s) url")
    ap.add_argument("--project-dir", help="engagement dir; merges into <dir>/asset-map.json")
    ap.add_argument("--out", help="explicit output asset-map path (overrides --project-dir default)")
    ap.add_argument("--server", help="override the server base url (else spec servers[0])")
    ap.add_argument("--dry-run", action="store_true", help="print summary, write nothing")
    ap.add_argument("--json", action="store_true", help="machine-readable summary on stdout")
    a = ap.parse_args(argv)

    if a.selftest:
        try:
            _selftest()
        except AssertionError as e:
            print(f"[openapi] selftest FAIL: {e}", file=sys.stderr)
            return 1
        print("[openapi] selftest OK")
        return 0

    if not a.spec:
        ap.error("--spec is required (unless --selftest)")
    spec = load_spec(a.spec, opener=_egress.opener(proxy=_egress.proxy(a.project_dir)))

    out_path = a.out
    if not out_path and a.project_dir:
        out_path = os.path.join(a.project_dir, "asset-map.json")

    existing = {}
    if out_path and os.path.exists(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
        except (OSError, json.JSONDecodeError):
            existing = {}

    new_eps = openapi_to_endpoints(spec, a.server)
    data = ingest(spec, existing, a.server)

    id_bearing = sum(1 for e in new_eps if "{" in e["url"])
    writes = sum(1 for e in new_eps if e["method"] in ("POST", "PUT", "PATCH", "DELETE"))
    summary = {
        "spec_title": (spec.get("info") or {}).get("title", ""),
        "operations": len(new_eps),
        "id_bearing": id_bearing,
        "write_ops": writes,
        "with_body_fields": sum(1 for e in new_eps if e.get("body_fields")),
        "endpoints_total_after_merge": len(data["endpoints"]),
        "out": out_path or "(dry-run)",
    }

    if not a.dry_run and out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    if a.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[openapi] {summary['spec_title']}: {summary['operations']} ops "
              f"({summary['id_bearing']} id-bearing, {summary['write_ops']} writes, "
              f"{summary['with_body_fields']} with body fields) -> "
              f"{summary['endpoints_total_after_merge']} endpoints in "
              f"{'(dry-run, nothing written)' if a.dry_run else out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
