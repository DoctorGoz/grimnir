#!/usr/bin/env python3
"""corpus-build.py -- fill asset-map.json endpoints[] / hosts[] / auth_mechanisms[] from ALL recon output.

Why this exists. asset-map.sh was the only writer of `endpoints[]` and it read a single file
(`crawl-katana.txt`, truncated to 200 lines). It ignored the JS crawl, the archive URL lists, any
OpenAPI/Swagger spec sitting in recon/, put JS-extracted paths in `js_analysis` instead of
`endpoints[]`, and never filled `hosts[]` or `auth_mechanisms[]`. Most engagements therefore reached
the lane synthesizer (scripts/lane synthesis) with an empty corpus and got zero lanes even for
credential-free classes. This is the missing ingest: it MERGES every on-disk recon source into the
existing asset map, tags each endpoint with where it came from, and drops anything out of scope.

Offline and deterministic: it only reads files already under $PROJECT_DIR/recon/. No network, no LLM.

SOURCES (each recorded on the entry as `sources[]`, plus a `seen_live` boolean)
    crawl    crawl-katana.txt, js-urls-katana.txt            live fetch of the target       seen_live
    archive  urls-gau.txt, urls-wayback.txt                  historical; host must be live  not live
    js       js-endpoints.txt                                paths mined from JS bundles    not live
    spec     recon/**/{openapi,swagger}*.{json,yaml,yml}     every documented operation     not live
             (+ any recon *.json whose top level has `openapi`/`swagger`)
    probe    other recon/*.jsonl with `url` + `method`       requests actually sent         seen_live
    hosts    httpx-results.json, httpx-all.jsonl             -> top-level hosts[]

ENTRY SCHEMA. Matches request_to_endpoint (authed-crawl.py) and openapi_to_endpoints so the same
downstream chain runs unchanged: {url, method, source, auth_required?, tags[], parameters[],
body_fields[]}. Additions: `sources[]` (list; the legacy `source` string is kept untouched because
authed-crawl.merge_endpoints compares it) and `seen_live`. `auth_required` is deliberately OMITTED
for crawl/archive/js entries: lane synthesis treats `auth_required is False` as "public, skip", and an
archive URL says nothing about auth, so asserting False would silently kill lanes.

RANKING UNDER THE CAP. New entries are admitted in the order (seen live, source quality, has a query or
id, url), with source quality spec < probe < crawl < js < archive. Provenance outranks shape: an archive
URL that happens to carry `?x=` must not displace a crawled, mined or documented path. Archive-only
candidates (no other source saw them) may additionally take at most `--archive-share` (default 0.4) of
the room left under the cap, and that room is not backfilled when the other sources run short; the
overflow is reported as `archive_capped`, separately from `capped`.

DEDUPE. Entries merge on (METHOD, canonical url = path + sorted query-param NAMES). Separately the
path is templatized (numeric ids, UUIDs, long hex/base64 segments, `{placeholders}` -> `{id}`) and at
most 3 concrete examples are kept per (method, host, template): the lane synthesizer needs concrete
ids, but 40k `/orders/<n>` rows add nothing. Query parameter VALUES are never recorded as separate
fields; they exist only inside the concrete url that was already on disk.

SCOPE GATE. scripts/scope.py is the shared in-scope decision. When it has a parseable in-scope
pattern, every NEW endpoint and host that is not in scope is dropped (pre-existing entries are never
deleted, only counted as `preexisting_oos`). When it does not, entries are kept and the summary says
`scope: "unavailable"`; the fire gates downstream fail closed on their own.

Usage:
    corpus-build.py --project-dir DIR [--asset-map PATH] [--out PATH] [--max-endpoints 5000]
                    [--archive-share 0.4]
                    [--json] [--dry-run]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

_HERE = Path(__file__).resolve().parent
_SCRIPTS = _HERE.parent.parent / "scripts"


def _load_by_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ── normalization ───────────────────────────────────────────────────────────────
_STATIC_EXT = {
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif", "bmp", "tif", "tiff",
    "css", "scss", "less", "map", "woff", "woff2", "ttf", "otf", "eot",
    "mp4", "mp3", "webm", "ogg", "wav", "m4a", "avi", "mov", "flac",
    "pdf", "zip", "gz", "tgz", "rar", "7z", "dmg", "exe", "apk", "ipa",
    "js", "mjs", "cjs", "jsx", "ts",
}
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_B64ISH_RE = re.compile(r"^[A-Za-z0-9_=-]{20,}$")
_PREFIXED_ID_RE = re.compile(r"^[a-z]{2,6}_[A-Za-z0-9]{12,}$")
_PLACEHOLDER_RE = re.compile(r"^\{[^/{}]+\}$")
_BAD_URL_CHARS = re.compile(r"[\s<>\"'`\\^|*$]|\{\{|%7[bB]%7[bB]")
METHODS_WRITE = ("POST", "PUT", "PATCH", "DELETE")


def normalize_url(raw: str, base: str | None = None) -> str | None:
    """Canonical concrete url, or None to drop. http(s) only, lowercase host, no fragment/userinfo,
    no static assets (a `.js` file is a script, not an endpoint)."""
    raw = (raw or "").strip().strip("\"'")
    if not raw or _BAD_URL_CHARS.search(raw.replace("{", "").replace("}", "")):
        return None
    if raw.startswith("//"):
        return None
    if base and raw.startswith("/"):
        raw = base.rstrip("/") + raw
    try:
        p = urlsplit(raw)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https") or not host or "{" in host or ("." not in host and ":" not in host):
        return None
    path = p.path or "/"
    last = path.rsplit("/", 1)[-1]
    if "." in last and last.rsplit(".", 1)[-1].lower() in _STATIC_EXT:
        return None
    netloc = host if ":" not in host else f"[{host}]"
    if port and not ((p.scheme.lower() == "http" and port == 80) or (p.scheme.lower() == "https" and port == 443)):
        netloc += f":{port}"
    out = f"{p.scheme.lower()}://{netloc}{path}"
    if p.query:
        out += "?" + p.query
    return out


def _segment_template(seg: str) -> str:
    if not seg:
        return seg
    if _PLACEHOLDER_RE.match(seg) or seg.isdigit() or _UUID_RE.match(seg) or _HEX_RE.match(seg):
        return "{id}"
    if _PREFIXED_ID_RE.match(seg):
        return "{id}"
    if (_B64ISH_RE.match(seg) and any(c.isdigit() for c in seg)
            and any(c.isupper() for c in seg) and any(c.islower() for c in seg)):
        return "{id}"
    return seg


def template_path(path: str) -> str:
    return "/".join(_segment_template(s) for s in path.split("/"))


def param_names(url: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k})


def canonical(url: str) -> str:
    """(path + sorted query-param NAMES) -- same notion as authed-crawl / openapi-to-assetmap."""
    p = urlsplit(url)
    base = f"{p.scheme}://{p.netloc}{p.path or '/'}"
    keys = ",".join(param_names(url))
    return f"{base}?{keys}" if keys else base


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# ── readers ─────────────────────────────────────────────────────────────────────
def _lines(path: Path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield line
    except OSError:
        return


def _url_from_line(line: str) -> str | None:
    """A url from a plain-text line, or from a katana/httpx JSON-lines record."""
    if line.startswith("{"):
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(o, dict):
            return None
        req = o.get("request") if isinstance(o.get("request"), dict) else {}
        return req.get("endpoint") or o.get("url") or o.get("endpoint")
    m = re.search(r"https?://\S+", line)
    return m.group(0) if m else None


def _json_records(path: Path):
    """Records from a JSON array, a single object, or JSON lines (httpx writes all three)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    s = text.lstrip()
    if s.startswith("["):
        try:
            data = json.loads(s)
        except json.JSONDecodeError:
            data = []
        for r in data:
            if isinstance(r, dict):
                yield r
        return
    for line in s.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(r, dict):
                yield r


def read_hosts(recon: Path) -> list[dict]:
    seen: dict[str, dict] = {}
    for name in ("httpx-results.json", "httpx-all.jsonl"):
        for r in _json_records(recon / name):
            url = str(r.get("url") or "").strip()
            host = str(r.get("host") or _host_of(url)).lower()
            if not url or not host or r.get("failed") is True:
                continue
            if url in seen:
                continue
            tech = r.get("tech") or r.get("technologies") or []
            seen[url] = {
                "url": url,
                "host": host,
                "status": r.get("status_code", r.get("status")),
                "title": r.get("title") or "",
                "tech": sorted({str(t) for t in tech}) if isinstance(tech, list) else [],
                "cdn": str(r.get("cdn_name") or ("true" if r.get("cdn") is True else "")),
            }
    return [seen[k] for k in sorted(seen)]


def read_js_endpoints(path: Path) -> tuple[list[str], int]:
    """js-pipeline.sh writes `  [source: <js url>]` and then that file's endpoints, so the most
    recent marker is the origin that resolves a relative path. Returns (urls, unresolved_count)."""
    urls: list[str] = []
    unresolved = 0
    origin: str | None = None
    for line in _lines(path):
        m = re.match(r"^\[source:\s*(.*?)\]$", line)
        if m:
            src = m.group(1)
            try:
                p = urlsplit(src)
                origin = f"{p.scheme}://{p.netloc}" if p.scheme in ("http", "https") and p.netloc else None
            except ValueError:
                origin = None
            continue
        if line.startswith("["):
            continue
        tok = line.split()[0] if line.split() else ""
        if re.match(r"^https?://", tok):
            urls.append(tok)
        elif tok.startswith("/") and not tok.startswith("//"):
            if "node_modules" in tok or tok.startswith("/ROOT/") or len(tok) < 3:
                continue
            if origin:
                urls.append(origin + tok)
            else:
                unresolved += 1
    return urls, unresolved


def read_probes(recon: Path) -> list[dict]:
    out = []
    for f in sorted(recon.glob("*.jsonl")):
        if f.name == "httpx-all.jsonl":
            continue
        for line in _lines(f):
            if not line.startswith("{"):
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(r, dict) or not r.get("url") or not r.get("method"):
                continue
            if "host_ip" in r and "input" in r:   # an httpx record, not a probe
                continue
            out.append(r)
    return out


_SPEC_SKIP_DIRS = {"js", "js-netnew", "beautified", "raw", "node_modules"}
_SPEC_MAX_BYTES = 25 * 1024 * 1024


def find_specs(recon: Path) -> tuple[list[tuple[Path, dict]], list[str]]:
    """OpenAPI/Swagger docs under recon/. Returns ([(path, doc)], yaml_skipped_files)."""
    specs, yaml_skipped = [], []
    if not recon.is_dir():
        return specs, yaml_skipped
    for root, dirs, files in os.walk(recon):
        dirs[:] = sorted(d for d in dirs if d not in _SPEC_SKIP_DIRS)
        for fn in sorted(files):
            low = fn.lower()
            p = Path(root) / fn
            named = re.search(r"openapi|swagger", low) is not None
            ext = low.rsplit(".", 1)[-1]
            if ext not in ("yaml", "yml", "json") or (ext != "json" and not named):
                continue
            try:
                if p.stat().st_size > _SPEC_MAX_BYTES:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            doc = None
            if ext == "json":
                try:
                    doc = json.loads(text)
                except json.JSONDecodeError:
                    pass   # a spec saved as .json is sometimes YAML; try below if it is named like one
            if doc is None and (ext != "json" or named):
                try:
                    import yaml  # optional
                except ImportError:
                    yaml_skipped.append(str(p.relative_to(recon)))
                    continue
                try:
                    doc = yaml.safe_load(text)
                except Exception:  # noqa: BLE001 -- any YAML error just means "not a spec"
                    continue
            if isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and isinstance(doc.get("paths"), dict):
                specs.append((p, doc))
    return specs, yaml_skipped


def _swagger2_to_v3(doc: dict) -> dict:
    """Minimal Swagger 2 -> OpenAPI 3 shape so openapi_to_endpoints can read it: a servers[] entry
    from host/basePath/schemes and the `in: body` parameter lifted into requestBody."""
    if "swagger" not in doc or "openapi" in doc:
        return doc
    d = json.loads(json.dumps(doc))
    host = d.get("host")
    if host:
        scheme = (d.get("schemes") or ["https"])[0]
        d["servers"] = [{"url": f"{scheme}://{host}{d.get('basePath', '') or ''}"}]
    for item in (d.get("paths") or {}).values():
        if not isinstance(item, dict):
            continue
        for m, op in item.items():
            if not isinstance(op, dict):
                continue
            for prm in op.get("parameters") or []:
                if isinstance(prm, dict) and prm.get("in") == "body":
                    op["requestBody"] = {"content": {"application/json": {"schema": prm.get("schema") or {}}}}
    return d


_SCHEME_TYPES = {"oauth2": "oauth2", "openidconnect": "oidc"}


def spec_auth_types(doc: dict) -> set[str]:
    """Playbook-vocabulary auth types from securitySchemes / securityDefinitions."""
    schemes = ((doc.get("components") or {}).get("securitySchemes")) or doc.get("securityDefinitions") or {}
    out: set[str] = set()
    for s in schemes.values() if isinstance(schemes, dict) else []:
        if not isinstance(s, dict):
            continue
        t = str(s.get("type", "")).lower()
        if t in _SCHEME_TYPES:
            out.add(_SCHEME_TYPES[t])
        elif t == "http":
            sch = str(s.get("scheme", "")).lower()
            out.add("bearer_token" if sch == "bearer" else "basic" if sch == "basic" else "api_token")
        elif t == "basic":
            out.add("basic")
        elif t == "apikey":
            out.add("api_key_header" if str(s.get("in", "")).lower() == "header" else "api_token")
    return out


# ── the build ───────────────────────────────────────────────────────────────────
_SRC_RANK = {"spec": 0, "probe": 1, "crawl": 2, "js": 3, "archive": 4}
_LEGACY_SOURCE_MAP = {"katana": "crawl", "openapi": "spec", "authed-crawl": "authed-crawl"}
_LIVE_LEGACY = {"katana", "crawl", "authed-crawl", "probe"}


class Candidate:
    __slots__ = ("url", "method", "sources", "seen_live", "extra")

    def __init__(self, url: str, method: str):
        self.url, self.method = url, method
        self.sources: set[str] = set()
        self.seen_live = False
        self.extra: dict = {}


def build(project_dir: Path, asset_map: dict, max_endpoints: int = 5000,
          archive_share: float = 0.4) -> tuple[dict, dict]:
    recon = project_dir / "recon"
    scope = None
    scope_mod = _SCRIPTS / "scope.py"
    try:
        scope = _load_by_path("grimnir_scope_for_corpus", scope_mod).load(str(project_dir))
    except Exception as exc:  # noqa: BLE001 -- a broken scope module must not take the corpus down
        sys.stderr.write(f"[corpus-build] scope.py unavailable: {exc}\n")
    scope_ok = bool(scope is not None and scope.ok)

    summary: dict = {
        "scope": ("enforced" if scope_ok else "unavailable"),
        "candidates": {}, "new_by_source": {}, "static_dropped": 0, "archive_not_live": 0,
        "js_unresolved": 0, "spec_no_server": 0, "specs": [], "yaml_skipped": [],
        "oos_dropped": 0, "oos_sample_hosts": [], "preexisting_oos": 0,
        "template_capped": 0, "capped": 0, "archive_capped": 0,
    }

    am = dict(asset_map)
    for k, v in (("hosts", []), ("endpoints", []), ("auth_mechanisms", [])):
        if not isinstance(am.get(k), list):
            am[k] = v
    existing: list[dict] = am["endpoints"]
    summary["endpoints_before"] = len(existing)
    summary["hosts_before"] = len(am["hosts"])

    # liveness comes from httpx; archive urls on any other host are noise
    hosts = read_hosts(recon)
    live_hosts = {h["host"] for h in hosts}

    cands: dict[tuple[str, str], Candidate] = {}
    uniq: dict[str, set[str]] = {}

    def add(raw: str | None, source: str, live: bool, method: str = "GET", extra: dict | None = None,
            base: str | None = None):
        if not raw:
            return
        url = normalize_url(raw, base)
        if url is None:
            summary["static_dropped"] += 1
            return
        if source == "archive" and _host_of(url) not in live_hosts:
            summary["archive_not_live"] += 1
            return
        method = method.upper()
        uniq.setdefault(source, set()).add(url)
        c = cands.setdefault((method, canonical(url)), Candidate(url, method))
        if url < c.url:
            c.url = url
        c.sources.add(source)
        c.seen_live = c.seen_live or live
        for k, v in (extra or {}).items():
            if k in ("parameters", "body_fields", "tags"):
                c.extra[k] = sorted(set(c.extra.get(k, [])) | set(v))
            else:
                c.extra.setdefault(k, v)

    for name in ("crawl-katana.txt", "js-urls-katana.txt"):
        for line in _lines(recon / name):
            add(_url_from_line(line), "crawl", True)
    for name in ("urls-gau.txt", "urls-wayback.txt"):
        for line in _lines(recon / name):
            add(_url_from_line(line), "archive", False)
    if (recon / "js-endpoints.txt").is_file():
        js_urls, unresolved = read_js_endpoints(recon / "js-endpoints.txt")
        summary["js_unresolved"] = unresolved
        for u in js_urls:
            add(u, "js", False)
    for r in read_probes(recon):
        extra = {}
        if isinstance(r.get("status_code", r.get("status")), int):
            extra["status_code"] = r.get("status_code", r.get("status"))
        for k in ("body_fields", "tags"):     # e.g. scripts/caido-export.py's proxied traffic
            if isinstance(r.get(k), list) and r[k]:
                extra[k] = [str(x) for x in r[k]]
        add(str(r["url"]), "probe", True, str(r["method"]), extra)

    spec_auth: set[str] = set()
    specs, yaml_skipped = find_specs(recon)
    summary["yaml_skipped"] = yaml_skipped
    if yaml_skipped:
        summary["yaml_note"] = "PyYAML not installed; YAML specs skipped"
    oa = None
    if specs:
        oa = _load_by_path("grimnir_openapi_for_corpus", _SCRIPTS / "openapi-to-assetmap.py")
    for path, doc in specs:
        ops = oa.openapi_to_endpoints(_swagger2_to_v3(doc))
        kept = 0
        for op in ops:
            if "://" not in op["url"]:
                summary["spec_no_server"] += 1
                continue
            extra = {k: op[k] for k in ("auth_required", "parameters", "body_fields", "tags") if k in op}
            add(op["url"], "spec", False, op["method"], extra)
            kept += 1
        if kept:
            spec_auth |= spec_auth_types(doc)
        summary["specs"].append({"file": str(path.relative_to(recon)), "operations": len(ops)})
    summary["candidates"] = {k: len(v) for k, v in sorted(uniq.items())}

    # ── existing entries: index, add provenance only ──
    ex_keys: dict[tuple[str, str], dict] = {}
    for e in existing:
        if not isinstance(e, dict) or not e.get("url"):
            continue
        url = str(e["url"])
        key = (str(e.get("method") or "GET").upper(), canonical(url))
        ex_keys.setdefault(key, e)
        if "sources" not in e:
            leg = str(e.get("source") or "")
            e["sources"] = [_LEGACY_SOURCE_MAP.get(leg, leg)] if leg else []
        if "seen_live" not in e:
            e["seen_live"] = bool(e.get("source") in _LIVE_LEGACY or isinstance(e.get("status_code"), int))
        if scope_ok and not scope.check(url).in_scope:
            summary["preexisting_oos"] += 1
    for key, c in cands.items():
        e = ex_keys.get(key)
        if e is not None:
            e["sources"] = sorted(set(e.get("sources") or []) | c.sources)
            e["seen_live"] = bool(e.get("seen_live")) or c.seen_live

    # ── new entries: scope gate, template cap, global cap ──
    per_template: dict[tuple[str, str, str], int] = {}
    for key, e in ex_keys.items():
        p = urlsplit(str(e["url"]))
        per_template[(key[0], (p.hostname or "").lower(), template_path(p.path or "/"))] = \
            per_template.get((key[0], (p.hostname or "").lower(), template_path(p.path or "/")), 0) + 1

    oos_hosts: set[str] = set()
    fresh: list[tuple[tuple, Candidate]] = []
    for key, c in cands.items():
        if key in ex_keys:
            continue
        if scope_ok:
            v = scope.check(c.url)
            if not v.in_scope:
                summary["oos_dropped"] += 1
                oos_hosts.add(v.host or _host_of(c.url))
                continue
        p = urlsplit(c.url)
        has_id = template_path(p.path or "/") != (p.path or "/")
        # provenance before shape: a query string on a stale archive URL must not outrank a crawled
        # or spec'd path, and archive is the largest source by orders of magnitude
        rank = (0 if c.seen_live else 1, min(_SRC_RANK.get(s, 9) for s in c.sources),
                0 if (p.query or has_id) else 1, c.url)
        fresh.append((rank, c))
    fresh.sort(key=lambda t: t[0])

    kept_new: list[Candidate] = []
    room = max(0, max_endpoints - len(existing))
    # archive-only candidates may take at most this share of the room; the rest is NOT backfilled
    archive_room = int(room * min(1.0, max(0.0, archive_share)))
    archive_kept = 0
    for _rank, c in fresh:
        p = urlsplit(c.url)
        tk = (c.method, (p.hostname or "").lower(), template_path(p.path or "/"))
        if per_template.get(tk, 0) >= 3:
            summary["template_capped"] += 1
            continue
        # the archive share is spent on candidates it considers, so the global cap can still bind inside it
        archive_only = c.sources == {"archive"}
        if archive_only:
            if archive_kept >= archive_room:
                summary["archive_capped"] += 1
                continue
            archive_kept += 1
        if len(kept_new) >= room:
            summary["capped"] += 1
            continue
        per_template[tk] = per_template.get(tk, 0) + 1
        kept_new.append(c)
    summary["oos_sample_hosts"] = sorted(oos_hosts)[:10]

    new_entries = []
    for c in sorted(kept_new, key=lambda c: (_host_of(c.url), template_path(urlsplit(c.url).path or "/"), c.method, c.url)):
        srcs = sorted(c.sources, key=lambda s: (_SRC_RANK.get(s, 9), s))
        rec = {"url": c.url, "method": c.method,
               "source": "openapi" if "spec" in c.sources else srcs[0],
               "sources": srcs, "seen_live": c.seen_live, "tags": []}
        names = param_names(c.url)
        if names or c.extra.get("parameters"):
            rec["parameters"] = sorted(set(names) | set(c.extra.get("parameters", [])))
        for k in ("body_fields", "status_code", "auth_required"):
            if k in c.extra:
                rec[k] = c.extra[k]
        if c.extra.get("tags"):
            rec["tags"] = c.extra["tags"]
        new_entries.append(rec)
        for s in c.sources:
            summary["new_by_source"][s] = summary["new_by_source"].get(s, 0) + 1
    summary["new_by_source"] = dict(sorted(summary["new_by_source"].items()))
    am["endpoints"] = existing + new_entries
    summary["endpoints_after"] = len(am["endpoints"])

    # ── hosts[] ──
    have = {str(h.get("url")) for h in am["hosts"] if isinstance(h, dict)}
    host_oos = 0
    for h in hosts:
        if h["url"] in have:
            continue
        if scope_ok and not scope.check(h["url"]).in_scope:
            host_oos += 1
            continue
        am["hosts"].append(h)
    summary["hosts_oos_dropped"] = host_oos
    summary["oos_dropped"] += host_oos
    summary["hosts_after"] = len(am["hosts"])

    # ── auth_mechanisms[] (conservative: only evidence on disk) ──
    found: dict[str, str] = {}
    for t in sorted(spec_auth):
        found.setdefault(t, "openapi securitySchemes")
    path_rules = [(re.compile(r"/oauth2?/(authorize|token)\b|/connect/(authorize|token)\b|/authorize$", re.I), "oauth2"),
                  (re.compile(r"/\.well-known/openid-configuration", re.I), "oidc"),
                  (re.compile(r"/saml2?(/|$)|/sso/saml", re.I), "saml")]
    for e in am["endpoints"]:
        if not isinstance(e, dict):
            continue
        path = urlsplit(str(e.get("url") or "")).path
        for rx, t in path_rules:
            if rx.search(path):
                found.setdefault(t, f"path seen: {path}")
    www = recon / "response-headers.txt"
    for line in _lines(www):
        m = re.match(r"(?i)^www-authenticate:\s*(\w+)", line)
        if m:
            sch = m.group(1).lower()
            t = {"bearer": "bearer_token", "basic": "basic", "negotiate": "negotiate", "ntlm": "negotiate"}.get(sch)
            if t:
                found.setdefault(t, f"WWW-Authenticate: {m.group(1)} in response-headers.txt")
    have_types = {str(a.get("type", "")).lower() for a in am["auth_mechanisms"] if isinstance(a, dict)}
    added_auth = 0
    for t in sorted(found):
        if t not in have_types:
            am["auth_mechanisms"].append({"type": t, "evidence": found[t], "source": "corpus-build"})
            added_auth += 1
    summary["auth_mechanisms_added"] = added_auth
    return am, summary


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Merge all recon output into asset-map.json endpoints[]/hosts[]/auth_mechanisms[].")
    ap.add_argument("--project-dir", required=True, help="absolute engagement dir")
    ap.add_argument("--asset-map", help="input asset map (default <project-dir>/asset-map.json)")
    ap.add_argument("--out", help="output path (default: rewrite the input asset map)")
    ap.add_argument("--max-endpoints", type=int, default=5000, help="cap on total endpoints[] (existing are never dropped)")
    ap.add_argument("--archive-share", type=float, default=0.4,
                    help="max share of the remaining room archive-only urls may take (default 0.4; unused room is not backfilled)")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    ap.add_argument("--dry-run", action="store_true", help="compute and report, write nothing")
    a = ap.parse_args(argv)

    pd = Path(a.project_dir).expanduser().resolve()
    if not pd.is_dir():
        print(f"[corpus-build] not a directory: {pd}", file=sys.stderr)
        return 2
    src = Path(a.asset_map) if a.asset_map else pd / "asset-map.json"
    base: dict = {}
    if src.is_file():
        try:
            base = json.loads(src.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[corpus-build] cannot read {src}: {exc}", file=sys.stderr)
            return 2
        if not isinstance(base, dict):
            print(f"[corpus-build] {src} is not a JSON object", file=sys.stderr)
            return 2
    else:
        base = {"target": "", "generated_by": "huginn", "hosts": [], "endpoints": [], "auth_mechanisms": []}

    result, summary = build(pd, base, a.max_endpoints, a.archive_share)
    out = Path(a.out) if a.out else src
    summary["out"] = "(dry-run)" if a.dry_run else str(out)
    if not a.dry_run:
        _atomic_write(out, result)

    if a.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(f"[corpus-build] endpoints {summary['endpoints_before']} -> {summary['endpoints_after']} "
              f"(new by source {summary['new_by_source']}), "
              f"hosts {summary['hosts_before']} -> {summary['hosts_after']}, "
              f"oos_dropped {summary['oos_dropped']}, capped {summary['capped']}, archive_capped {summary['archive_capped']}, scope {summary['scope']}"
              f"{' (dry-run)' if a.dry_run else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
