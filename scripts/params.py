#!/usr/bin/env python3
"""params.py — the parameter inventory and the reflection map.

Most injection classes start from the same two questions: which parameters reach the server, and
which come back in the response (and how). The corpus (asset-map.json endpoints[], filled by
huginn/scripts/corpus-build.py from crawl, archive, JS, and spec sources) records endpoints; this
records their parameters and, for the ones it can probe safely, what the server does with them.

  inventory   Offline. Every query, path, and body parameter named by endpoints[], one row per
              (method, host, path, location, name), with the sources that named it and a concrete
              example URL. Writes $PROJECT_DIR/params.json; probe results from earlier runs are kept.

  probe       Live, read-only. For each GET query parameter with a concrete example URL:
                1. one baseline GET per endpoint (status, length)
                2. one GET with the parameter set to an inert alphanumeric canary: where it comes
                   back (HTML text, attribute, script, style, comment, JSON, plain text, a header)
                3. only when it came back: one GET whose value tags each of ' " < > ` with its own
                   canary, so each character reads as raw or encoded in the response
              Every request is scope-checked (scope.py, fail closed), paced and counted by roe.py,
              and the run spends at most --budget-share of what is left of the day's RoE budget, so
              lanes always keep the rest. Nothing is sent that a browser following a link wouldn't.

  show        The inventory and reflection map, human or --json.

The map feeds the classes that need it: reflected XSS (context + raw characters), SSTI (a reflected
parameter makes the math probe readable), SQLi and other injection (status/length change against
the baseline), and cache poisoning (cache headers on the endpoint). One summary entry per probe run
goes to intel.jsonl with reflection tags, so `playbook.py match` reads real signals; the run itself
is recorded in the activity ledger.

Usage:
  params.py inventory --project-dir DIR [--json]
  params.py probe     --project-dir DIR [--max-params N] [--budget-share F] [--supervised]
                      [--force] [-H 'Name: value']... [--timeout S] [--dry-run] [--json]
  params.py show      --project-dir DIR [--reflected] [--json]
  params.py selftest
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import egress as _egress  # noqa: E402  where target traffic leaves (the program's proxy, fail closed)
import roe as _roe  # noqa: E402
import scope as _scope  # noqa: E402
try:
    import activity as _activity
except Exception:  # noqa: BLE001 — the ledger is best-effort by contract
    _activity = None

PARAMS_FILE = "params.json"
EXIT_SCOPE_REFUSED = 3
EXIT_ROE_REFUSED = 4

# The characters whose encoding decides an injection context, each tagged with its own label so a
# response that reorders or drops some still reads unambiguously.
BREAKERS = (("a", "'"), ("b", '"'), ("c", "<"), ("d", ">"), ("e", "`"))
CACHE_HEADERS = ("age", "x-cache", "cf-cache-status", "x-cache-hits", "x-served-by", "x-varnish",
                 "akamai-cache-status", "x-proxy-cache", "cdn-cache-control")
BODY_CAP = 2 * 1024 * 1024
DEFAULT_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0.0.0 Safari/537.36")
# A path segment that is an object id, so /orders/123 and /orders/456 are one endpoint.
_ID_SEG = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|"
                     r"[0-9a-f]{16,}|[A-Za-z0-9_-]{24,})$", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Inventory ────────────────────────────────────────────────────────────────
def path_template(path: str) -> str:
    segs = []
    for s in path.split("/"):
        if s.startswith("{") and s.endswith("}"):
            segs.append(s)
        elif s and _ID_SEG.match(s):
            segs.append("{id}")
        else:
            segs.append(s)
    return "/".join(segs) or "/"


def param_id(method: str, host: str, tpl: str, where: str, name: str) -> str:
    key = "\x00".join((method, host, tpl, where, name))
    return "P-" + hashlib.sha1(key.encode()).hexdigest()[:10]


def _sources(ep: dict) -> list[str]:
    out = [str(s) for s in ep.get("sources") or [] if s]
    src = ep.get("source")
    if not out and src:
        out = [str(src).split()[0]]
    return out or ["asset-map"]


def _add_param(url: str, name: str) -> str:
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True) + [(name, "1")]
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))


def build_inventory(endpoints: list) -> list[dict]:
    rows: dict[str, dict] = {}

    def add(method, host, tpl, where, name, sources, example_url, example_value=None):
        pid = param_id(method, host, tpl, where, name)
        r = rows.get(pid)
        if r is None:
            r = rows[pid] = {"id": pid, "method": method, "host": host, "path": tpl, "in": where,
                             "name": name, "sources": [], "example_url": None}
        for s in sources:
            if s not in r["sources"]:
                r["sources"].append(s)
        if example_url and not r["example_url"]:
            r["example_url"] = example_url
            if example_value is not None:
                r["example_value"] = example_value

    for ep in endpoints or []:
        if not isinstance(ep, dict) or not ep.get("url"):
            continue
        url = str(ep["url"])
        try:
            p = urlsplit(url)
        except ValueError:
            continue
        if p.scheme not in ("http", "https") or not p.hostname:
            continue
        method = str(ep.get("method") or "GET").upper()
        host = p.hostname.lower()
        tpl = path_template(p.path or "/")
        src = _sources(ep)
        concrete = "{" not in p.path and "}" not in p.path
        query = parse_qsl(p.query, keep_blank_values=True)
        named = set()
        for k, v in query:
            if k and k not in named:
                named.add(k)
                add(method, host, tpl, "query", k, src, url if concrete else None, v)
        path_names = set(re.findall(r"\{([^}/]+)\}", p.path or ""))
        for name in ep.get("parameters") or []:
            name = str(name)
            if not name or name in named:
                continue
            named.add(name)
            # Spec entries carry names only: a name in the path template is a path parameter; the
            # rest are query parameters. On a concrete path one is probe-ready by adding it.
            if name in path_names:
                add(method, host, tpl, "path", name, src, None)
            else:
                add(method, host, tpl, "query", name, src,
                    _add_param(url, name) if concrete else None, "" if concrete else None)
        for name in ep.get("body_fields") or []:
            if name:
                add(method, host, tpl, "body", str(name), src, None)
    return sorted(rows.values(), key=lambda r: (r["host"], r["path"], r["method"], r["in"], r["name"]))


def probe_ready(row: dict) -> bool:
    """Only a GET query parameter with a concrete URL is probed: the request is the link a browser
    would follow, so it changes nothing server-side."""
    return row["method"] == "GET" and row["in"] == "query" and bool(row.get("example_url"))


def _read_json(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def load(project_dir: str) -> dict:
    doc = _read_json(os.path.join(project_dir, PARAMS_FILE))
    if not isinstance(doc, dict) or not isinstance(doc.get("params"), list):
        return {"version": 1, "params": [], "endpoints": {}}
    doc.setdefault("endpoints", {})
    return doc


def save(project_dir: str, doc: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=project_dir, prefix=".params-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, os.path.join(project_dir, PARAMS_FILE))


def inventory(project_dir: str) -> dict:
    am = _read_json(os.path.join(project_dir, "asset-map.json"))
    endpoints = am.get("endpoints") if isinstance(am, dict) else []
    rows = build_inventory(endpoints if isinstance(endpoints, list) else [])
    prev = {r["id"]: r for r in load(project_dir)["params"]}
    for r in rows:
        if prev.get(r["id"], {}).get("probe"):
            r["probe"] = prev[r["id"]]["probe"]
    doc = load(project_dir)
    doc.update({"version": 1, "generated": _now(), "params": rows})
    doc["summary"] = summarize(rows)
    save(project_dir, doc)
    return doc


def summarize(rows: list[dict]) -> dict:
    by_in: dict[str, int] = {}
    for r in rows:
        by_in[r["in"]] = by_in.get(r["in"], 0) + 1
    probed = [r for r in rows if r.get("probe")]
    reflected = [r for r in probed if r["probe"].get("reflected")]
    return {"params": len(rows), "by_location": by_in,
            "endpoints": len({(r["method"], r["host"], r["path"]) for r in rows}),
            "probe_ready": sum(1 for r in rows if probe_ready(r)),
            "probed": len(probed), "reflected": len(reflected)}


# ── Reflection analysis (pure functions; the selftest covers them) ───────────
def _last(hay: str, needle: str, end: int) -> int:
    return hay.rfind(needle, 0, end)


def html_context(body: str, i: int) -> str:
    """The HTML context of the byte at i: script, style, comment, attribute-{dq,sq,unquoted,url},
    or html-text."""
    low = body.lower()
    if _last(low, "<!--", i) > _last(low, "-->", i):
        return "comment"
    if _last(low, "<script", i) > _last(low, "</script", i) and low.find(">", _last(low, "<script", i)) < i:
        return "script"
    if _last(low, "<style", i) > _last(low, "</style", i) and low.find(">", _last(low, "<style", i)) < i:
        return "style"
    lt, gt = _last(low, "<", i), _last(low, ">", i)
    if lt > gt:
        tag = low[lt:i]
        m = re.search(r"([a-z_:][-a-z0-9_:.]*)\s*=\s*(\"|'|)([^\"'=]*)$", tag)
        if not m:
            return "attribute-name"
        quote = {"\"": "dq", "'": "sq"}.get(m.group(2), "unquoted")
        if m.group(1) in ("href", "src", "action", "formaction", "data", "poster", "srcset") \
                and not m.group(3).strip():
            return "attribute-url"
        return f"attribute-{quote}"
    return "html-text"


def body_kind(content_type: str, body: str) -> str:
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "html" in ct or "xml" in ct:
        return "html"
    head = body.lstrip()[:1]
    if head in ("{", "["):
        return "json"
    if head == "<":
        return "html"
    return "text"


def reflections(body: str, headers: dict, content_type: str, canary: str) -> list[str]:
    """Every distinct context the canary comes back in."""
    out: list[str] = []
    kind = body_kind(content_type, body)
    start = body.find(canary)
    while start != -1:
        ctx = html_context(body, start) if kind == "html" else kind
        if ctx not in out:
            out.append(ctx)
        start = body.find(canary, start + 1)
    for name, value in headers.items():
        if canary in str(value):
            ctx = f"header:{name.lower()}"
            if ctx not in out:
                out.append(ctx)
    return out


def breaker_value(canary: str) -> str:
    return "".join(f"{canary}{label}{ch}" for label, ch in BREAKERS)


def raw_breakers(body: str, headers: dict, canary: str) -> tuple[list[str], list[str]]:
    """(raw, transformed): which breaker characters came back verbatim after their tag, and which
    came back tagged but encoded, stripped, or replaced."""
    hay = body + "\n" + "\n".join(str(v) for v in headers.values())
    raw, other = [], []
    for label, ch in BREAKERS:
        tagged = f"{canary}{label}"
        if f"{tagged}{ch}" in hay:
            raw.append(ch)
        elif tagged in hay:
            other.append(ch)
    return raw, other


def cache_signals(headers: dict) -> dict:
    low = {k.lower(): str(v) for k, v in headers.items()}
    out = {h: low[h] for h in CACHE_HEADERS if h in low}
    cc = low.get("cache-control", "")
    if cc:
        out["cache-control"] = cc
    out["cacheable"] = bool(any(h in low for h in CACHE_HEADERS if h != "cdn-cache-control")
                            or re.search(r"\b(public|s-maxage)\b", cc))
    return out


def signal_tags(rows: list[dict]) -> list[str]:
    """Intel tags from the reflection map; playbook.py match reads them as signals."""
    tags: set[str] = set()
    for r in rows:
        pr = r.get("probe") or {}
        if not pr.get("reflected"):
            continue
        tags.add("reflected-param")
        for ctx in pr.get("contexts") or []:
            tags.add("reflected-" + ctx.split(":")[0].replace("attribute-", "attr-"))
        if xss_shaped(pr):
            tags.add("xss-candidate")
    return sorted(tags)


def xss_shaped(probe: dict) -> bool:
    """Reflected with the characters its context needs left raw. A lead for the XSS class oracle,
    never a finding: execution is what render-confirm.py proves."""
    raw = set(probe.get("raw_chars") or [])
    for ctx in probe.get("contexts") or []:
        if ctx in ("html-text", "comment") and "<" in raw:
            return True
        if ctx == "attribute-dq" and '"' in raw or ctx == "attribute-sq" and "'" in raw:
            return True
        if ctx in ("attribute-unquoted", "attribute-url", "script") and raw & {"'", '"', "<", "`"}:
            return True
    return False


# ── Live probing ─────────────────────────────────────────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


# One opener per distinct proxy. The proxy is re-read on every call (an env override or a roe.json
# edit lands immediately), the opener itself is reusable.
_OPENERS: dict = {}


def _opener(project_dir: str | None = None) -> urllib.request.OpenerDirector:
    """params' opener: no redirects, and the program's egress proxy when one is configured
    (GRIMNIR_PROXY wins; else the project dir's roe.json). Raises EgressError on an unusable
    configured value, so a probe refuses rather than going direct."""
    proxy = _egress.proxy(project_dir)
    if proxy not in _OPENERS:
        _OPENERS[proxy] = _egress.opener(_NoRedirect, proxy=proxy)
    return _OPENERS[proxy]


def fetch(url: str, headers: list[str], timeout: float, opener=None) -> dict:
    if opener is None:
        opener = _opener()
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", DEFAULT_UA)
    for line in headers:
        if ":" in line:
            k, v = line.split(":", 1)
            req.add_header(k.strip(), v.strip())
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"status": 0, "error": str(e)[:200], "body": "", "headers": {}, "content_type": ""}
    try:
        raw = resp.read(BODY_CAP)
    except OSError:
        raw = b""
    hdrs = dict(resp.headers.items()) if resp.headers else {}
    return {"status": resp.status if hasattr(resp, "status") else resp.code,
            "body": raw.decode("utf-8", "replace"), "headers": hdrs,
            "content_type": hdrs.get("Content-Type", "")}


def with_param(url: str, name: str, value: str) -> str:
    """The URL with `name` set to `value`, appended when the URL doesn't carry it yet."""
    p = urlsplit(url)
    q = parse_qsl(p.query, keep_blank_values=True)
    if any(k == name for k, _ in q):
        q = [(k, value if k == name else v) for k, v in q]
    else:
        q.append((name, value))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))


def new_canary() -> str:
    # Starts with letters so no parser reads it as a number; lowercase hex survives case folding.
    return "zq" + secrets.token_hex(5)


class Prober:
    """Sends the probe's requests: each one scope-checked, paced, counted, and capped."""

    def __init__(self, project_dir, roe, headers, timeout, max_requests, _sleep=time.sleep, _fetch=fetch):
        self.pd, self.roe, self.headers, self.timeout = project_dir, roe, headers, timeout
        self.max_requests, self.sent, self.throttled = max_requests, 0, 0
        self._sleep, self._fetch = _sleep, _fetch

    def get(self, url: str) -> dict | None:
        if self.sent >= self.max_requests:
            return None
        _roe.pace(self.pd, url, self.roe, _sleep=self._sleep)
        self.sent += 1
        r = self._fetch(url, self.headers, self.timeout)
        if r.get("status"):
            _roe.note_status(self.pd, url, r["status"])
        self.throttled = self.throttled + 1 if r.get("status") in _roe.THROTTLE_STATUSES else 0
        return r


def probe_param(pr: Prober, row: dict, baseline: dict) -> dict | None:
    canary = new_canary()
    r = pr.get(with_param(row["example_url"], row["name"], canary))
    if r is None:
        return None
    out = {"ts": _now(), "status": r["status"], "length": len(r["body"]),
           "baseline_status": baseline.get("status"), "baseline_length": len(baseline.get("body", "")),
           "contexts": reflections(r["body"], r["headers"], r["content_type"], canary)}
    if r.get("error"):
        out["error"] = r["error"]
    out["reflected"] = bool(out["contexts"])
    out["status_changed"] = bool(baseline.get("status")) and r["status"] != baseline["status"]
    if out["reflected"]:
        c2 = new_canary()
        r2 = pr.get(with_param(row["example_url"], row["name"], breaker_value(c2)))
        if r2 is not None:
            out["raw_chars"], out["transformed_chars"] = raw_breakers(r2["body"], r2["headers"], c2)
            out["breaker_status"] = r2["status"]
    return out


_TRACKING = re.compile(r"^(utm_\w+|fbclid|gclid|dclid|msclkid|yclid|_ga|_gl|mc_[ce]id|trk\w*|ref_?src|"
                       r"igshid|spm|scid|_hs\w+|hsa_\w+|matt_\w+)$", re.I)
_LIVE_SOURCES = ("crawl", "probe", "authed-crawl", "traffic")


def is_tracking(name: str) -> bool:
    """Analytics and ad-click parameters: the server rarely does anything with them."""
    return bool(_TRACKING.match(name or ""))


def _rank(r: dict) -> tuple:
    """Probe order: real parameters before tracking ones, live-seen before archive-only."""
    live = any(str(s).split(":")[0] in _LIVE_SOURCES for s in r.get("sources") or [])
    return (is_tracking(r["name"]), not live, r["host"], r["path"], r["name"])


def plan_probe(doc: dict, sc, force: bool, max_params: int) -> tuple[list[dict], dict]:
    """The params this run probes, and the counts of what was skipped and why. Each (host, name)
    is probed once before any repeats on other paths, so a capped run spreads across the surface
    instead of spending itself on one name that every page carries; tracking params go last."""
    skipped = {"not_probe_ready": 0, "out_of_scope": 0, "already_probed": 0, "over_cap": 0}
    eligible = []
    for r in doc["params"]:
        if not probe_ready(r):
            skipped["not_probe_ready"] += 1
        elif r.get("probe") and not force:
            skipped["already_probed"] += 1
        elif not sc.check(r["example_url"]).in_scope:
            skipped["out_of_scope"] += 1
        else:
            eligible.append(r)
    eligible.sort(key=_rank)
    seen, keyed = set(), []
    for r in eligible:
        keyed.append(((is_tracking(r["name"]), (r["host"], r["name"]) in seen), r))
        seen.add((r["host"], r["name"]))
    ordered = [r for _, r in sorted(keyed, key=lambda kr: kr[0])]   # stable: keeps _rank within
    skipped["over_cap"] = max(0, len(ordered) - max_params)
    return ordered[:max_params], skipped


def run_probe(project_dir: str, a, _sleep=time.sleep, _fetch=None) -> tuple[int, dict]:
    sc = _scope.load(project_dir)
    if not sc.ok:
        return EXIT_SCOPE_REFUSED, {"refused": "no parseable in-scope pattern (fail closed)"}
    roe = _roe.load(project_dir)
    unattended = not a.supervised
    block = _roe.global_block(project_dir, unattended, roe)
    if block:
        return EXIT_ROE_REFUSED, {"refused": block}
    if unattended and roe["automated_scanning_banned"]:
        return EXIT_ROE_REFUSED, {"refused": "roe: automated scanning banned; run --supervised"}
    if _fetch is None:
        try:
            opener = _opener(project_dir)
        except _egress.EgressError as e:
            # The program's proxy is configured but unusable: probing direct is the leak this
            # refuses, so the run stops before its first request.
            return EXIT_ROE_REFUSED, {"refused": f"egress: {e}"}

        def _fetch(url, headers, timeout):
            return fetch(url, headers, timeout, opener=opener)
    doc = load(project_dir)
    if not doc["params"]:
        doc = inventory(project_dir)
    picked, skipped = plan_probe(doc, sc, a.force, a.max_params)
    used = _roe.usage(project_dir).get("requests", 0)
    left = max(0, int(roe["daily_request_budget"]) - used)
    max_requests = int(left * max(0.0, min(1.0, a.budget_share)))
    endpoints = {}
    for r in picked:
        endpoints.setdefault(r["example_url"].split("?")[0] + "|" + r["method"], r["example_url"])
    est = len(endpoints) + len(picked)
    result = {"picked": len(picked), "endpoints": len(endpoints), "skipped": skipped,
              "max_requests": max_requests, "estimated_requests": est}
    if a.dry_run:
        result["would_probe"] = [f"{r['method']} {r['example_url']} :: {r['name']}" for r in picked]
        return 0, result
    headers = _roe.required_header_lines(project_dir) + list(a.header or [])
    pr = Prober(project_dir, roe, headers, a.timeout, max_requests, _sleep=_sleep, _fetch=_fetch)
    by_id = {r["id"]: r for r in doc["params"]}
    baselines: dict[str, dict] = {}
    done, reflected, stopped = 0, 0, ""
    for r in picked:
        key = r["example_url"].split("?")[0] + "|" + r["method"]
        if key not in baselines:
            b = pr.get(r["example_url"])
            if b is None:
                stopped = "request cap reached"
                break
            baselines[key] = b
            doc["endpoints"][f"{r['method']} {r['host']}{r['path']}"] = {
                "ts": _now(), "status": b["status"], "length": len(b["body"]),
                "content_type": b["content_type"], "cache": cache_signals(b["headers"])}
        res = probe_param(pr, r, baselines[key])
        if res is None:
            stopped = "request cap reached"
            break
        by_id[r["id"]]["probe"] = res
        done += 1
        reflected += bool(res["reflected"])
        if pr.throttled >= 3:
            stopped = "throttled 3 times in a row"
            break
    doc["summary"] = summarize(doc["params"])
    save(project_dir, doc)
    result.update({"probed": done, "reflected": reflected, "requests": pr.sent, "stopped": stopped,
                   "tags": signal_tags([by_id[r["id"]] for r in picked if by_id[r["id"]].get("probe")])})
    _record(project_dir, result)
    return 0, result


def _record(project_dir: str, result: dict) -> None:
    summary = (f"param probe: {result['probed']} params on {result['endpoints']} endpoints, "
               f"{result['reflected']} reflected, {result['requests']} requests"
               + (f" (stopped: {result['stopped']})" if result["stopped"] else ""))
    if _activity is not None:
        try:
            _activity.emit(project_dir, "recon", "huginn", summary, verdict="n/a", refs=["file:params.json"])
        except Exception:  # noqa: BLE001
            pass
    if result["reflected"]:
        argv = ["bash", os.path.join(_HERE, "intel.sh"), "add", "--project-dir", project_dir,
                "--agent", "huginn", "--type", "vulnerability_hint", "--confidence", "medium",
                "--hint", summary + "; detail in params.json (params.py show --reflected)",
                "--potential-category", "injection", "--suggested-test", "reflection-driven classes"]
        for t in result["tags"] + ["needs-specter"]:
            argv += ["--tag", t]
        try:
            import subprocess
            subprocess.run(argv, capture_output=True, timeout=30)
        except Exception:  # noqa: BLE001
            pass


# ── CLI ──────────────────────────────────────────────────────────────────────
def _abs_dir(p: str) -> str | None:
    return p if p and os.path.isabs(p) and os.path.isdir(p) else None


def cmd_inventory(a) -> int:
    pd = _abs_dir(a.project_dir)
    if not pd:
        print("params: --project-dir must be an existing absolute path", file=sys.stderr)
        return 2
    doc = inventory(pd)
    if a.json:
        print(json.dumps(doc["summary"], indent=2))
    else:
        s = doc["summary"]
        locs = ", ".join(f"{k} {v}" for k, v in sorted(s["by_location"].items())) or "none"
        print(f"{s['params']} params on {s['endpoints']} endpoints ({locs}); "
              f"{s['probe_ready']} probe-ready; {s['probed']} probed, {s['reflected']} reflected")
    return 0


def cmd_probe(a) -> int:
    pd = _abs_dir(a.project_dir)
    if not pd:
        print("params: --project-dir must be an existing absolute path", file=sys.stderr)
        return 2
    rc, res = run_probe(pd, a)
    if a.json:
        print(json.dumps(res, indent=2))
    elif "refused" in res:
        print(f"REFUSED: {res['refused']}", file=sys.stderr)
    elif a.dry_run:
        print(f"[dry-run] {res['picked']} params on {res['endpoints']} endpoints, "
              f"~{res['estimated_requests']} requests (+1 per reflected param); cap {res['max_requests']}")
        for line in res["would_probe"]:
            print("  " + line)
    else:
        print(f"probed {res['probed']} params, {res['reflected']} reflected, {res['requests']} requests"
              + (f"; stopped: {res['stopped']}" if res["stopped"] else "")
              + (f"; tags: {', '.join(res['tags'])}" if res["tags"] else ""))
    return rc


def cmd_show(a) -> int:
    pd = _abs_dir(a.project_dir)
    if not pd:
        print("params: --project-dir must be an existing absolute path", file=sys.stderr)
        return 2
    doc = load(pd)
    rows = [r for r in doc["params"] if not a.reflected or (r.get("probe") or {}).get("reflected")]
    if a.json:
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        pr = r.get("probe") or {}
        note = ""
        if pr:
            note = ("reflected " + ",".join(pr["contexts"]) + (f" raw {''.join(pr.get('raw_chars') or [])}"
                    if pr.get("raw_chars") else "")) if pr.get("reflected") else f"not reflected ({pr.get('status')})"
        print(f"{r['id']}  {r['method']:6} {r['host']}{r['path']}  {r['in']}:{r['name']}  {note}")
    return 0


def cmd_selftest(_a) -> int:
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        fails += 0 if cond else 1

    rows = build_inventory([
        {"url": "https://a.example.com/s?q=x&page=2", "method": "GET", "sources": ["crawl"]},
        {"url": "https://a.example.com/s?q=y", "method": "GET", "sources": ["archive"]},
        {"url": "https://a.example.com/v1/orders/{order_id}", "method": "PUT",
         "parameters": ["order_id", "expand"], "body_fields": ["note"]},
        {"url": "https://a.example.com/u/12345/view?tab=a", "method": "GET"},
    ])
    names = {(r["in"], r["name"]) for r in rows}
    check("query params from urls", ("query", "q") in names and ("query", "page") in names)
    check("spec path vs query split", ("path", "order_id") in names and ("query", "expand") in names)
    check("body fields", ("body", "note") in names)
    q = next(r for r in rows if r["name"] == "q")
    check("one row per param, sources merged", q["sources"] == ["crawl", "archive"])
    check("id segments templatize", any(r["path"] == "/u/{id}/view" for r in rows))
    check("only concrete GET query params are probe-ready",
          probe_ready(q) and not probe_ready(next(r for r in rows if r["name"] == "expand")))
    spec = build_inventory([{"url": "https://a.example.com/v1/search", "method": "GET",
                             "parameters": ["term"]}])
    check("a spec query param on a concrete path gets an example url",
          probe_ready(spec[0]) and spec[0]["example_url"] == "https://a.example.com/v1/search?term=1")

    c = "zqabc123"
    html = (f'<html><!-- {c} --><a href="{c}">x</a><input value="{c}"><input value=\'{c}\'>'
            f'<div title={c}>{c}</div><script>var a="{c}";</script><style>.{c}{{}}</style></html>')
    ctx = reflections(html, {"Location": f"/r?{c}"}, "text/html", c)
    for want in ("comment", "attribute-url", "attribute-dq", "attribute-sq", "attribute-unquoted",
                 "html-text", "script", "style", "header:location"):
        check(f"context {want}", want in ctx)
    check("json context", reflections(f'{{"q":"{c}"}}', {}, "application/json", c) == ["json"])
    check("no reflection", reflections("<p>nothing</p>", {}, "text/html", c) == [])
    bv = breaker_value(c)
    raw, other = raw_breakers(f"{c}a&#39;{c}b&quot;{c}c<{c}d>{c}e`", {}, c)
    check("breaker value tags each char", all(f"{c}{l}{ch}" in bv for l, ch in BREAKERS))
    check("raw vs encoded breakers", raw == ["<", ">", "`"] and other == ["'", '"'])
    check("xss-shaped needs the context's char raw",
          xss_shaped({"contexts": ["html-text"], "raw_chars": ["<"]})
          and not xss_shaped({"contexts": ["html-text"], "raw_chars": ['"']})
          and xss_shaped({"contexts": ["attribute-dq"], "raw_chars": ['"']}))
    check("cache signals", cache_signals({"Age": "30", "Cache-Control": "public, max-age=60"})["cacheable"]
          and not cache_signals({"Cache-Control": "no-store"})["cacheable"])
    class _All:
        def check(self, _u):
            return type("V", (), {"in_scope": True})()
    plan_doc = {"params": build_inventory([
        {"url": "https://h.example.com/a?utm_source=x&q=1", "method": "GET", "sources": ["archive"]},
        {"url": "https://h.example.com/b?q=2", "method": "GET", "sources": ["archive"]},
        {"url": "https://h.example.com/c?id=3", "method": "GET", "sources": ["crawl"]}])}
    picked, sk = plan_probe(plan_doc, _All(), False, 3)
    check("probe order: live first, repeats and tracking last, cap counted",
          [(r["path"], r["name"]) for r in picked] == [("/c", "id"), ("/a", "q"), ("/b", "q")]
          and sk["over_cap"] == 1)
    check("with_param replaces only that param",
          with_param("https://h/s?q=1&p=2", "q", "zq") == "https://h/s?q=zq&p=2")
    print(f"\n{'ALL CHECKS PASSED' if not fails else f'{fails} FAILED'}")
    return 1 if fails else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="params.py", description="parameter inventory and reflection map")
    sub = p.add_subparsers(dest="cmd", required=True)
    pi = sub.add_parser("inventory", help="build params.json from asset-map endpoints[] (offline)")
    pi.add_argument("--project-dir", required=True)
    pi.add_argument("--json", action="store_true")
    pp = sub.add_parser("probe", help="read-only reflection probe of GET query params (live)")
    pp.add_argument("--project-dir", required=True)
    pp.add_argument("--max-params", type=int, default=40, help="params per run (default 40)")
    pp.add_argument("--budget-share", type=float, default=0.5,
                    help="max share of the remaining daily RoE budget this run may spend (default 0.5)")
    pp.add_argument("--supervised", action="store_true",
                    help="an operator is running this: lifts the auto-fire switch and the scanning ban")
    pp.add_argument("--force", action="store_true", help="re-probe params that already have a result")
    pp.add_argument("-H", "--header", action="append", help="extra request header (repeatable)")
    pp.add_argument("--timeout", type=float, default=15.0)
    pp.add_argument("--dry-run", action="store_true")
    pp.add_argument("--json", action="store_true")
    ps = sub.add_parser("show", help="print the inventory and reflection map")
    ps.add_argument("--project-dir", required=True)
    ps.add_argument("--reflected", action="store_true")
    ps.add_argument("--json", action="store_true")
    sub.add_parser("selftest")
    a = p.parse_args(argv)
    return {"inventory": cmd_inventory, "probe": cmd_probe, "show": cmd_show,
            "selftest": cmd_selftest}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
