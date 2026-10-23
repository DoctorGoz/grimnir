#!/usr/bin/env python3
"""authed-crawl.py — turn ONE authenticated session into a request corpus in asset-map endpoints[].

WHY IT EXISTS
    Go-tools recon produces a STATIC, unauthenticated asset-map — endpoints[] is empty, so lane synthesis
    and downstream planning have no real routes/params/bodies to work from and the pipeline parks at TEST. This
    crawler loads ONE captured authenticated session (the only manual step), exercises the logged-in app
    READ-ONLY within scope, and writes what it observes — method, params, body-field NAMES, status,
    auth-required — into asset-map endpoints[]. That is the corpus downstream analysis mines and
    downstream planning (③) ranks. One login per program (two for cross-tenant BOLA), then hands-off.

SESSION SOURCE IS PLUGGABLE  (--session-source caido|login, default caido)
    Both adapters produce ONE normalized bundle {cookies, origins, auth_headers, refresh}; the pure core
    is source-agnostic. `caido` consumes a Caido-captured authed request (cookies/headers exported via
    the caido-mode playbook). `login` uses a headed Playwright login you complete once, saving Playwright
    storageState. Capture keeps the FULL auth material (refresh_token/endpoint/cookies) so refresh is
    generic (classify_refresh): oauth-refresh, cookie-warm (kept alive by the crawl itself), or re-login.

SAFETY (the crawl runs unattended against a live target — these are gates, not preferences)
    Read-only: only GET/HEAD/OPTIONS navigate; mutating verbs and logout/dangerous links are refused
    (is_safe_nav) and the browser driver ALSO route-aborts a non-safe request as defense in depth. In
    scope only: host_allowed blocks off-scope + third-party egress (the out-of-scope-app trap). Bounded:
    max pages/depth/time. Own-account only. The LOCAL asset-map keeps full fidelity (it is the operator's
    engagement dir); masking to the cloud model happens later, in downstream analysis, never here.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from urllib.parse import urlparse, parse_qsl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import egress as _egress  # noqa: E402 — the program's egress proxy: the browser rides it or refuses
import graphql_ops as _gq  # noqa: E402 — the shared GraphQL read/write classifier (stdlib-only)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# URL path/name fragments that must never be navigated/clicked: they end or mutate the session/account.
_DANGEROUS_PATH_RE = re.compile(
    r"(?:^|[/_.-])(?:logout|signout|sign-out|log-out|delete|remove|revoke|deactivate|close-account|"
    r"terminate|reset|purge|destroy|disable)(?:$|[/_.?-])", re.IGNORECASE)
# Element-semantics mirror of _DANGEROUS_PATH_RE: an interactive element whose visible text / aria-label
# reads as one of these actions is never clicked by --spider (a click would fire a state-changing request).
_DANGEROUS_LABEL_RE = re.compile(
    r"(?:delete|remove|pay\b|payment|purchase|checkout|check\s*out|submit|\bsend\b|invite|confirm|"
    r"deactivate|log\s*out|logout|sign\s*out|signout|revoke|cancel|unsubscribe|\bbuy\b|place\s*order|"
    # Moderation and membership actions, for crawls run as a privileged account. Whole words, so the
    # list tabs ("Approved users", "Banned", "Muted") stay clickable: those are the privileged reads.
    r"\b(?:approve|ban|unban|mute|unmute|leave|lock|unlock|block|report|kick|demote|promote|archive)\b)",
    re.IGNORECASE)


# ── scope (pure) ───────────────────────────────────────────────────────────────
def host_allowed(host: str, allow: list, deny: list[str]) -> bool:
    """host is in scope iff it matches an allow pattern and no deny pattern. A pattern is an exact host,
    a `*.suffix` wildcard (which also matches the bare apex), or the engagement's scope.Scope (its own
    exclusions included). Empty allow = nothing in scope (fail closed) — the caller must derive allow
    from scope/the start hosts, never crawl the open web."""
    host = (host or "").lower().strip()
    if not host:
        return False

    def _match(pat) -> bool:
        if hasattr(pat, "check"):   # scope.Scope
            return pat.check(f"https://{host}/").in_scope
        pat = pat.lower().strip()
        if pat.startswith("*."):
            base = pat[2:]
            return host == base or host.endswith("." + base)
        return host == pat

    if not any(_match(p) for p in allow):
        return False
    return not any(_match(p) for p in deny)


def url_allowed(url: str, allow: list, deny: list[str], gate=()) -> bool:
    """host_allowed, then the full URL against every engagement scope in play: a scope.Scope in allow,
    plus `gate` (the engagement scope when --allow-host narrowed the hosts). host_allowed only sees
    the host, so without this a path exclusion on an in-scope host (a banned feature's API route)
    would still egress as an SPA XHR."""
    host = urlparse(url or "").netloc.split(":")[0]
    if not host_allowed(host, allow, deny):
        return False
    scopes = [p for p in allow if hasattr(p, "check")] + list(gate)
    return all(sc.check(url).in_scope for sc in scopes)


# ── navigation safety (pure) ───────────────────────────────────────────────────
def is_safe_nav(method: str, url: str) -> bool:
    """True only for a read-only navigation to a non-dangerous path. A mutating verb or a
    logout/delete-shaped URL is refused so the crawl never changes state or ends its own session."""
    if (method or "GET").upper() not in SAFE_METHODS:
        return False
    path = urlparse(url or "").path or ""
    return not _DANGEROUS_PATH_RE.search(path)


# ── interaction safety (pure; the --spider click gate) ───────────────────────────
def is_safe_interaction(label: str) -> bool:
    """True if an interactive element is safe to CLICK. Element-semantics mirror of is_safe_nav: an
    element whose visible text / aria-label / name reads as a mutating or destructive action (delete,
    pay, submit, invite, logout, ...) is refused, so a click never fires a state-changing request.
    Over-skipping is the safe failure — when a label is ambiguous we do not click."""
    return not _DANGEROUS_LABEL_RE.search(label or "")


def would_submit_form(tag: str, el_type: str, in_form: bool) -> bool:
    """True if clicking this element would submit an HTML form. A type=submit/image control always
    submits; a bare <button>/<input> INSIDE a form defaults to type=submit. --spider categorically
    refuses form auto-submission, so these are never clicked (independent of the label)."""
    tag = (tag or "").lower()
    t = (el_type or "").lower()
    if t in ("submit", "image"):
        return True
    if in_form and tag in ("button", "input") and t == "":
        return True
    return False


def spider_should_click(tag: str, role: str, el_type: str, in_form: bool, label: str) -> bool:
    """Pure gate for a candidate interactive element (--spider). Click only when the click would NOT
    submit a form AND the label is non-destructive. This is the DOM-interaction layer of the same
    read-only guarantee is_safe_nav/classify_route enforce at the request layer."""
    if would_submit_form(tag, el_type, in_form):
        return False
    return is_safe_interaction(label)


STATIC_CACHE_TYPES = ("script", "stylesheet")

# history.pushState + popstate: what a client-side router (React Router, Vue Router, ...) listens to.
_SPA_NAV_JS = """u => { history.pushState({}, '', u);
  window.dispatchEvent(new PopStateEvent('popstate', {state: {}})); }"""


def spa_route_change(current_url: str, url: str) -> bool:
    """True when url can be reached as an in-app route change from current_url: same scheme and host
    (pushState cannot cross origins) and a real page is loaded (not about:blank or an error page)."""
    a, b = urlparse(current_url or ""), urlparse(url or "")
    return bool(a.scheme in ("http", "https") and a.netloc and (a.scheme, a.netloc) == (b.scheme, b.netloc))


def cacheable_headers(headers: dict) -> dict:
    """Response headers safe to replay with a decoded body: the body Playwright hands back is already
    decompressed and its length may differ, so the encoding and length headers must not be replayed."""
    drop = {"content-encoding", "content-length", "transfer-encoding", "set-cookie"}
    return {k: v for k, v in (headers or {}).items() if k.lower() not in drop}


def classify_route(method: str, url: str, allow: list[str], deny: list[str], gate=()) -> str:
    """Pure routing decision for the driver's request interceptor: 'continue' only for a safe read-only
    nav to an in-scope host; otherwise 'abort'. A mutating verb, an off-scope host, or a dangerous path
    is aborted so it never egresses — the server never sees a click-triggered POST/DELETE."""
    if (method or "GET").upper() not in SAFE_METHODS \
            or not url_allowed(url, allow, deny, gate) \
            or not is_safe_nav(method, url):
        return "abort"
    return "continue"


def graphql_read_route(method: str, url: str, body, allow: list[str], deny: list[str], gate=()) -> bool:
    """True for an in-scope POST whose body is a GraphQL read (graphql_ops.is_read: query text that is a
    query, or a name-only operation with a read shape and no write word). The driver lets these out
    only under --allow-graphql-reads; everything else that mutates stays aborted."""
    return ((method or "").upper() == "POST" and url_allowed(url, allow, deny, gate)
            and not _DANGEROUS_PATH_RE.search(urlparse(url or "").path or "")
            and _gq.is_graphql(url, body) and _gq.is_read(body))


_BLOCKED_RESOURCE_TYPES = {"image", "media", "font"}


def should_block_resource(resource_type: str) -> bool:
    """Heavy static sub-resources (images/media/fonts) are never API endpoints and are the bulk of a
    page's request volume. The driver aborts them so the crawl stays LIGHT on the target (a strict-RoE
    program forbids volumetric load) and the corpus stays free of asset-URL noise. Documents, scripts,
    stylesheets, and XHR/fetch are always kept — those carry the endpoints we are here to map."""
    return (resource_type or "").lower() in _BLOCKED_RESOURCE_TYPES


def canonical(url: str) -> str:
    """A frontier/dedup key: scheme+host+path with the fragment dropped and the query reduced to its
    SORTED KEY SET (so `?id=1` and `?id=2` collapse to one page, but `?a=` vs `?a=&b=` stay distinct)."""
    p = urlparse(url or "")
    keys = ",".join(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
    base = f"{p.scheme}://{p.netloc}{p.path or '/'}"
    return f"{base}?{keys}" if keys else base


def should_enqueue(url: str, seen: set[str], depth: int, max_depth: int,
                   allow: list[str], deny: list[str], gate=()) -> bool:
    if depth > max_depth:
        return False
    if not is_safe_nav("GET", url):
        return False
    if not url_allowed(url, allow, deny, gate):
        return False
    return canonical(url) not in seen


# ── request -> endpoint (pure) ─────────────────────────────────────────────────
def extract_body_field_names(content_type: str, body: str) -> list[str]:
    """Field NAMES from a request body — JSON object keys (top level + one nested level as parent.child)
    or form keys. VALUES are discarded; only names are kept (they are what flags a privilege field to
    downstream analysis). Best-effort: an unparseable body yields []."""
    ct = (content_type or "").lower()
    names: list[str] = []
    if not body:
        return names
    if "json" in ct or body.lstrip().startswith("{"):
        try:
            obj = json.loads(body)
        except (ValueError, TypeError):
            return names
        if isinstance(obj, dict):
            for k, v in obj.items():
                names.append(str(k))
                if isinstance(v, dict):
                    names += [f"{k}.{sk}" for sk in list(v.keys())[:20]]
    elif "form-urlencoded" in ct or ("=" in body and "&" in body) or re.match(r"^[^=&]+=[^=&]*$", body):
        names = [k for k, _ in parse_qsl(body, keep_blank_values=True)]
    # dedup, preserve order
    out, seen = [], set()
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out[:40]


def query_param_names(url: str) -> list[str]:
    return [k for k, _ in parse_qsl(urlparse(url or "").query, keep_blank_values=True)]


def request_to_endpoint(method: str, url: str, sent_auth: bool, status,
                        content_type: str = "", body: str = "",
                        observed_not_executed: bool = False) -> dict:
    """One asset-map endpoints[] record from an observed request. Stores the REAL url locally (the
    engagement dir keeps full fidelity; downstream analysis masks before anything reaches the cloud).
    auth_required is inferred: a request we sent auth on that returns 401/403 without it, or any
    authed request to a non-public path — conservatively True when we were authenticated.

    observed_not_executed=True marks a state-changing request that --spider saw a click fire but that
    the route interceptor ABORTED before egress (so it has no response/status). lane synthesis learns the
    mutating endpoint exists and parks it; it is never a request we actually sent."""
    params = sorted(set(query_param_names(url)))
    body_fields = extract_body_field_names(content_type, body)
    rec = {
        "url": url,
        "method": (method or "GET").upper(),
        "source": "authed-crawl",
        "auth_required": bool(sent_auth),
        "tags": [],
    }
    if params:
        rec["parameters"] = params
    if body_fields:
        rec["body_fields"] = body_fields
    if isinstance(status, int):
        rec["status_code"] = status
    if body and _gq.is_graphql(url, body):
        ops = sorted(set(n for n in _gq.names(body) if n))
        if ops:   # one endpoint carries many operations; the ones never sent are kept apart
            rec["graphql_ops_not_executed" if observed_not_executed else "graphql_ops"] = ops
    if observed_not_executed:
        rec["observed_not_executed"] = True
        rec["tags"] = sorted(set(rec["tags"]) | {"observed-not-executed", "state-changing"})
    elif sent_auth:
        # A request our logged-in session actually sent: the same provenance caido-export gives the
        # proxy's authenticated traffic, so the crawl's reads feed authn lanes (lane synthesis keeps only
        # the 2xx GETs). An aborted, never-sent request is not traffic.
        rec["tags"] = sorted(set(rec["tags"]) | {"authed-traffic"})
    return rec


def merge_endpoints(existing: list[dict], crawled: list[dict]) -> list[dict]:
    """Merge crawled records into any existing endpoints[], keyed by (METHOD, canonical url). Unions
    parameters + body_fields, keeps the last-seen status. Non-crawl entries are preserved as-is."""
    def key(e: dict) -> tuple:
        return (str(e.get("method", "GET")).upper(), canonical(str(e.get("url", ""))))

    merged: dict[tuple, dict] = {}
    order: list[tuple] = []
    for e in (existing or []) + (crawled or []):
        if not isinstance(e, dict) or not e.get("url"):
            continue
        k = key(e)
        if k not in merged:
            merged[k] = dict(e)
            order.append(k)
        else:
            row = merged[k]
            for field in ("parameters", "body_fields", "tags", "graphql_ops", "graphql_ops_not_executed"):
                if e.get(field):
                    row[field] = sorted(set(row.get(field, [])) | set(e[field]))
            if isinstance(e.get("status_code"), int):
                row["status_code"] = e["status_code"]
            if e.get("auth_required"):
                row["auth_required"] = True
            if e.get("source") == "authed-crawl":
                row["source"] = "authed-crawl"
    return [merged[k] for k in order]


# ── session normalization + refresh (pure) ─────────────────────────────────────
# Client-hint / locale headers that identify the BROWSER (not the request). Pinning these to the values
# from the captured request makes the automated context present as the SAME browser that produced the
# real (and separately replayed) traffic. The User-Agent is carried separately (it must go through the
# context user_agent so navigator.userAgent matches too). Per-request headers (accept, sec-fetch-*,
# accept-encoding) are intentionally NOT pinned — the browser sets those correctly per resource.
_FINGERPRINT_HEADER_KEYS = (
    "accept-language", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-ch-ua-platform-version", "sec-ch-ua-arch", "sec-ch-ua-bitness", "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list", "sec-ch-ua-model", "sec-ch-ua-wow64")


def select_fingerprint_headers(headers: dict) -> dict:
    """From a captured real request's headers, keep the browser-identity client-hint + locale headers so an
    automated context can present as the SAME browser that produced the captured/replayed traffic. This is
    fingerprint PARITY for an own-account, read-only, in-scope, throttled self-crawl — not a control bypass:
    every other safeguard (route-abort, scope, interaction filter, throttle) is unchanged. User-Agent is
    handled separately (via context user_agent); auth and per-request headers are not returned here."""
    low = {str(k).lower(): v for k, v in (headers or {}).items()}
    return {k: low[k] for k in _FINGERPRINT_HEADER_KEYS if low.get(k)}


def normalize_session(raw: dict) -> dict:
    """Coerce a caido export OR a Playwright storageState into one bundle: {cookies[], origins[],
    auth_headers{}, refresh{}, user_agent, fingerprint_headers{}}. Tolerant of both shapes so the two
    --session-source adapters converge."""
    raw = raw or {}
    cookies = raw.get("cookies") or []
    origins = raw.get("origins") or raw.get("localStorage") or []
    headers = raw.get("auth_headers") or raw.get("headers") or {}
    # keep only auth-bearing headers (never a whole captured header set with UA/etc noise)
    auth_headers = {k: v for k, v in headers.items()
                    if k.lower() in ("authorization", "cookie", "x-csrf-token", "x-xsrf-token",
                                     "x-api-key", "x-auth-token")}
    refresh = raw.get("refresh") or {}
    return {"cookies": cookies, "origins": origins,
            "auth_headers": auth_headers, "refresh": refresh,
            "user_agent": raw.get("user_agent") or "",
            "fingerprint_headers": raw.get("fingerprint_headers") or {}}


def classify_refresh(session: dict) -> str:
    """How this session can be kept alive without a human: oauth-refresh (a refresh_token + token
    endpoint were captured) > cookie-warm (a session cookie the crawl's own traffic keeps alive) >
    re-login (neither — the daily digest must ask for a fresh login). Drives the generic refresh layer."""
    refresh = (session or {}).get("refresh") or {}
    if refresh.get("refresh_token") and refresh.get("token_endpoint"):
        return "oauth-refresh"
    if (session or {}).get("cookies"):
        return "cookie-warm"
    return "re-login"


# ── asset-map I/O ──────────────────────────────────────────────────────────────
def write_endpoints(project_dir: str, crawled: list[dict]) -> int:
    """Merge crawled endpoints into asset-map.json (preserving hosts/technologies/etc), atomically.
    Returns the endpoint count after merge. Creates a minimal asset-map if none exists."""
    path = os.path.join(project_dir, "asset-map.json")
    data: dict = {}
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("target", "")
    data.setdefault("generated_by", "huginn")
    data["endpoints"] = merge_endpoints(data.get("endpoints") or [], crawled)
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".asset-map.", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return len(data["endpoints"])


def load_session_bundle(source: str, session_file: str) -> dict:
    """caido|login both hand us a JSON file on disk (the caido playbook writes one; the login flow saves
    Playwright storageState). We normalize either shape. The difference between the sources is only WHERE
    the file came from — the login flow is driven live in _drive_browser, caido is produced out of band."""
    if not session_file or not os.path.isfile(session_file):
        raise FileNotFoundError(f"session file not found: {session_file}")
    with open(session_file, encoding="utf-8") as fh:
        return normalize_session(json.load(fh))


# ── live browser driver (I/O; the only browser-touching code) ──────────────────
# Enumerate candidate interactive elements and tag each with a stable, re-queryable signature attribute.
# Read-only wrt the server (a client-side setAttribute only); returns the metadata spider_should_click
# needs (tag/role/type/in-form/label) plus a selector to re-grab the element after the DOM settles.
_INTERACTIVE_ENUM_JS = r"""() => {
  const sel = 'button, [role=button], [role=tab], [role=menuitem], [role=link], [onclick]';
  const nodes = Array.from(document.querySelectorAll(sel));
  let extra = [];
  try {
    extra = Array.from(document.querySelectorAll('div,span,li')).slice(0, 2000)
      .filter(e => { try { return getComputedStyle(e).cursor === 'pointer'; } catch (_) { return false; } })
      .slice(0, 50);
  } catch (_) {}
  const all = nodes.concat(extra);
  const out = [];
  let i = 0;
  for (const e of all) {
    if (i >= 60) break;
    const tag = e.tagName.toLowerCase();
    const type = (e.getAttribute('type') || '').toLowerCase();
    const role = (e.getAttribute('role') || '').toLowerCase();
    const inForm = !!e.closest('form');
    const label = (e.innerText || e.getAttribute('aria-label') || e.getAttribute('title')
                   || e.getAttribute('name') || '').trim().slice(0, 80);
    e.setAttribute('data-grimnir-sig', String(i));
    out.push({tag, type, role, inForm, label, sig: i, selector: '[data-grimnir-sig="' + i + '"]'});
    i++;
  }
  return out;
}"""


def _spider_interact(page, allow, deny, depth, max_depth, frontier, seen, clicked_sigs,
                     max_clicks: int = 40, gate=()):
    """--spider step: enumerate safe interactive elements on the current page, click the ones
    spider_should_click approves (de-duped by element signature + current route), and enqueue any new
    in-scope route a click navigates to. Read-only by construction: dangerous-labelled and form-submitting
    elements are skipped HERE, and the route interceptor aborts (and records) any mutating request a click
    fires, so the crawl never changes server state. Best-effort throughout — a click that errors or
    navigates away must not kill the crawl."""
    try:
        start_url = page.url
        cands = page.evaluate(_INTERACTIVE_ENUM_JS)
    except Exception:  # noqa: BLE001
        return
    clicks = 0
    for c in cands or []:
        if clicks >= max_clicks:
            break
        sig = (start_url, c.get("tag"), c.get("sig"), c.get("label"))
        if sig in clicked_sigs:
            continue
        clicked_sigs.add(sig)
        if not spider_should_click(c.get("tag"), c.get("role"), c.get("type"),
                                   c.get("inForm"), c.get("label")):
            continue
        clicks += 1
        try:
            el = page.query_selector(c["selector"])
            if not el:
                continue
            el.click(timeout=2000, no_wait_after=True)   # no_wait_after: never block on navigation
            page.wait_for_timeout(250)                   # let a click-driven XHR/route change settle
        except Exception:  # noqa: BLE001
            pass
        try:
            new_url = page.url
        except Exception:  # noqa: BLE001
            new_url = start_url
        if new_url and new_url != start_url \
                and should_enqueue(new_url, seen, depth + 1, max_depth, allow, deny, gate):
            frontier.append((new_url, depth + 1))
        # return to the page being spidered so the next click starts from a known DOM; bail if it fails
        if page.url != start_url:
            try:
                page.goto(start_url, wait_until="domcontentloaded", timeout=15000)
            except Exception:  # noqa: BLE001
                break


def _drive_browser(start_urls, session, allow, deny, max_pages, max_depth, headless, timeout_s,
                   spider=False, proxy=None, min_req_interval_ms=0, settle_ms=2000,
                   allow_graphql_reads=False, gate=(), proxy_spki="", spa_nav=False):
    """Bounded, read-only Playwright crawl. Loads the session, BFS-navigates in-scope safe pages,
    captures every request/response into endpoint records. Route-aborts non-safe methods + off-scope
    hosts as defense in depth, and drops heavy static assets (images/media/fonts). With spider=True,
    ALSO clicks safe interactive elements on each page (buttons/tabs/menus — not just <a href>) to
    surface interaction-gated SPA XHR/fetch endpoints, still read-only (see _spider_interact). proxy
    routes the browser through an intercepting proxy (e.g. Caido) with its CA trusted; min_req_interval_ms
    paces outbound requests so a strict-RoE target sees only light load. Requires playwright + a browser
    binary; imported lazily so the pure core (and its tests) never need them. Returns endpoint records."""
    from playwright.sync_api import sync_playwright  # lazy: only the live path needs it

    captured: dict[tuple, dict] = {}
    seen: set[str] = set()
    clicked_sigs: set[tuple] = set()
    frontier = [(u, 0) for u in start_urls]
    deadline = time.monotonic() + timeout_s

    def _union_ops(rec, prev):
        for f in ("graphql_ops", "graphql_ops_not_executed"):
            merged = sorted(set(rec.get(f, [])) | set((prev or {}).get(f, [])))
            if merged:
                rec[f] = merged
        return rec

    def _record(method, url, sent_auth, status, ctype, body):
        rec = request_to_endpoint(method, url, sent_auth, status, ctype, body)
        key = (rec["method"], canonical(url))
        captured[key] = _union_ops(rec, captured.get(key))   # executed: replaces an aborted record

    min_interval = max(0, min_req_interval_ms) / 1000.0
    _last_req = [0.0]
    # Routing turns Chromium's HTTP cache off, so a throttled crawl of a script-heavy SPA would spend
    # most of its request budget re-downloading the same bundles on every page. Keep each in-scope
    # script/stylesheet the first time it arrives and answer repeats from memory, off the network.
    static_cache: dict[str, dict] = {}

    ua = (session.get("user_agent") or "").strip() or None
    fp_headers = session.get("fingerprint_headers") or {}

    with sync_playwright() as pw:
        # Present as the real authenticated browser that produced the captured/replayed traffic: drop the
        # navigator.webdriver automation tell and (below) pin the captured UA + client-hint headers. This
        # is fingerprint parity for an own-account, read-only, in-scope, throttled self-crawl replaying
        # legitimate traffic — NOT a control bypass. Every other safeguard is unchanged.
        launch_args = ["--disable-blink-features=AutomationControlled"]
        launch_kwargs = {"headless": headless, "args": launch_args}
        if proxy:
            launch_kwargs["proxy"] = {"server": proxy}
            # An intercepting proxy (Caido) does TLS MITM with its own CA. Context-level
            # ignore_https_errors alone does NOT suppress it in headless chromium (navigation loops with
            # ERR_TOO_MANY_RETRIES); the launch arg is required to actually trust the MITM cert.
            # With proxy_spki the proxy's keys are pinned instead: its certs then verify cleanly, and
            # Chromium caches again (it caches nothing from a page with a certificate error, so a
            # throttled crawl would re-download every script on every page).
            launch_args.append(f"--ignore-certificate-errors-spki-list={proxy_spki}" if proxy_spki
                               else "--ignore-certificate-errors")
        ctx = pw.chromium.launch(**launch_kwargs).new_context(
            storage_state={"cookies": session.get("cookies", []),
                           "origins": session.get("origins", [])},
            ignore_https_errors=bool(proxy),   # trust an intercepting proxy's CA (also for route.fetch)
            user_agent=ua)                     # match the captured browser's UA (navigator + header)
        ctx.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        ctx.set_extra_http_headers({**(session.get("auth_headers") or {}), **fp_headers})

        def _route(route):
            req = route.request
            if should_block_resource(req.resource_type):
                return route.abort()           # drop heavy static assets: keep the crawl light + corpus clean
            if req.method.upper() == "GET" and req.url in static_cache:
                return route.fulfill(**static_cache[req.url])
            if classify_route(req.method, req.url, allow, deny, gate) == "continue" or (
                    allow_graphql_reads and graphql_read_route(req.method, req.url, req.post_data, allow, deny,
                                                               gate)):
                if min_interval > 0:
                    gap = _last_req[0] + min_interval - time.monotonic()
                    if gap > 0:
                        time.sleep(gap)        # RoE throttle: pace outbound requests to the target
                    _last_req[0] = time.monotonic()
                if req.resource_type in STATIC_CACHE_TYPES and req.method.upper() == "GET":
                    # Read the body now: a response event is handled late under the throttle, after the
                    # page has moved on and the body is gone, so the cache would keep missing.
                    try:
                        resp = route.fetch()
                        body = resp.body()
                    except Exception:  # noqa: BLE001 — fall back to an uncached pass-through
                        return route.continue_()
                    if resp.status == 200:
                        static_cache[req.url] = {"status": 200, "body": body,
                                                 "headers": cacheable_headers(resp.headers)}
                    return route.fulfill(response=resp, body=body)
                return route.continue_()
            # Aborting (defense in depth: never let a mutating/off-scope req out). If this is an IN-SCOPE
            # state-changing request — e.g. a --spider click firing a POST — record its SHAPE as
            # observed-not-executed BEFORE the abort: the server never sees it, but lane synthesis learns the
            # mutating endpoint exists (and parks it). Off-scope aborts are third-party noise, not recorded.
            if url_allowed(req.url, allow, deny, gate) and not is_safe_nav(req.method, req.url):
                sent_auth = bool(req.headers.get("authorization") or req.headers.get("cookie"))
                rec = request_to_endpoint(req.method, req.url, sent_auth, None,
                                          req.headers.get("content-type", ""), req.post_data or "",
                                          observed_not_executed=True)
                key = (rec["method"], canonical(req.url))
                prev = captured.get(key)
                if prev is None or prev.get("observed_not_executed"):   # never clobber an executed record
                    captured[key] = _union_ops(rec, prev)
                else:
                    _union_ops(prev, rec)    # keep the executed record; add the unsent operation names
            return route.abort()

        ctx.route("**/*", _route)

        def _on_response(resp):
            req = resp.request
            sent_auth = bool(req.headers.get("authorization") or req.headers.get("cookie"))
            body = ""
            if req.post_data and (req.method.upper() in SAFE_METHODS or (
                    allow_graphql_reads and graphql_read_route(req.method, req.url, req.post_data, allow, deny,
                                                               gate))):
                body = req.post_data
            _record(req.method, req.url, sent_auth, resp.status,
                    req.headers.get("content-type", ""), body)

        ctx.on("response", _on_response)
        page = ctx.new_page()
        pages_done = 0
        while frontier and pages_done < max_pages and time.monotonic() < deadline:
            url, depth = frontier.pop(0)
            if not should_enqueue(url, seen, depth, max_depth, allow, deny, gate):
                continue
            seen.add(canonical(url))
            try:
                if spa_nav and pages_done and spa_route_change(page.url, url):
                    # In-app route change: the SPA renders the route from its own router without a reload,
                    # so it does not re-run its start-up calls on every page. Requests it then makes still
                    # pass the same route gate.
                    page.evaluate(_SPA_NAV_JS, url)
                else:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                pages_done += 1
                if settle_ms:
                    # Let the SPA fire its on-load XHR/fetch calls before we read the DOM and move on.
                    # networkidle returns early if the page quiesces; beacon-heavy apps never idle, so the
                    # bounded timeout just gives the API calls time to fire (and be captured by _route).
                    try:
                        page.wait_for_load_state("networkidle", timeout=settle_ms)
                    except Exception:  # noqa: BLE001
                        pass
                hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            except Exception:  # noqa: BLE001 — a dead page must not kill the crawl
                continue
            for h in hrefs or []:
                if should_enqueue(h, seen, depth + 1, max_depth, allow, deny, gate):
                    frontier.append((h, depth + 1))
            if spider and time.monotonic() < deadline:
                _spider_interact(page, allow, deny, depth, max_depth, frontier, seen, clicked_sigs, gate=gate)
        ctx.close()
    return list(captured.values())


def capture_login_session(start_url: str, out_file: str, timeout_s: int = 600,
                          proxy: dict | None = None) -> str:
    """Open a HEADED browser at start_url, let the operator complete login (CAPTCHA/2FA by hand), then
    save the session (Playwright storageState: cookies + origins) to out_file. This is the self-contained
    producer for --session-source login; the caido source uses a session exported out of band instead.
    Needs a display (run on a workstation, not a headless VPS). Returns the written path. The login is
    target traffic like any other, so it rides `proxy` when the program has one configured."""
    from playwright.sync_api import sync_playwright  # lazy: only interactive capture needs it

    with sync_playwright() as pw:
        ctx = pw.chromium.launch(headless=False, proxy=proxy).new_context()
        page = ctx.new_page()
        page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
        print("\n>>> Log in in the browser window. When you are fully logged in, press Enter here to "
              "save the session (or wait for the timeout).", file=sys.stderr)
        try:
            input()
        except EOFError:                       # non-interactive stdin — fall back to a fixed wait
            time.sleep(min(timeout_s, 120))
        state = ctx.storage_state()
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
        ctx.close()
    print(f"[authed-crawl] saved session -> {out_file} "
          f"({len(state.get('cookies', []))} cookie(s), {len(state.get('origins', []))} origin(s))",
          file=sys.stderr)
    return out_file


# Second-level labels under a two-letter country TLD that are registries, not registrants: the apex of
# www.brand.com.co is brand.com.co, and `*.com.co` would put every Colombian .com.co site in scope.
_CC_SECOND_LEVEL = {"com", "co", "net", "org", "gov", "gob", "edu", "ac", "ne", "or", "go", "mil", "nic", "ltd", "plc"}


def _apex(parts: list[str]) -> str:
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _CC_SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _scope_allow(project_dir: str) -> list:
    """The engagement's own scope as the allow list, when it has one: scope.py merges scope.md, the
    platform's structured scope and scope.json, exclusions included. [] when none parses."""
    try:
        import scope as _scope
        sc = _scope.load(project_dir)
    except Exception:  # noqa: BLE001 — a scope read failure falls back to the start-host default
        return []
    return [sc] if sc.ok else []


def _allow_desc(allow: list) -> list[str]:
    """allow for display/JSON: a scope.Scope becomes 'scope:<its sources>'."""
    return [f"scope:{','.join(os.path.basename(x) for x in p.sources)}" if hasattr(p, "check") else p
            for p in allow]


def _default_allow(start_urls: list[str]) -> list[str]:
    """With no --allow-host and no engagement scope, scope to the apex of each start host (`*.apex`,
    country-code second levels kept: `*.brand.com.co`, never `*.com.co`). Never returns [] for a real
    start url."""
    allow = set()
    for u in start_urls:
        host = urlparse(u).netloc.split(":")[0].lower()
        if not host:
            continue
        parts = host.split(".")
        # An IP literal or a single-label host is scoped EXACTLY; only a real domain gets a *.apex
        # wildcard (a wildcard over an IP's last two octets would be nonsense and over-broad).
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) or len(parts) < 2:
            allow.add(host)
        else:
            allow.add("*." + _apex(parts))
    return sorted(allow)


def _selftest() -> int:
    # scope: wildcard matches apex + sub; off-scope + denied are blocked.
    assert host_allowed("api.acme.com", ["*.acme.com"], [])
    assert host_allowed("acme.com", ["*.acme.com"], [])
    assert not host_allowed("evil.com", ["*.acme.com"], [])
    assert not host_allowed("cdn.acme.com", ["*.acme.com"], ["cdn.acme.com"])
    assert not host_allowed("api.acme.com", [], [])            # empty allow = fail closed

    # navigation safety: mutating verb or logout/delete path is refused.
    assert is_safe_nav("GET", "https://a/x/users")
    assert not is_safe_nav("POST", "https://a/x/users")
    assert not is_safe_nav("GET", "https://a/account/logout")
    assert not is_safe_nav("GET", "https://a/orgs/1/delete")
    assert is_safe_nav("GET", "https://a/orgs/1/members")

    # frontier: ?id=1 and ?id=2 collapse; fragment dropped; depth + scope enforced.
    assert canonical("https://a/p?id=1#frag") == canonical("https://a/p?id=2")
    assert should_enqueue("https://evil.com/new", set(), 1, 3, ["*.acme.com"], []) is False  # off-scope
    assert should_enqueue("https://x.acme.com/new", set(), 1, 3, ["*.acme.com"], [])
    assert not should_enqueue("https://x.acme.com/seen", {canonical("https://x.acme.com/seen")},
                              1, 3, ["*.acme.com"], [])
    assert not should_enqueue("https://x.acme.com/deep", set(), 4, 3, ["*.acme.com"], [])  # too deep

    # body field NAMES only (values discarded), JSON + form + nested.
    assert extract_body_field_names("application/json", '{"role":"admin","user":{"id":9,"plan":"pro"}}') \
        == ["role", "user", "user.id", "user.plan"]
    assert extract_body_field_names("application/x-www-form-urlencoded", "role=admin&note=x") \
        == ["role", "note"]
    assert extract_body_field_names("application/json", "not json") == []

    # request -> endpoint: keeps real url locally, records params/body-field-names/status/auth.
    ep = request_to_endpoint("PATCH", "https://api.acme.com/orgs/9/members?expand=roles", True, 200,
                             "application/json", '{"role":"admin"}')
    assert ep["url"].endswith("expand=roles") and ep["method"] == "PATCH"
    assert ep["parameters"] == ["expand"] and ep["body_fields"] == ["role"]
    assert ep["auth_required"] is True and ep["status_code"] == 200 and ep["source"] == "authed-crawl"

    # merge: same (method, canonical url) unions params/body_fields, keeps latest status; preserves other rows.
    existing = [{"url": "https://api.acme.com/orgs/9/members", "method": "GET",
                 "parameters": ["expand"], "source": "huginn"}]
    crawled = [{"url": "https://api.acme.com/orgs/9/members", "method": "GET",
                "parameters": ["page"], "status_code": 200, "auth_required": True,
                "source": "authed-crawl"},
               {"url": "https://api.acme.com/fetch?u=1", "method": "GET",
                "parameters": ["u"], "source": "authed-crawl"}]
    m = merge_endpoints(existing, crawled)
    assert len(m) == 2
    row = next(e for e in m if e["url"].endswith("/members"))
    assert row["parameters"] == ["expand", "page"] and row["status_code"] == 200
    assert row["source"] == "authed-crawl" and row["auth_required"] is True

    # session normalization + refresh classification.
    s = normalize_session({"cookies": [{"name": "sid", "value": "x"}],
                           "headers": {"Authorization": "Bearer x", "User-Agent": "z"},
                           "refresh": {"refresh_token": "r", "token_endpoint": "/oauth/token"}})
    assert list(s["auth_headers"]) == ["Authorization"]        # UA dropped from auth_headers, auth kept
    assert classify_refresh(s) == "oauth-refresh"
    assert classify_refresh({"cookies": [{"name": "sid"}]}) == "cookie-warm"
    assert classify_refresh({}) == "re-login"

    # fingerprint parity: client-hint/locale headers kept; UA/auth/per-request headers excluded here.
    fp = select_fingerprint_headers({"User-Agent": "UA", "sec-ch-ua": '"X";v="1"',
                                     "Sec-CH-UA-Platform": '"Linux"', "Accept-Language": "en-US",
                                     "Accept": "text/html", "sec-fetch-mode": "navigate",
                                     "Authorization": "Bearer x", "Cookie": "sid=1"})
    assert fp == {"accept-language": "en-US", "sec-ch-ua": '"X";v="1"', "sec-ch-ua-platform": '"Linux"'}
    assert select_fingerprint_headers({}) == {}
    sfp = normalize_session({"cookies": [], "user_agent": "UA/1", "fingerprint_headers": {"sec-ch-ua": "x"}})
    assert sfp["user_agent"] == "UA/1" and sfp["fingerprint_headers"] == {"sec-ch-ua": "x"}

    assert _default_allow(["https://api.acme.com/x"]) == ["*.acme.com"]
    assert _default_allow(["http://127.0.0.1:8080/x"]) == ["127.0.0.1"]     # IP scoped exactly
    assert _default_allow(["http://localhost/x"]) == ["localhost"]

    # --spider negative tests (the whole point — read-only by construction; see memory spec):
    # (a) a Delete/Pay-labelled element is NOT clicked; benign labels are.
    assert is_safe_interaction("View details") and is_safe_interaction("Insights tab")
    for bad in ("Delete account", "Pay now", "Submit", "Checkout", "Invite teammate", "Confirm",
                "Deactivate", "Log out", "Revoke token", "Remove", "Send message", "Buy credits"):
        assert not is_safe_interaction(bad), bad
    assert not spider_should_click("button", "", "", False, "Delete account")   # dangerous label skipped
    assert spider_should_click("div", "button", "", False, "Expand row")        # benign click allowed
    # (c) form auto-submit is categorically refused.
    assert would_submit_form("input", "submit", False) and would_submit_form("input", "image", False)
    assert would_submit_form("button", "", True)                 # bare <button> in a form defaults submit
    assert not would_submit_form("button", "button", True)       # explicit type=button is safe
    assert not would_submit_form("button", "", False)            # not inside a form
    assert not spider_should_click("button", "", "", True, "Save")   # refused even with a benign label
    # (b) a click that fires a POST is route-aborted AND recorded observed_not_executed (never executed).
    assert classify_route("GET", "https://x.acme.com/api/list", ["*.acme.com"], []) == "continue"
    assert classify_route("POST", "https://x.acme.com/api/pay", ["*.acme.com"], []) == "abort"
    assert classify_route("GET", "https://evil.com/x", ["*.acme.com"], []) == "abort"        # off-scope
    assert classify_route("GET", "https://x.acme.com/account/logout", ["*.acme.com"], []) == "abort"
    one = request_to_endpoint("POST", "https://x.acme.com/api/pay", True, None,
                              "application/json", '{"amount":5,"to":"acct_9"}', observed_not_executed=True)
    assert one["observed_not_executed"] is True and one["method"] == "POST"
    assert one["body_fields"] == ["amount", "to"]                # shape recorded (field NAMES only)...
    assert "status_code" not in one                              # ...but never executed (no response)
    assert "observed-not-executed" in one["tags"]

    # RoE: heavy static assets are dropped (light load); endpoint-bearing resource types are kept.
    for t in ("image", "media", "font", "IMAGE"):
        assert should_block_resource(t), t
    for t in ("document", "script", "stylesheet", "xhr", "fetch", "websocket", ""):
        assert not should_block_resource(t), t

    print("authed-crawl selftest OK")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="authed-crawl.py",
                                description="Populate asset-map endpoints[] from one authed session")
    p.add_argument("--project-dir", help="absolute engagement dir")
    p.add_argument("--session-source", choices=["caido", "login"], default="caido")
    p.add_argument("--session-file", help="normalized session / storageState JSON (caido source, or a "
                   "saved login state)")
    p.add_argument("--start", action="append", default=[], help="start URL (repeatable)")
    p.add_argument("--allow-host", action="append", default=[], help="in-scope host / *.suffix (repeatable)")
    p.add_argument("--deny-host", action="append", default=[], help="explicitly out-of-scope host")
    p.add_argument("--max-pages", type=int, default=120)
    p.add_argument("--max-depth", type=int, default=4)
    p.add_argument("--timeout-s", type=int, default=600)
    p.add_argument("--headless", action="store_true", help="headless (fast path; may trip bot walls)")
    p.add_argument("--live", action="store_true", help="drive a real browser (default: dry-run plan only)")
    p.add_argument("--spider", action="store_true",
                   help="interaction crawl: also click safe interactive elements (buttons/tabs/menus), not "
                        "just <a href>, to surface SPA XHR/fetch endpoints. Read-only: destructive-labelled "
                        "elements and form submits are skipped; mutating requests are route-aborted but their "
                        "shape is recorded as observed_not_executed")
    p.add_argument("--allow-graphql-reads", action="store_true",
                   help="let in-scope GraphQL POSTs out when the body is a read (query text that is a query, "
                        "or a name-only operation with a read shape and no write word; see "
                        "scripts/graphql_ops.py). Name-only verdicts are a heuristic: use it as an account "
                        "whose writes would only touch your own resources. Every other POST stays aborted")
    p.add_argument("--proxy", help="route the browser through this proxy, e.g. http://127.0.0.1:8080 for "
                   "Caido (enables ignore_https_errors so the intercepting CA does not break TLS). Required "
                   "to keep traffic visible/logged on programs whose RoE mandates proxy routing")
    p.add_argument("--spa-nav", action="store_true",
                   help="after the first page load, reach same-origin routes with history.pushState + "
                        "popstate instead of a reload, so the SPA does not re-run its start-up requests "
                        "per page (client-side routers only)")
    p.add_argument("--proxy-spki", default="",
                   help="comma-separated base64 SHA-256 SPKI hashes of the proxy's leaf and CA keys; pins "
                        "them instead of ignoring certificate errors, so the browser cache works")
    p.add_argument("--min-req-interval-ms", type=int, default=0,
                   help="minimum gap between outbound requests, ms (RoE throttle; e.g. 1000 = ~1 req/s). "
                        "0 = no throttle")
    p.add_argument("--settle-ms", type=int, default=2000,
                   help="after each navigation, wait up to this long for the page to go network-idle so "
                        "SPA on-load XHR/fetch calls fire and get captured (0 = move on immediately)")
    p.add_argument("--user-agent", help="override the browser User-Agent (default: the session file's "
                   "captured user_agent, for fingerprint parity with the real traffic being replayed)")
    p.add_argument("--capture-login", action="store_true",
                   help="open a headed browser, let the operator log in, save the session to --session-file")
    p.add_argument("--selftest", action="store_true")
    a = p.parse_args()

    if a.selftest:
        return _selftest()
    if a.capture_login:
        if not a.session_file or not a.start:
            print("--capture-login needs --session-file and --start", file=sys.stderr)
            return 2
        capture_login_session(a.start[0], a.session_file, a.timeout_s,
                              proxy=_egress.playwright_proxy(_egress.proxy(a.project_dir)))
        return 0
    if not a.project_dir or not os.path.isabs(a.project_dir):
        print("--project-dir must be an absolute path", file=sys.stderr)
        return 2
    if not a.start:
        print("--start URL is required", file=sys.stderr)
        return 2

    allow = a.allow_host or _scope_allow(a.project_dir) or _default_allow(a.start)
    if not a.allow_host:
        print(f"[authed-crawl] allow: {_allow_desc(allow)}", file=sys.stderr)
    # --allow-host narrows the hosts; the engagement scope still decides each URL (path exclusions).
    gate = _scope_allow(a.project_dir) if a.allow_host else []
    deny = a.deny_host
    session = {"cookies": [], "origins": [], "auth_headers": {}, "refresh": {}}
    if a.session_file:
        try:
            session = load_session_bundle(a.session_source, a.session_file)
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            print(f"[authed-crawl] session load failed: {e}", file=sys.stderr)
            return 3

    # The program's required headers (roe.json) ride every crawl request, as they do for login.py and
    # the lanes. A required User-Agent is the browser UA; --user-agent still wins below.
    try:
        import roe as _roe
        for line in _roe.required_header_lines(a.project_dir):
            k, v = (x.strip() for x in line.split(":", 1))
            if k.lower() == "user-agent":
                session["user_agent"] = v
            else:
                session.setdefault("auth_headers", {})[k] = v
    except Exception:  # noqa: BLE001 — no roe.json: nothing required
        pass

    if a.user_agent:
        session["user_agent"] = a.user_agent

    if not a.proxy:
        # No explicit --proxy (Caido, for visibility): the program's egress proxy still applies so
        # the crawl leaves through the address the program expects. An unusable value raises here,
        # before the browser opens — a crawl must not fall back to a direct connection.
        pw = _egress.playwright_proxy(_egress.proxy(a.project_dir))
        a.proxy = (pw or {}).get("server") or None

    if not a.live:
        print(json.dumps({"dry_run": True, "source": a.session_source, "start": a.start,
                          "allow": _allow_desc(allow), "deny": deny, "max_pages": a.max_pages,
                          "max_depth": a.max_depth, "spider": a.spider, "proxy": a.proxy,
                          "scope_gate": _allow_desc(gate),
                          "min_req_interval_ms": a.min_req_interval_ms, "settle_ms": a.settle_ms,
                          "user_agent": session.get("user_agent") or None,
                          "headers": sorted((session.get("auth_headers") or {}).keys()),
                          "fingerprint_headers": list((session.get("fingerprint_headers") or {}).keys()),
                          "refresh": classify_refresh(session)}, indent=2))
        return 0

    crawled = _drive_browser(a.start, session, allow, deny, a.max_pages, a.max_depth,
                             a.headless, a.timeout_s, spider=a.spider, proxy=a.proxy,
                             min_req_interval_ms=a.min_req_interval_ms, settle_ms=a.settle_ms,
                             allow_graphql_reads=a.allow_graphql_reads, gate=gate,
                             proxy_spki=a.proxy_spki, spa_nav=a.spa_nav)
    n = write_endpoints(a.project_dir, crawled)
    print(f"[authed-crawl] captured {len(crawled)} endpoint(s); asset-map now has {n} "
          f"(refresh={classify_refresh(session)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
