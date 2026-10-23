#!/usr/bin/env python3
"""
render-confirm.py — headless-browser confirmation for rendered output (Grimnir confirmation harness).

Two jobs, selected by --vuln-class:

  XSS/DOM (default).  Loads a URL (or local HTML), hooks alert/prompt/confirm plus a
  window.__grimnir_xss flag, screenshots, and reports whether the payload EXECUTED rather
  than being escaped to text.

  SSRF via a renderer (--vuln-class ssrf).  The screenshot bot's drawn artifact IS the
  response channel, so the question is not "did script run" but "did the internal response
  reach the output". That is what --expect-marker answers: a string you know appears only
  in the internal response (an instance id prefix, a header name, a canary you planted).
  Found in the rendered text, it is a real read; absent, the run stays inconclusive and the
  screenshot goes to vision review. Execution-hook detection is meaningless here and is not
  used as the verdict.

Writes evidence/<id>/render.json + render.png. For a server-side-request class it ALSO
writes evidence/<id>/verdict.json, because that is the artifact the ssrf branch of the
evidence gate reads -- render.json alone is only consulted for xss/dom/redirect/csrf, so
the rendering-bot lane could never satisfy its own critical ceiling.

  render-confirm.py --finding-id SPE-003 --project-dir ~/workspace/prog \
     --url 'https://app/x?q=<payload>' [--cookie 'k=v; k2=v2'] [--wait 4]
  render-confirm.py --finding-id SPE-003 --project-dir DIR --html-file stored.html
  render-confirm.py --finding-id SPE-003 --project-dir DIR --vuln-class ssrf \
     --url 'https://app/screenshot?id=123' --expect-marker 'ami-id' --channel-rung full

Payload tip (xss): have the payload set window.__grimnir_xss=1 (e.g.
  <img src=x onerror=window.__grimnir_xss=1>) or call alert()/prompt() — all are detected.
A screenshot is always captured for visual review even when the verdict can't be automated.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import _rung  # noqa: E402  (sibling module; see its docstring)
import egress as _egress  # noqa: E402  the program's egress proxy: the browser rides it or refuses

HOOK = ("window.__grimnir_xss=window.__grimnir_xss||0;"
        "(function(){window.alert=function(){window.__grimnir_xss=1;};"
        "window.prompt=function(){window.__grimnir_xss=1;return '';};"
        "window.confirm=function(){window.__grimnir_xss=1;return true;};})();")

#: Classes whose proof lives in evidence/<id>/verdict.json rather than render.json.
#: Kept in step with the ssrf branch of evidence_gate() in validate-finding.sh.
SSR_CLASSES = ("ssrf", "imds")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="page to load (the feature that shows the rendered artifact)")
    g.add_argument("--html-file", help="local HTML to render instead of navigating")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--wait", type=float, default=3.0)
    ap.add_argument("--vuln-class", default="xss",
                    help="evidence class to record (default xss). Use ssrf for a renderer "
                         "acting as an SSRF response channel.")
    ap.add_argument("--expect-marker", default="",
                    help="string that appears ONLY in the internal response. Found in the "
                         "rendered text it confirms the response reached the drawn output; "
                         "this is the oracle for the SSRF-via-renderer lane.")
    _rung.add_argument(ap)
    a = ap.parse_args()

    try:
        rung = _rung.normalize(a.channel_rung)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    cls = a.vuln_class.strip().lower()
    is_ssr = cls in SSR_CLASSES

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("error: playwright missing (pip install playwright && playwright install chromium)", file=sys.stderr)
        sys.exit(2)

    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    shot = os.path.join(d, "render.png")
    executed, marker_found, err, text = False, False, "", ""
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True,
                              proxy=_egress.playwright_proxy(_egress.proxy(a.project_dir)))
        ctx = b.new_context()
        ctx.add_init_script(HOOK)
        if a.cookie and a.url:
            from urllib.parse import urlparse
            host = urlparse(a.url).hostname
            cks = []
            for kv in a.cookie.split(";"):
                if "=" in kv:
                    k, v = kv.strip().split("=", 1)
                    cks.append({"name": k, "value": v, "domain": host, "path": "/"})
            try:
                ctx.add_cookies(cks)
            except Exception as e:
                err = f"cookie: {e}"
        pg = ctx.new_page()
        try:
            if a.url:
                pg.goto(a.url, wait_until="load", timeout=30000)
            else:
                pg.set_content(open(a.html_file).read(), wait_until="load")
            pg.wait_for_timeout(int(a.wait * 1000))
            executed = bool(pg.evaluate("window.__grimnir_xss"))
            if a.expect_marker:
                # Search the rendered content, not the raw response: the claim is that the
                # internal response was DRAWN, which is what a triager sees in the image.
                try:
                    text = pg.content() or ""
                except Exception:
                    text = ""
                marker_found = a.expect_marker in text
            pg.screenshot(path=shot, full_page=True)
        except Exception as e:
            err = str(e)
        b.close()

    if is_ssr:
        # Execution hooks say nothing about a fetch. Only the marker does, and without one
        # there is no automated oracle -- the screenshot goes to vision review rather than
        # promoting itself.
        confirmed = marker_found
        note = ("marker found in the rendered output: the internal response reached the drawn "
                "artifact, which is the response channel (hunting Rule 32)." if confirmed else
                "no --expect-marker supplied or marker absent. Review render.png: a renderer "
                "callback alone is the blind rung and caps at medium.")
    else:
        confirmed = executed
        note = ("executed=true means the payload ran (alert/prompt/window.__grimnir_xss). "
                "Review render.png to confirm visually.")

    verdict = "confirmed" if confirmed else "inconclusive"
    rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": cls,
           "verdict": verdict,
           "executed": executed, "marker": a.expect_marker or None,
           "marker_found": marker_found if a.expect_marker else None,
           "screenshot": shot, "error": err,
           "ts": datetime.now(timezone.utc).isoformat(),
           "note": note}
    if is_ssr:
        rec["channel_rung"] = rung or "blind"
        rec["reproducer"] = (
            f"drive the target's renderer at {a.url or a.html_file}, point it at the internal "
            f"endpoint, and read the response out of the drawn artifact")

    json.dump(rec, open(os.path.join(d, "render.json"), "w"), indent=2)
    if is_ssr:
        # The ssrf branch of the evidence gate reads verdict.json and nothing else, so a
        # renderer-confirmed SSRF has to speak that shape or it cannot be promoted at all.
        json.dump(rec, open(os.path.join(d, "verdict.json"), "w"), indent=2)

    keys = ["finding_id", "vuln_class", "verdict", "screenshot"]
    if is_ssr:
        keys.insert(3, "channel_rung")
        keys.insert(4, "marker_found")
    else:
        keys.insert(3, "executed")
    print(json.dumps({k: rec[k] for k in keys}, indent=2))


if __name__ == "__main__":
    main()
