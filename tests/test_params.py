"""The parameter inventory and the reflection probe.

The probe is the first thing that sends a request per parameter, so the tests that matter most are
the ones where it must NOT send: no parseable scope, a supervised-only or scanning-banned program
run unattended, an out-of-scope URL, a spent budget share. The rest pin the reflection map the
injection classes will read: the context, and which breaker characters came back raw.
"""
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from conftest import _load


@pytest.fixture(scope="module")
def params_mod():
    return _load("grimnir_params", "scripts/params.py")


@pytest.fixture()
def server():
    hits = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlsplit(self.path)
            q = parse_qs(u.query, keep_blank_values=True).get("q", [""])[0]
            hits.append(self.path)
            ctype, status, body, extra = "text/html", 200, "<p>static</p>", {}
            if u.path == "/text":
                body = f"<p>you searched {q}</p>"
            elif u.path == "/attr":
                body = f'<input value="{html.escape(q, quote=True)}">'
            elif u.path == "/json":
                ctype, body = "application/json", json.dumps({"q": q})
            elif u.path == "/redir":
                status, extra = 302, {"Location": f"/next?q={q}"}
            elif u.path == "/slow-down":
                status = 429
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", hits
    srv.shutdown()


def _project(tmp_path, base, paths, roe=None, scope=("127.0.0.1",)):
    eps = [{"url": f"{base}{p}", "method": "GET", "sources": ["crawl"]} for p in paths]
    (tmp_path / "asset-map.json").write_text(json.dumps({"endpoints": eps}))
    if scope is not None:
        (tmp_path / "scope.json").write_text(json.dumps({"in_scope": list(scope)}))
    # Probing is unattended automated requesting, so it needs the auto-fire opt-in; a per-test `roe`
    # can still override it off (the supervised-lift cases below rely on that).
    (tmp_path / "roe.json").write_text(json.dumps(
        {"max_rps_per_host": 1000, "daily_request_budget": 1000, "auto_fire_allowed": True,
         **(roe or {})}))
    return str(tmp_path)


def _args(**kw):
    base = dict(max_params=40, budget_share=1.0, supervised=False, force=False, header=None,
                timeout=5.0, dry_run=False)
    base.update(kw)
    return SimpleNamespace(**base)


def _probe(params_mod, pd, **kw):
    return params_mod.run_probe(pd, _args(**kw), _sleep=lambda s: None)


def _row(params_mod, pd, path):
    return next(r for r in params_mod.load(pd)["params"] if r["path"] == path)


def test_reflection_map(params_mod, server, tmp_path):
    base, hits = server
    pd = _project(tmp_path, base, ["/text?q=a", "/attr?q=a", "/json?q=a", "/static?q=a", "/redir?q=a"])
    rc, res = _probe(params_mod, pd)
    assert rc == 0 and res["probed"] == 5
    text = _row(params_mod, pd, "/text")["probe"]
    assert text["contexts"] == ["html-text"] and set(text["raw_chars"]) == {"'", '"', "<", ">", "`"}
    attr = _row(params_mod, pd, "/attr")["probe"]
    assert attr["contexts"] == ["attribute-dq"] and attr["raw_chars"] == ["`"]
    assert {"'", '"', "<", ">"} <= set(attr["transformed_chars"])
    assert _row(params_mod, pd, "/json")["probe"]["contexts"] == ["json"]
    assert _row(params_mod, pd, "/static")["probe"]["reflected"] is False
    assert _row(params_mod, pd, "/redir")["probe"]["contexts"] == ["header:location"]
    # baseline once per endpoint, one canary per param, one breaker request per reflected param
    assert res["requests"] == len(hits) == 5 + 5 + 4
    assert {"reflected-param", "reflected-html-text", "xss-candidate"} <= set(res["tags"])
    assert params_mod.xss_shaped(text) and not params_mod.xss_shaped(attr)


def test_records_intel_and_activity(params_mod, server, tmp_path):
    base, _ = server
    pd = _project(tmp_path, base, ["/text?q=a"])
    _probe(params_mod, pd)
    intel = [json.loads(l) for l in (tmp_path / "intel.jsonl").read_text().splitlines()]
    assert len(intel) == 1 and "reflected-param" in intel[0]["tags"]
    acts = [json.loads(l) for l in (tmp_path / "activity.jsonl").read_text().splitlines()]
    assert acts[-1]["kind"] == "recon" and "1 reflected" in acts[-1]["summary"]


def test_no_scope_refuses_and_sends_nothing(params_mod, server, tmp_path):
    base, hits = server
    pd = _project(tmp_path, base, ["/text?q=a"], scope=None)
    rc, res = _probe(params_mod, pd)
    assert rc == params_mod.EXIT_SCOPE_REFUSED and hits == []


def test_out_of_scope_url_is_never_requested(params_mod, server, tmp_path):
    base, hits = server
    pd = _project(tmp_path, base, ["/text?q=a"], scope=("in.example.com",))
    rc, res = _probe(params_mod, pd)
    assert rc == 0 and res["skipped"]["out_of_scope"] == 1 and hits == []


@pytest.mark.parametrize("roe", [{"auto_fire_allowed": False}, {"automated_scanning_banned": True}])
def test_unattended_refusals_lift_only_when_supervised(params_mod, server, tmp_path, roe):
    base, hits = server
    pd = _project(tmp_path, base, ["/text?q=a"], roe=roe)
    rc, _ = _probe(params_mod, pd)
    assert rc == params_mod.EXIT_ROE_REFUSED and hits == []
    rc, res = _probe(params_mod, pd, supervised=True)
    assert rc == 0 and res["probed"] == 1


def test_budget_share_caps_requests(params_mod, server, tmp_path):
    base, hits = server
    pd = _project(tmp_path, base, [f"/static{i}?q=a" for i in range(6)],
                  roe={"daily_request_budget": 8})
    rc, res = _probe(params_mod, pd, budget_share=0.5)
    assert res["max_requests"] == 4 and len(hits) == 4 and res["stopped"] == "request cap reached"


def test_second_run_skips_probed_params(params_mod, server, tmp_path):
    base, hits = server
    pd = _project(tmp_path, base, ["/static?q=a"])
    _probe(params_mod, pd)
    n = len(hits)
    rc, res = _probe(params_mod, pd)
    assert res["skipped"]["already_probed"] == 1 and len(hits) == n
    params_mod.inventory(pd)   # a re-inventory keeps the probe result
    assert _row(params_mod, pd, "/static")["probe"]["reflected"] is False


def test_throttling_stops_the_run(params_mod, server, tmp_path):
    base, hits = server
    pd = _project(tmp_path, base, [f"/slow-down?q=a&p{i}=1" for i in range(5)])
    rc, res = _probe(params_mod, pd, max_params=20)
    assert res["stopped"] == "throttled 3 times in a row" and len(hits) < 10


def test_dry_run_sends_nothing(params_mod, server, tmp_path):
    base, hits = server
    pd = _project(tmp_path, base, ["/text?q=a", "/attr?q=a"])
    rc, res = _probe(params_mod, pd, dry_run=True)
    assert rc == 0 and res["picked"] == 2 and hits == []
