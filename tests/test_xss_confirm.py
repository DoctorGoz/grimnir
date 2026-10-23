"""xss-confirm.py proves reflected XSS by execution in a real browser. The failures that would be
silent: a reflection whose characters are encoded read as XSS, a JSON response read as an HTML one,
a CSP-blocked payload read as executed (or as a clean negative, when it is a lead), and the browser
pulling the page's own scripts and images from the target (the one-request-per-load promise). The
logic tests use a fake browser; the last group drives real headless Chromium at a local server and
is skipped where Playwright isn't installed.
"""
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest


def _q(url):
    return parse_qs(urlsplit(url).query, keep_blank_values=True).get("q", [""])[0]


def _html(body, status=200, headers=None):
    return {"status": status, "body": body, "headers": headers or {}, "content_type": "text/html"}


class TestLogic:
    """Fake browser: 'executes' only when told to, so these pin the decisions, not Chromium."""

    @staticmethod
    def _run(mod, server, executes=True, **render_extra):
        def render(u):
            r = server(u)
            value = None
            if executes:
                import re
                m = re.search(r"(?:on\w+=|'-)\(window\.__grimnir_xss=(\d+)\)", r["body"])
                value = int(m.group(1)) if m else None
            return {**r, "value": value, **render_extra}
        return mod.probe_xss(server, render, "https://app.example.com/s?q=a&p=1", "q")

    def test_raw_html_text_confirms(self, xss_confirm_mod):
        res = self._run(xss_confirm_mod, lambda u: _html(f"<p>{_q(u)}</p>"))
        assert res["verdict"] == "confirmed" and res["context"] == "html-text"
        assert res["payload"].startswith("<svg onload=") and res["requests"] == 2

    def test_encoded_attribute_is_negative(self, xss_confirm_mod):
        res = self._run(xss_confirm_mod, lambda u: _html(f'<input value="{html.escape(_q(u))}">'))
        assert res["verdict"] == "negative" and "encoded" in res["why"] and res["requests"] == 1

    def test_json_response_is_negative(self, xss_confirm_mod):
        res = self._run(xss_confirm_mod, lambda u: {"status": 200, "body": json.dumps({"q": _q(u)}),
                                                    "headers": {}, "content_type": "application/json"})
        assert res["verdict"] == "negative" and "not HTML" in res["why"]

    def test_unreflected_is_inconclusive(self, xss_confirm_mod):
        res = self._run(xss_confirm_mod, lambda u: _html("<p>static</p>"))
        assert res["verdict"] == "inconclusive"

    def test_intact_but_not_run_is_a_candidate(self, xss_confirm_mod):
        res = self._run(xss_confirm_mod, lambda u: _html(f"<p>{_q(u)}</p>"), executes=False,
                        csp="script-src 'none'")
        assert res["verdict"] == "xss-likely" and "Content-Security-Policy" in res["why"]
        assert len(res["attempts"]) == 2   # capped at two browser loads

    def test_javascript_url_needs_a_click(self, xss_confirm_mod):
        res = self._run(xss_confirm_mod, lambda u: _html(f'<a href="{html.escape(_q(u))}">x</a>'),
                        executes=False)
        assert res["verdict"] == "xss-likely" and "click" in res["why"]

    def test_payload_altered_on_the_way_back_is_negative(self, xss_confirm_mod):
        def strips_handlers(u):
            return _html(f"<p>{_q(u).replace('onload', '').replace('onerror', '')}</p>")
        res = self._run(xss_confirm_mod, strips_handlers)
        assert res["verdict"] == "negative" and "altered" in res["why"]

    def test_payload_choice_follows_raw_chars(self, xss_confirm_mod):
        m = xss_confirm_mod
        assert m.payloads_for(["attribute-dq"], ['"'])[0][1].startswith('" autofocus')
        assert m.payloads_for(["script"], ["'"]) == [("script", "'-X-'")]
        assert m.payloads_for(["html-text"], ['"']) == []


# ── real Chromium ────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def site():
    pytest.importorskip("playwright.sync_api")
    hits = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlsplit(self.path)
            hits.append(u.path)
            q = _q(self.path)
            ctype, extra = "text/html", {}
            assets = '<script src="/app.js"></script><img src="/logo.png">'
            if u.path == "/text":
                body = f"<html><body>{assets}<p>you searched {q}</p></body></html>"
            elif u.path == "/attr":
                body = f'<html><body><input value="{html.escape(q)}"></body></html>'
            elif u.path == "/js":
                safe = q.replace("<", "\\u003c").replace(">", "\\u003e")
                body = f"<html><body><script>var term = '{safe}';</script></body></html>"
            elif u.path == "/csp":
                body = f"<html><body><p>{q}</p></body></html>"
                extra["Content-Security-Policy"] = "script-src 'none'"
            elif u.path == "/json":
                ctype, body = "application/json", json.dumps({"q": q})
            else:
                body = "console.log(1)"
            data = body.encode()
            self.send_response(200)
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


def _cli(mod, monkeypatch, tmp_path, url, fid="SPE-001"):
    monkeypatch.setattr("sys.argv", ["xss-confirm.py", "--finding-id", fid, "--project-dir", str(tmp_path),
                                     "--url", url, "--param", "q", "--timeout", "10"])
    assert mod.main() == 0
    return json.loads((tmp_path / "evidence" / fid / "render.json").read_text())


class TestChromium:
    def test_executes_and_fetches_only_the_main_document(self, xss_confirm_mod, site, tmp_path, monkeypatch):
        base, hits = site
        hits.clear()
        rec = _cli(xss_confirm_mod, monkeypatch, tmp_path, f"{base}/text?q=a")
        assert rec["verdict"] == "confirmed" and rec["executed"] is True
        assert (tmp_path / "evidence" / "SPE-001" / "render.png").exists()
        assert hits == ["/text", "/text"]   # map + one load; /app.js and /logo.png never requested

    def test_js_string_breakout(self, xss_confirm_mod, site, tmp_path, monkeypatch):
        rec = _cli(xss_confirm_mod, monkeypatch, tmp_path, f"{site[0]}/js?q=a")
        assert rec["verdict"] == "confirmed" and rec["context"] == "script" and rec["payload"].startswith("'-")

    def test_escaped_attribute_is_negative(self, xss_confirm_mod, site, tmp_path, monkeypatch):
        assert _cli(xss_confirm_mod, monkeypatch, tmp_path, f"{site[0]}/attr?q=a")["verdict"] == "negative"

    def test_csp_blocks_execution(self, xss_confirm_mod, site, tmp_path, monkeypatch):
        rec = _cli(xss_confirm_mod, monkeypatch, tmp_path, f"{site[0]}/csp?q=a")
        assert rec["verdict"] == "xss-likely" and rec["attempts"][0]["csp"]

    def test_json_is_negative(self, xss_confirm_mod, site, tmp_path, monkeypatch):
        assert _cli(xss_confirm_mod, monkeypatch, tmp_path, f"{site[0]}/json?q=a")["verdict"] == "negative"
