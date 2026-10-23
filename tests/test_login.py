"""login.py: minting a fresh session for our own account when nothing is left to refresh.

The local app below has an API login, an OTP login whose verify step echoes a challenge id from
the send step, and browser sign-in pages (one page, two-step, cookie-only, and one behind a
CAPTCHA). The checks that matter: tokens land in the store, a human step stops with BLOCKED
instead of guessing, a CAPTCHA is never attempted, and repeated failures can't lock the account.
"""
import argparse
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


def b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def jwt(**c):
    return f"{b64({'alg': 'RS256'})}.{b64(c)}.c2ln"


PW = "correct-horse-9"
FORM = """<html><body><form id=f>
<input type=email name=email><input type=password name=password><button type=submit>Sign in</button>
</form><script>
document.getElementById('f').onsubmit = async (ev) => { ev.preventDefault();
  const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: ev.target.email.value, password: ev.target.password.value})});
  if (r.ok) { const j = await r.json(); localStorage.setItem('auth', JSON.stringify(j)); location = '/home'; }
};</script></body></html>"""
TWO_STEP = """<html><body><div id=s1><input type=email id=e><button id=n>Next</button></div>
<div id=s2 style="display:none"><input type=password id=p><button id=go>Log in</button></div><script>
document.getElementById('n').onclick = () => { s1.style.display = 'none'; s2.style.display = 'block'; };
document.getElementById('go').onclick = async () => {
  const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: e.value, password: p.value})});
  const j = await r.json(); sessionStorage.setItem('tok', j.access_token); };
</script></body></html>"""
COOKIE_FORM = """<html><body><form method=post action=/cookie-login>
<input name=username type=text><input name=password type=password><input type=submit value=Go>
</form></body></html>"""
CAPTCHA = """<html><body><div class=cf-turnstile data-src="https://challenges.cloudflare.com/turnstile/v0/api.js">
</div><input type=email><input type=password></body></html>"""


class App(BaseHTTPRequestHandler):
    logins = 0
    sent = []

    def _send(self, code, body, ctype="application/json", headers=()):
        b = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):  # noqa: N802
        pages = {"/signin": FORM, "/two-step": TWO_STEP, "/cookie": COOKIE_FORM, "/captcha": CAPTCHA,
                 "/home": "<html><body>welcome</body></html>"}
        self._send(200 if self.path in pages else 404, pages.get(self.path, "nf"), "text/html")

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        if self.path == "/api/login":
            App.logins += 1
            d = json.loads(body)
            if d.get("password") == PW and d.get("email") == "a1@test.example":
                return self._send(200, {"access_token": jwt(sub="sub-a1", azp="web", exp=int(time.time()) + 900),
                                        "refresh_token": "R" * 30})
            return self._send(401, {"error": "bad credentials"})
        if self.path == "/api/otp/send":
            App.sent.append(json.loads(body).get("email"))
            return self._send(200, {"challenge_id": "chal-0000-1111"})
        if self.path == "/api/otp/verify":
            d = json.loads(body)
            if d.get("challenge_id") == "chal-0000-1111" and d.get("code") == "424242":
                return self._send(200, {"accessToken": jwt(sub="sub-a1", azp="app", exp=int(time.time()) + 900),
                                        "refreshToken": "Q" * 30})
            return self._send(401, {"error": "bad code"})
        if self.path == "/cookie-login":
            ok = f"password={PW.replace('-', '-')}" in body
            if ok:
                self.send_response(302)
                self.send_header("Set-Cookie", "sid=s3ss10nvalue; Path=/; HttpOnly")
                self.send_header("Location", "/home")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self._send(200, COOKIE_FORM, "text/html")
        self._send(404, {})

    def log_message(self, *a):
        pass


@pytest.fixture
def app():
    App.logins, App.sent = 0, []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def proj(tmp_path):
    pd = tmp_path / "eng"
    pd.mkdir()
    (pd / "credentials.jsonl").write_text(json.dumps({"account": "a1", "email": "a1@test.example",
                                                      "password": PW}) + "\n")
    return str(pd)


def ns(**kw):
    d = dict(otp="", otp_prompt=False, headful=False, timeout=20, force=False)
    d.update(kw)
    return argparse.Namespace(**d)


def recipe_login(base):
    return {"kind": "http", "method": "POST", "url": base + "/api/login", "requires_otp": False,
            "headers": [["Content-Type", "application/json"]],
            "body": '{"email": "{username}", "password": "{password}"}'}


def recipe_otp(base):
    return {"kind": "http", "method": "POST", "url": base + "/api/otp/verify", "requires_otp": True,
            "headers": [["Content-Type", "application/json"]],
            "body": '{"challenge_id": "{pre.challenge_id}", "code": "{otp}"}',
            "pre": {"method": "POST", "url": base + "/api/otp/send", "chain": ["challenge_id"],
                    "headers": [["Content-Type", "application/json"]], "body": '{"email": "{username}"}'}}


def put_recipe(login_mod, pd, client, r):
    S = login_mod.S
    st = S.load(pd)
    st["recipes"]["login"][client] = r
    S.save(pd, st)


class TestHttp:
    def test_replays_the_learned_login(self, login_mod, proj, app):
        put_recipe(login_mod, proj, "web", recipe_login(app))
        c = login_mod.login(proj, "a1", "web", a=ns())
        e = login_mod.S.load(proj)["accounts"]["a1"]["clients"][c]
        assert c == "web" and e["minted_by"] == "login-http" and e["refresh_token"] == "R" * 30
        assert login_mod.S.entry_state(e) == "live"

    def test_wrong_password_fails_and_the_next_try_waits(self, login_mod, proj, app):
        with open(os.path.join(proj, "credentials.jsonl"), "w") as fh:
            fh.write(json.dumps({"account": "a1", "email": "a1@test.example", "password": "nope"}) + "\n")
        put_recipe(login_mod, proj, "web", recipe_login(app))
        with pytest.raises(login_mod.Failed):
            login_mod.login(proj, "a1", "web", a=ns())
        with pytest.raises(login_mod.Failed, match="lockout"):
            login_mod.login(proj, "a1", "web", a=ns())
        assert App.logins == 1

    def test_otp_blocks_after_sending_then_resumes_with_the_code(self, login_mod, proj, app):
        put_recipe(login_mod, proj, "app", recipe_otp(app))
        with pytest.raises(login_mod.Blocked, match="code has been sent"):
            login_mod.login(proj, "a1", "app", a=ns())
        assert App.sent == ["a1@test.example"]
        c = login_mod.login(proj, "a1", "app", a=ns(otp="424242"))     # resumes: no second send
        assert App.sent == ["a1@test.example"]
        st = login_mod.S.load(proj)
        assert st["accounts"]["a1"]["clients"][c]["refresh_token"] == "Q" * 30 and "pending_otp" not in st

    def test_main_reports_blocked_as_exit_5(self, login_mod, proj, app, capsys):
        put_recipe(login_mod, proj, "app", recipe_otp(app))
        assert login_mod.main(["--project-dir", proj, "--account", "a1", "--client", "app"]) == 5
        assert "BLOCKED" in capsys.readouterr().err


def test_harvest_learns_the_otp_send_step(session_mod, tmp_path):
    from test_session import FakeCaido
    pd = tmp_path / "eng"
    pd.mkdir()
    (pd / "scope.md").write_text("## In scope\n- `*.acme.example`\n")
    (pd / "credentials.jsonl").write_text(json.dumps({"account": "a1", "email": "a1@test.example"}) + "\n")
    caido = FakeCaido(str(tmp_path / "caido"))
    t0 = time.time() - 300
    caido.add("POST", "auth.acme.example", "/v2/otp/send", [("Content-Type", "application/json")],
              json.dumps({"email": "a1@test.example"}), 200, {"challenge_id": "chal-abcdef-123"}, t=t0)
    caido.add("POST", "auth.acme.example", "/v2/otp/login", [("Content-Type", "application/json")],
              json.dumps({"challenge_id": "chal-abcdef-123", "otp": "987654"}), 200,
              {"access_token": jwt(sub="s1", email="a1@test.example", azp="web", exp=9e9),
               "refresh_token": "Z" * 24}, t=t0 + 30)
    session_mod.harvest(str(pd), session_mod.caido_projects(caido.root), session_mod.scope_domains(str(pd), []),
                        log=lambda *_: None)
    r = session_mod.load(str(pd))["recipes"]["login"]["web"]
    assert r["requires_otp"] and "{otp}" in r["body"] and "{pre.challenge_id}" in r["body"]
    assert r["pre"]["chain"] == ["challenge_id"] and "{username}" in r["pre"]["body"]
    assert "987654" not in json.dumps(r) and "a1@test" not in json.dumps(r)


class TestBrowser:
    def test_one_page_form_with_token_in_the_response(self, login_mod, proj, app):
        c = login_mod.login(proj, "a1", "", "browser", app + "/signin", a=ns())
        e = login_mod.S.load(proj)["accounts"]["a1"]["clients"][c]
        assert c == "web" and e["minted_by"] == "login-browser" and e["refresh_token"] == "R" * 30
        assert oct(os.stat(e["storage_state"]).st_mode)[-3:] == "600"
        assert login_mod.S.load(proj)["config"]["login_urls"]["default"] == app + "/signin"

    def test_state_file_records_the_login_user_agent(self, login_mod, proj, app):
        """A server may bind the session to its User-Agent; authed-crawl.py replays the recorded one."""
        c = login_mod.login(proj, "a1", "", "browser", app + "/signin", a=ns())
        e = login_mod.S.load(proj)["accounts"]["a1"]["clients"][c]
        st = json.load(open(e["storage_state"]))
        assert st["user_agent"] == login_mod.S.DEFAULT_UA and "cookies" in st
        assert oct(os.stat(e["storage_state"]).st_mode)[-3:] == "600"

    def test_two_step_form(self, login_mod, proj, app):
        c = login_mod.login(proj, "a1", "", "browser", app + "/two-step", a=ns())
        assert login_mod.S.load(proj)["accounts"]["a1"]["clients"][c]["access_token"].startswith("eyJ")

    def test_cookie_only_session(self, login_mod, proj, app):
        c = login_mod.login(proj, "a1", "", "browser", app + "/cookie", a=ns())
        e = login_mod.S.load(proj)["accounts"]["a1"]["clients"][c]
        assert e["cookie_header"] == "sid=s3ss10nvalue" and not e.get("access_token")
        assert login_mod.S.entry_state(e) == "live"
        login_mod.S.sync(proj)
        rec = json.loads(open(os.path.join(proj, "credentials.jsonl")).read())
        assert rec["auth_headers"] == ["Cookie: sid=s3ss10nvalue"] and "token" not in rec

    def test_captcha_is_blocked_not_attempted(self, login_mod, proj, app):
        with pytest.raises(login_mod.Blocked, match="CAPTCHA"):
            login_mod.login(proj, "a1", "", "browser", app + "/captcha", a=ns())
        assert App.logins == 0
