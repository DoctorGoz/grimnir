"""session.py: the session store, the Caido harvester, and the rotation-safe refresher.

The failures these tests exist to catch are the silent ones from the requirements note: a refresh
that spends a single-use token without persisting its successor, a vault token that looks live but
is expired, a harvested chain head that a later request already burned, and a sync that writes one
client's token over another's. The refresher runs against a local OAuth server that enforces
single-use rotation, so a reused token fails loudly.
"""
import base64
import json
import os
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import pytest


def b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def jwt(**claims) -> str:
    return f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(claims)}.c2ln"


# ── a minimal Caido project on disk ──────────────────────────────────────────
class FakeCaido:
    def __init__(self, root):
        self.root = root
        self.pid = "11111111-2222-3333-4444-555555555555"
        self.dir = os.path.join(root, "projects", self.pid)
        os.makedirs(self.dir)
        con = sqlite3.connect(os.path.join(root, "projects.db"))
        con.execute("CREATE TABLE projects (id text, name text)")
        con.execute("INSERT INTO projects VALUES (?, ?)", (self.pid, "hunt-test"))
        con.commit()
        con.close()
        self.idx = sqlite3.connect(os.path.join(self.dir, "database.caido"))
        self.idx.executescript("""
            CREATE TABLE requests (id integer primary key, host text, method text, path text, length int,
              port int, raw_id int, is_tls int, query text, file_extension text, source text,
              response_id int, created_at bigint);
            CREATE TABLE responses (id integer primary key, status_code int, raw_id int, length int,
              created_at bigint);""")
        self.raw = sqlite3.connect(os.path.join(self.dir, "database_raw.caido"))
        self.raw.executescript("""
            CREATE TABLE requests_raw (id integer primary key, data blob);
            CREATE TABLE responses_raw (id integer primary key, data blob);""")
        self.n = 0

    def add(self, method, host, path, req_headers, req_body, status, resp_body, resp_headers=(), t=None):
        self.n += 1
        ms = int((t or time.time()) * 1000) + self.n
        rq = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in req_headers)
        rq += f"Content-Length: {len(req_body)}\r\n\r\n{req_body}"
        body = resp_body if isinstance(resp_body, str) else json.dumps(resp_body)
        rs = f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n" + \
             "".join(f"{k}: {v}\r\n" for k, v in resp_headers) + f"\r\n{body}"
        self.raw.execute("INSERT INTO requests_raw VALUES (?, ?)", (self.n, rq.encode()))
        self.raw.execute("INSERT INTO responses_raw VALUES (?, ?)", (self.n, rs.encode()))
        self.idx.execute("INSERT INTO responses VALUES (?, ?, ?, ?, ?)", (self.n, status, self.n, len(rs), ms))
        self.idx.execute("INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (self.n, host, method, path.split("?")[0], len(rq), 443, self.n, 1,
                          path.split("?")[1] if "?" in path else "", "", "intercept", self.n, ms))
        self.raw.commit()
        self.idx.commit()


@pytest.fixture
def proj(tmp_path):
    pd = tmp_path / "eng"
    pd.mkdir()
    (pd / "scope.md").write_text("# Scope\n\n## In scope\n- `*.acme.example`\n")
    (pd / "credentials.jsonl").write_text(
        json.dumps({"account": "a1", "email": "a1@test.example", "token": "stale"}) + "\n" +
        json.dumps({"account": "a2", "email": "a2@test.example", "object_id": "u2"}) + "\n" +
        "# a comment line stays\n")
    return str(pd)


# ── extraction ───────────────────────────────────────────────────────────────
class TestExtract:
    def test_oauth_json(self, session_mod):
        m = session_mod.extract_tokens(200, [], json.dumps({"access_token": jwt(sub="u1", exp=9e9),
                                                             "refresh_token": "r" * 32, "expires_in": "3600"}).encode())
        assert m["refresh"] == "r" * 32 and m["expires_in"] == 3600

    def test_generic_token_key_needs_an_auth_exchange(self, session_mod):
        body = json.dumps({"data": {"token": "p" * 40}}).encode()
        assert session_mod.extract_tokens(200, [], body, "https://api.acme.example/v1/push") is None
        assert session_mod.extract_tokens(200, [], body, "https://api.acme.example/v1/login")["access"] == "p" * 40

    def test_id_token_is_the_bearer_when_alone(self, session_mod):
        idt = jwt(sub="u1", exp=9e9)
        m = session_mod.extract_tokens(200, [], json.dumps({"idToken": idt, "refreshToken": "r" * 30}).encode())
        assert m["access"] == idt

    def test_jwt_cookie(self, session_mod):
        tok = jwt(sub="u1", exp=9e9)
        m = session_mod.extract_tokens(200, [("Set-Cookie", f"rt={jwt(sub='u1', typ='refresh')}; HttpOnly"),
                                             ("Set-Cookie", f"auth_refresh={tok}; Path=/")], b"")
        assert m["access"] and m["refresh"] == tok

    def test_errors_mint_nothing(self, session_mod):
        assert session_mod.extract_tokens(401, [], b'{"access_token": "' + b"x" * 30 + b'"}') is None


# ── harvest ──────────────────────────────────────────────────────────────────
def _history(caido, t0):
    a1_v1 = jwt(sub="sub-a1", email="a1@test.example", azp="web", exp=int(t0) + 60)
    caido.add("POST", "auth.acme.example", "/v1/login", [("Content-Type", "application/json")],
              json.dumps({"email": "a1@test.example", "password": "hunter2-pass"}), 200,
              {"access_token": a1_v1, "refresh_token": "R1" * 12}, t=t0)
    caido.add("GET", "api.acme.example", "/v1/me", [("Authorization", f"Bearer {a1_v1}")], "", 200,
              {"id": "sub-a1"}, t=t0 + 1)
    a1_v2 = jwt(sub="sub-a1", email="a1@test.example", azp="web", exp=int(t0) + 3600)
    caido.add("POST", "auth.acme.example", "/oauth/token",
              [("Content-Type", "application/x-www-form-urlencoded"), ("Authorization", f"Bearer {a1_v1}")],
              "grant_type=refresh_token&client_id=web&refresh_token=" + "R1" * 12, 200,
              {"access_token": a1_v2, "refresh_token": "R2" * 12}, t=t0 + 2)
    return a1_v2


class TestHarvest:
    def test_newest_mint_recipes_and_templating(self, session_mod, proj, tmp_path):
        caido = FakeCaido(str(tmp_path / "caido"))
        t0 = time.time() - 600
        a1_v2 = _history(caido, t0)
        s = session_mod.harvest(proj, session_mod.caido_projects(caido.root),
                                session_mod.scope_domains(proj, []), log=lambda *_: None)
        st = session_mod.load(proj)
        e = st["accounts"]["a1"]["clients"]["web"]
        assert e["access_token"] == a1_v2 and e["refresh_token"] == "R2" * 12
        assert e["rotates"] is True and e["refresh_state"] == "fresh" and e["minted_by"] == "caido-refresh"
        rr = st["recipes"]["refresh"]["web"]
        assert "{refresh_token}" in rr["body"] and "R1" not in json.dumps(rr)
        assert any(v == "Bearer {access_token}" for k, v in rr["headers"])     # the old access, templated
        lr = st["recipes"]["login"]["web"]
        assert "{password}" in lr["body"] and "hunter2" not in json.dumps(lr) and lr["requires_otp"] is False
        assert s["entries"][0]["account"] == "a1"
        assert oct(os.stat(session_mod.store_path(proj)).st_mode)[-3:] == "600"

    def test_a_later_request_that_spent_the_head_marks_it(self, session_mod, proj, tmp_path):
        caido = FakeCaido(str(tmp_path / "caido"))
        t0 = time.time() - 600
        _history(caido, t0)
        # the app (not us) tried the head later and was refused: a rotating server has burned it
        caido.add("POST", "auth.acme.example", "/oauth/token", [], "refresh_token=" + "R2" * 12, 403,
                  {"error": "app_check"}, t=t0 + 5)
        session_mod.harvest(proj, session_mod.caido_projects(caido.root), session_mod.scope_domains(proj, []),
                            log=lambda *_: None)
        e = session_mod.load(proj)["accounts"]["a1"]["clients"]["web"]
        assert e["refresh_state"] == "spent-failed:403"
        assert session_mod.entry_state(e) != "refreshable"

    def test_out_of_scope_hosts_are_not_read(self, session_mod, proj, tmp_path):
        caido = FakeCaido(str(tmp_path / "caido"))
        caido.add("POST", "login.other.example", "/login", [], json.dumps({"email": "a1@test.example"}), 200,
                  {"access_token": jwt(sub="x", exp=9e9), "refresh_token": "Q" * 20})
        s = session_mod.harvest(proj, session_mod.caido_projects(caido.root),
                                session_mod.scope_domains(proj, []), log=lambda *_: None)
        assert s["exchanges_read"] == 0 and not session_mod.load(proj)["accounts"]

    def test_dry_run_writes_nothing(self, session_mod, proj, tmp_path):
        caido = FakeCaido(str(tmp_path / "caido"))
        _history(caido, time.time() - 600)
        session_mod.harvest(proj, session_mod.caido_projects(caido.root), session_mod.scope_domains(proj, []),
                            dry_run=True, log=lambda *_: None)
        assert not [f for f in os.listdir(proj) if f.startswith("sessions")]

    def test_store_newer_than_history_is_kept(self, session_mod, proj, tmp_path):
        caido = FakeCaido(str(tmp_path / "caido"))
        _history(caido, time.time() - 600)
        st = session_mod.load(proj)
        st["accounts"]["a1"] = {"clients": {"web": {"access_token": "mine", "minted_at": time.time(),
                                                     "refresh_token": "R9" * 12, "refresh_state": "fresh"}}}
        session_mod.save(proj, st)
        session_mod.harvest(proj, session_mod.caido_projects(caido.root), session_mod.scope_domains(proj, []),
                            log=lambda *_: None)
        assert session_mod.load(proj)["accounts"]["a1"]["clients"]["web"]["refresh_token"] == "R9" * 12

    def test_package_ids_are_not_domains(self, session_mod, tmp_path):
        pd = tmp_path / "p"
        pd.mkdir()
        (pd / "scope.json").write_text(json.dumps({"in_scope": ["com.acme.app", "*.acme.example"]}))
        assert session_mod.scope_domains(str(pd), []) == ["acme.example"]


# ── refresh against a single-use rotating server ─────────────────────────────
class OAuth(BaseHTTPRequestHandler):
    valid: set = set()
    seen: list = []
    gen = 0
    lifetime = 3600

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        rt = parse_qs(self.rfile.read(n).decode()).get("refresh_token", [""])[0]
        OAuth.seen.append(rt)
        if rt not in OAuth.valid:
            self._send(400, {"error": "invalid_grant"})
            return
        OAuth.valid.discard(rt)               # single use
        OAuth.gen += 1
        new = f"RT{OAuth.gen:02d}" + "x" * 20
        OAuth.valid.add(new)
        self._send(200, {"access_token": jwt(sub="sub-a1", azp="web", exp=int(time.time()) + OAuth.lifetime),
                         "refresh_token": new, "token_type": "bearer"})

    def _send(self, code, doc):
        b = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


@pytest.fixture
def oauth():
    OAuth.valid, OAuth.seen, OAuth.gen, OAuth.lifetime = {"RT00" + "x" * 20}, [], 0, 3600
    srv = HTTPServer(("127.0.0.1", 0), OAuth)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _seed(session_mod, proj, url, access_exp):
    st = session_mod.load(proj)
    st["accounts"]["a1"] = {"clients": {"web": {
        "access_token": jwt(sub="sub-a1", azp="web", exp=int(access_exp)), "access_exp": access_exp,
        "refresh_token": "RT00" + "x" * 20, "refresh_state": "fresh", "minted_at": time.time() - 100}}}
    st["recipes"]["refresh"]["web"] = {"method": "POST", "url": url + "/oauth/token",
                                       "headers": [["Content-Type", "application/x-www-form-urlencoded"]],
                                       "body": "grant_type=refresh_token&refresh_token={refresh_token}"}
    session_mod.save(proj, st)


class TestRefresh:
    def test_live_token_is_returned_without_a_request(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() + 3000)
        session_mod.refresh_entry(proj, "a1")
        assert OAuth.seen == []

    def test_refresh_persists_the_rotated_token_before_returning(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() - 5)
        e = session_mod.refresh_entry(proj, "a1")
        disk = session_mod.load(proj)["accounts"]["a1"]["clients"]["web"]
        assert disk["refresh_token"] == "RT01" + "x" * 20 == e["refresh_token"]
        assert disk["access_exp"] > time.time() + 3000 and disk["rotates"] is True
        assert session_mod.thash("RT00" + "x" * 20) in disk["chain"] and "inflight" not in disk
        # the next forced refresh uses the successor, never the spent token
        session_mod.refresh_entry(proj, "a1", force=True)
        assert OAuth.seen == ["RT00" + "x" * 20, "RT01" + "x" * 20]

    def test_concurrent_callers_refresh_once(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() - 5)
        errs = []

        def worker():
            try:
                session_mod.refresh_entry(proj, "a1")
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=worker) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert not errs and OAuth.seen == ["RT00" + "x" * 20]

    def test_rejected_refresh_needs_login(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() - 5)
        OAuth.valid = set()                  # server already revoked it
        with pytest.raises(session_mod.NeedsLogin):
            session_mod.refresh_entry(proj, "a1")
        e = session_mod.load(proj)["accounts"]["a1"]["clients"]["web"]
        assert e["refresh_state"] == "rejected:400"
        with pytest.raises(session_mod.NeedsLogin):    # and never retries the dead token
            session_mod.refresh_entry(proj, "a1")
        assert len(OAuth.seen) == 1

    def test_crash_after_send_recovers_from_the_journal(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() - 5)
        real = session_mod.apply_mint
        calls = {"n": 0}

        def dies(*a, **k):
            calls["n"] += 1
            raise SystemExit("killed between the response and the store write")
        session_mod.apply_mint = dies
        try:
            with pytest.raises(SystemExit):
                session_mod.refresh_entry(proj, "a1")
        finally:
            session_mod.apply_mint = real
        st = session_mod.load(proj)
        assert st["accounts"]["a1"]["clients"]["web"]["inflight"]        # store never absorbed it
        e = session_mod.refresh_entry(proj, "a1")                        # recovery, no new request
        assert e["refresh_token"] == "RT01" + "x" * 20 and len(OAuth.seen) == 1
        assert oct(os.stat(os.path.join(proj, session_mod.JOURNAL)).st_mode)[-3:] == "600"

    def test_cli_get_exit_codes(self, session_mod, proj, oauth, capsys):
        _seed(session_mod, proj, oauth, time.time() - 5)
        assert session_mod.main(["get", "--project-dir", proj, "--account", "a1", "--format", "header"]) == 0
        assert capsys.readouterr().out.startswith("Authorization: Bearer eyJ")
        assert session_mod.main(["get", "--project-dir", proj, "--account", "nobody"]) == 4
        OAuth.valid = set()
        assert session_mod.main(["get", "--project-dir", proj, "--account", "a1", "--min-ttl", "99999"]) == 3


# ── sync into credentials.jsonl ──────────────────────────────────────────────
class TestSync:
    def test_writes_live_token_and_preserves_the_rest(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() + 3000)
        live = session_mod.load(proj)["accounts"]["a1"]["clients"]["web"]["access_token"]
        ch = session_mod.sync(proj)
        assert [c["account"] for c in ch] == ["a1"]
        lines = open(os.path.join(proj, "credentials.jsonl")).read().splitlines()
        assert json.loads(lines[0])["token"] == live and json.loads(lines[0])["session_client"] == "web"
        assert json.loads(lines[1]) == {"account": "a2", "email": "a2@test.example", "object_id": "u2"}
        assert lines[2] == "# a comment line stays"
        assert session_mod.sync(proj) == []         # idempotent

    def test_never_crosses_clients(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() + 3000)
        mobile = jwt(sub="sub-a1", azp="mobile", exp=9e9)
        with open(os.path.join(proj, "credentials.jsonl"), "w") as fh:
            fh.write(json.dumps({"account": "a1", "token": mobile}) + "\n")
        assert session_mod.sync(proj) == []
        assert json.loads(open(os.path.join(proj, "credentials.jsonl")).read())["token"] == mobile

    def test_expired_entries_are_not_synced(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() - 5)
        assert session_mod.sync(proj) == []

    def test_auth_headers_follow_the_token(self, session_mod, proj, oauth):
        _seed(session_mod, proj, oauth, time.time() + 3000)
        with open(os.path.join(proj, "credentials.jsonl"), "w") as fh:
            fh.write(json.dumps({"account": "a1", "token": "old-token-value",
                                 "auth_headers": ["Authorization: Bearer old-token-value", "X-App: 7"]}) + "\n")
        session_mod.sync(proj)
        r = json.loads(open(os.path.join(proj, "credentials.jsonl")).read())
        assert r["auth_headers"][0] == f"Authorization: Bearer {r['token']}" and r["auth_headers"][1] == "X-App: 7"


def test_alias_folds_a_subject_into_an_account(session_mod, proj):
    st = session_mod.load(proj)
    st["accounts"]["sub:abc"] = {"clients": {"web": {"access_token": "t"}}}
    session_mod.save(proj, st)
    session_mod.main(["config", "--project-dir", proj, "--alias", "sub:abc=a1"])
    st = session_mod.load(proj)
    assert "sub:abc" not in st["accounts"] and st["accounts"]["a1"]["clients"]["web"]["access_token"] == "t"
    assert st["config"]["aliases"] == {"sub:abc": "a1"}


def test_render_regenerates_request_unique_headers(session_mod):
    tpl = {"method": "POST", "url": "https://a.example/t", "body": "rt={refresh_token}",
           "headers": [["X-Idempotency-Key", "0f8fad5b-d9cb-469f-a165-70867728950e"], ["X-App", "7"]]}
    r = session_mod.render(tpl, {"refresh_token": "abc"})
    assert r["headers"][0][1] != "0f8fad5b-d9cb-469f-a165-70867728950e" and len(r["headers"][0][1]) == 36
    assert r["headers"][1] == ["X-App", "7"] and r["body"] == "rt=abc"


def test_check_marks_a_rejected_session_and_sync_skips_it(session_mod, proj, oauth, monkeypatch):
    _seed(session_mod, proj, oauth, time.time() + 3000)
    monkeypatch.setattr(session_mod, "send", lambda pd, req, timeout=30: (401, [], b""))
    assert session_mod.main(["check", "--project-dir", proj, "--url", "https://api.acme.example/me"]) == 3
    e = session_mod.load(proj)["accounts"]["a1"]["clients"]["web"]
    assert e["access_rejected"] == 401 and session_mod.entry_state(e) == "refreshable"
    assert session_mod.sync(proj) == []
    assert session_mod.load(proj)["config"]["whoami_url"] == "https://api.acme.example/me"


def test_sync_keeps_one_backup(session_mod, proj, oauth):
    _seed(session_mod, proj, oauth, time.time() + 3000)
    before = open(os.path.join(proj, "credentials.jsonl")).read()
    session_mod.sync(proj)
    assert open(os.path.join(proj, "credentials.jsonl.bak")).read() == before
    assert oct(os.stat(os.path.join(proj, "credentials.jsonl.bak")).st_mode)[-3:] == "600"


def test_a_session_cookie_jwt_travels_as_a_cookie(session_mod, proj):
    tok = jwt(sub="sub-a1", cid="web", exp=int(time.time()) + 9000)
    m = session_mod.extract_tokens(200, [("Set-Cookie", f"app_session={tok}; Path=/; HttpOnly")], b"")
    st = session_mod.load(proj)
    e = st["accounts"].setdefault("a1", {"clients": {}})["clients"].setdefault("web", {})
    session_mod.apply_mint(e, m, time.time(), "caido-login", {})
    session_mod.save(proj, st)
    assert session_mod.auth_header(e) == [f"Cookie: app_session={tok}"]
    with open(os.path.join(proj, "credentials.jsonl"), "w") as fh:
        fh.write(json.dumps({"account": "a1", "token": "bearer-stays",
                             "auth_headers": ["Authorization: Bearer bearer-stays", "Cookie: a=1; app_session=old"]}) + "\n")
    session_mod.sync(proj)
    r = json.loads(open(os.path.join(proj, "credentials.jsonl")).read())
    assert r["token"] == "bearer-stays" and r["auth_headers"][0] == "Authorization: Bearer bearer-stays"
    assert r["auth_headers"][1] == f"Cookie: a=1; app_session={tok}"


def test_sync_flags_an_expired_bearer_beside_a_live_cookie(session_mod, proj):
    tok = jwt(sub="sub-a1", cid="web", exp=int(time.time()) + 9000)
    dead = jwt(sub="sub-a1", exp=int(time.time()) - 100)
    st = session_mod.load(proj)
    st["accounts"]["a1"] = {"clients": {"web": {}}}
    session_mod.apply_mint(st["accounts"]["a1"]["clients"]["web"],
                           session_mod.extract_tokens(200, [("Set-Cookie", f"sid={tok}")], b""), time.time(), "x", {})
    session_mod.save(proj, st)
    with open(os.path.join(proj, "credentials.jsonl"), "w") as fh:
        fh.write(json.dumps({"account": "a1", "token": dead, "auth_headers": [f"Authorization: Bearer {dead}"]}) + "\n")
    session_mod.sync(proj)
    r = json.loads(open(os.path.join(proj, "credentials.jsonl")).read())
    assert "token" not in r and r["token_expired"] == dead and r["auth_headers"] == [f"Cookie: sid={tok}"]


def test_sync_moves_expired_auth_header_lines(session_mod, proj):
    tok = jwt(sub="sub-a1", cid="web", exp=int(time.time()) + 9000)
    dead = jwt(sub="other", exp=int(time.time()) - 100)
    st = session_mod.load(proj)
    st["accounts"]["a1"] = {"clients": {"web": {}}}
    session_mod.apply_mint(st["accounts"]["a1"]["clients"]["web"],
                           session_mod.extract_tokens(200, [("Set-Cookie", f"sid={tok}")], b""), time.time(), "x", {})
    session_mod.save(proj, st)
    with open(os.path.join(proj, "credentials.jsonl"), "w") as fh:
        fh.write(json.dumps({"account": "a1", "auth_headers": [f"Authorization: bearer {dead}", "X-App: 1"]}) + "\n")
    session_mod.sync(proj)
    r = json.loads(open(os.path.join(proj, "credentials.jsonl")).read())
    assert r["auth_headers"] == ["X-App: 1", f"Cookie: sid={tok}"]
    assert r["auth_headers_expired"] == [f"Authorization: bearer {dead}"]


def test_sync_writes_host_bearers_and_repins_its_own_choice(session_mod, proj):
    web, ads = jwt(sub="u", azp="web", exp=int(time.time()) + 900), jwt(sub="u", azp="ads", exp=int(time.time()) + 900)
    st = session_mod.load(proj)
    st["accounts"]["a1"] = {"clients": {"web": {"access_token": web, "access_exp": time.time() + 900, "minted_at": 1},
                                        "ads": {"access_token": ads, "access_exp": time.time() + 900, "minted_at": 2}}}
    st["config"]["host_clients"] = {"api.acme.example": "web", "www.acme.example": "web", "ads.acme.example": "ads"}
    session_mod.save(proj, st)
    with open(os.path.join(proj, "credentials.jsonl"), "w") as fh:
        fh.write(json.dumps({"account": "a1", "token": ads, "session_client": "ads"}) + "\n")
    session_mod.sync(proj)
    r = json.loads(open(os.path.join(proj, "credentials.jsonl")).read())
    assert r["token"] == web                        # the bearer most hosts accept is the default
    assert r["host_auth"] == {"ads.acme.example": f"Authorization: Bearer {ads}"}


def test_storage_state_carries_the_session_cookie_and_fingerprint(session_mod):
    e = {"access_cookie": "sess", "access_token": "TOKEN", "access_exp": 2000000000.5,
         "cookie_header": "a=1; sess=OLD", "source": {"url": "https://www.example.com/login"}}
    st = session_mod.storage_state(e, session_mod._cookie_domain(e), "UA/1", {"sec-ch-ua": "x"})
    jar = {c["name"]: c for c in st["cookies"]}
    assert jar["sess"]["value"] == "TOKEN" and jar["sess"]["expires"] == 2000000000   # the live token wins
    assert jar["a"]["expires"] == -1 and all(c["domain"] == ".example.com" for c in st["cookies"])
    assert st["user_agent"] == "UA/1" and st["fingerprint_headers"] == {"sec-ch-ua": "x"}
