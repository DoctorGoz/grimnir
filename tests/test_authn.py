"""authn: replay our own authenticated reads without credentials, and as the second account.

The failure that costs most is a false `confirmed` on a public route (hunting Rule 31): the same
page for everyone, or an identifier the URL itself carries. The silent one is a false `negative`
when the owner's own request failed. The synthesizer must never replay our own probes as organic
traffic, nor a request whose secret query values were blanked on export.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EMAIL, UID = "a1@test.example", "t2_owner01"


def arm(status, body):
    return {"status": status, "body": body, "sha": str(hash((status, body))), "len": len(body), "snip": body[:20]}


class TestClassify:
    URL = "https://api.acme.example/v1/me/settings"

    def c(self, m, own, anon, other=None, url=None, ids=()):
        return m.classify(own, anon, other, url or self.URL, [EMAIL], [UID], list(ids))[0]

    def test_private_marker_to_anonymous_confirms(self, authn_confirm_mod):
        body = json.dumps({"email": EMAIL, "id": UID})
        assert self.c(authn_confirm_mod, arm(200, body), arm(200, body)) == "confirmed"

    def test_public_identifier_only_is_a_candidate(self, authn_confirm_mod):
        assert self.c(authn_confirm_mod, arm(200, f'{{"id":"{UID}","x":1}}'), arm(200, f'{{"id":"{UID}"}}')) == "authn-likely"

    def test_marker_carried_by_the_url_proves_nothing(self, authn_confirm_mod):
        url = f"https://api.acme.example/v1/users/{EMAIL}/card"
        body = f'{{"email":"{EMAIL}"}}'
        assert self.c(authn_confirm_mod, arm(200, body), arm(200, body), url=url) != "confirmed"

    def test_denied_anonymous_is_negative(self, authn_confirm_mod):
        own = arm(200, f'{{"email":"{EMAIL}"}}')
        assert self.c(authn_confirm_mod, own, arm(401, "no")) == "negative"
        assert self.c(authn_confirm_mod, own, arm(302, "")) == "negative"

    def test_same_page_for_everyone_is_public(self, authn_confirm_mod):
        page = "<html>catalogue</html>"
        assert self.c(authn_confirm_mod, arm(200, page), arm(200, page), arm(200, page)) == "negative"

    def test_per_account_response_given_to_anonymous_is_a_candidate(self, authn_confirm_mod):
        mine = '{"plan":"pro","items":[7,8]}'
        assert self.c(authn_confirm_mod, arm(200, mine), arm(200, mine), arm(200, '{"plan":"free","items":[]}')) == "authn-likely"

    def test_same_without_markers_or_second_account_is_inconclusive(self, authn_confirm_mod):
        assert self.c(authn_confirm_mod, arm(200, '{"ok":1}'), arm(200, '{"ok":1}')) == "inconclusive"

    def test_failed_positive_control_is_never_negative(self, authn_confirm_mod):
        assert self.c(authn_confirm_mod, arm(500, "err"), arm(401, "no")) == "inconclusive"

    def test_second_account_reading_the_owners_object_confirms(self, authn_confirm_mod):
        url = "https://api.acme.example/v1/accounts/a2_owner77/contacts"
        body = f'{{"contact":"{EMAIL}"}}'
        assert self.c(authn_confirm_mod, arm(200, body), arm(401, "no"), arm(200, body), url=url,
                      ids=["a2_owner77"]) == "confirmed"


class App(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        authed = self.headers.get("Authorization") == "Bearer OWN"
        if self.path == "/me" and not authed:
            return self._send(401, '{"error":"login"}')
        if self.path in ("/me", "/leaky"):   # /leaky forgot its check
            return self._send(200, json.dumps({"email": EMAIL, "id": UID}))
        self._send(404, "{}")

    def _send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


@pytest.fixture
def app():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.mark.parametrize("path,verdict", [("/me", "negative"), ("/leaky", "confirmed")])
def test_oracle_end_to_end(tmp_path, app, path, verdict):
    pd = str(tmp_path)
    out = subprocess.run([sys.executable, os.path.join(REPO, "scripts/confirm/authn-confirm.py"),
                          "--finding-id", "L1", "--project-dir", pd, "--url", app + path,
                          "-H", "Authorization: Bearer OWN", "-H", "Accept: application/json",
                          "--private-marker", EMAIL], capture_output=True, text=True, timeout=60)
    rec = json.load(open(os.path.join(pd, "evidence", "L1", "authn.json")))
    assert rec["verdict"] == verdict, out.stderr
    assert rec["removed_headers"] == ["Authorization"] and EMAIL not in json.dumps(rec["differential"]["anon"]["status"])


def test_oracle_refuses_writes(tmp_path):
    r = subprocess.run([sys.executable, os.path.join(REPO, "scripts/confirm/authn-confirm.py"), "--finding-id", "x",
                        "--project-dir", str(tmp_path), "--method", "POST", "--url", "http://127.0.0.1:9/",
                        "-H", "Authorization: Bearer OWN"], capture_output=True, text=True)
    assert r.returncode == 2 and "reads only" in r.stderr


def ep(url, status=200, tags=("caido", "authed-traffic"), method="GET"):
    return {"url": url, "method": method, "status_code": status, "tags": list(tags)}


class TestSynth:
    TENANTS = [{"account": "A", "username": EMAIL, "user_id": UID, "auth_headers": ["Cookie: sid=aaaa"],
                "resource_ids": {"ad_accounts": "a2_owner77"}},
               {"account": "B", "email": "b1@test.example", "user_id": "t2_other02", "auth_headers": ["Cookie: sid=bbbb"]}]

    def test_one_lane_per_route_and_only_organic_successful_reads(self, lane_synth_mod):
        am = {"endpoints": [
            ep("https://api.acme.example/v1/orders/1001"), ep("https://api.acme.example/v1/orders/1002"),
            ep("https://api.acme.example/v1/orders/NONEXISTENT9"),          # our own probe
            ep("https://api.acme.example/v1/search?q=%7B%7B7*7%7D%7D"),       # our own probe
            ep("https://api.acme.example/v1/cb?code="),                        # blanked secret on export
            ep("https://api.acme.example/v1/gone", status=403),
            ep("https://api.acme.example/v1/write", method="POST"),
            ep("https://api.acme.example/v1/public", tags=("caido",)),
            ep("https://ads.acme.example/v3/ad_accounts/a2_owner77/contacts")]}
        lanes, s = lane_synth_mod.synth_authn_lanes(am, self.TENANTS)
        urls = [l["url"] for l in lanes]
        assert s["authed_reads"] == 3 and s["routes"] == 2 and len(lanes) == 2
        assert "https://api.acme.example/v1/orders/1001" in urls
        own = next(l for l in lanes if "ads." in l["url"])
        assert own["headers"] == ["Cookie: sid=aaaa"] and own["other_headers"] == ["Cookie: sid=bbbb"]
        assert own["private_markers"] == [EMAIL] and UID in own["markers"] and "a2_owner77" in own["own_ids"]

    def test_owner_is_the_account_the_url_names(self, lane_synth_mod):
        am = {"endpoints": [ep("https://api.acme.example/v1/users/t2_other02/prefs")]}
        lanes, _ = lane_synth_mod.synth_authn_lanes(am, self.TENANTS)
        assert lanes[0]["headers"] == ["Cookie: sid=bbbb"] and lanes[0]["private_markers"] == ["b1@test.example"]

    def test_hosts_are_interleaved_under_a_cap(self, lane_synth_mod):
        am = {"endpoints": [ep(f"https://a.acme.example/r{i}") for i in range(5)] +
                           [ep("https://b.acme.example/only")]}
        lanes, _ = lane_synth_mod.synth_authn_lanes(am, self.TENANTS, max_lanes=2)
        assert {l["url"].split("/")[2] for l in lanes} == {"a.acme.example", "b.acme.example"}

    def test_no_session_no_lanes(self, lane_synth_mod):
        lanes, s = lane_synth_mod.synth_authn_lanes({"endpoints": [ep("https://a.acme.example/x")]}, [{"account": "A"}])
        assert lanes == [] and "session" in s["reason"]


def test_gap_report_counts_authn_as_missing_auth(writeup_gaps_mod):
    cov = writeup_gaps_mod.coverage()
    assert writeup_gaps_mod.cell_status("auth-bypass", "unknown", "missing-auth", cov) == "covered"
    assert writeup_gaps_mod.cell_status("auth-bypass", "unknown", "path-normalization", cov) == "partial"


def test_a_wall_in_front_of_everything_is_not_the_check(authn_confirm_mod):
    own, anon = arm(200, f'{{"email":"{EMAIL}"}}'), arm(403, "<html>blocked</html>")
    m = authn_confirm_mod
    assert m.classify(own, anon, None, TestClassify.URL, [EMAIL], [], [], root=arm(403, "blocked"))[0] == "inconclusive"
    assert m.classify(own, anon, None, TestClassify.URL, [EMAIL], [], [], root=arm(404, "nf"))[0] == "negative"


def test_a_walled_host_spends_nothing_for_the_rest_of_the_day(tmp_path):
    from datetime import datetime, timezone
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "authn-walls.json").write_text(
        json.dumps({"127.0.0.1": datetime.now(timezone.utc).date().isoformat()}))
    subprocess.run([sys.executable, os.path.join(REPO, "scripts/confirm/authn-confirm.py"), "--finding-id", "W",
                    "--project-dir", str(tmp_path), "--url", "http://127.0.0.1:9/me",
                    "-H", "Authorization: Bearer OWN"], capture_output=True, text=True, timeout=30)
    rec = json.load(open(tmp_path / "evidence" / "W" / "authn.json"))
    assert rec["verdict"] == "inconclusive" and "no requests sent" in rec["why"]
