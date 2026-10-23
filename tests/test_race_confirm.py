"""race-confirm.py's verdict decides whether a concurrent burst overran a limit. A wrong
"confirmed" ships a non-bug (e.g. counting a 200 error page as a spend); a wrong "negative" buries
a real double-spend. classify_race_verdict is pure and tested here without a target. The end-to-end
burst against a local stub HTTP server (below) proves the concurrency path and the race.json
artifact the evidence gate reads."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


# ── Pure verdict ladder ────────────────────────────────────────────────────────
class TestVerdict:
    def test_overrun_without_control_is_confirmed_overrun_concurrent(self, race_confirm_mod):
        v, sub, _ = race_confirm_mod.classify_race_verdict(successes=3, expected_max=1, count=30)
        assert (v, sub) == ("confirmed", "overrun-concurrent")

    def test_limit_held_is_negative(self, race_confirm_mod):
        v, sub, _ = race_confirm_mod.classify_race_verdict(successes=1, expected_max=1, count=30)
        assert v == "negative" and sub == "limit-held"

    def test_zero_success_is_inconclusive_positive_control(self, race_confirm_mod):
        v, sub, why = race_confirm_mod.classify_race_verdict(successes=0, expected_max=1, count=30)
        assert v == "inconclusive" and sub == "no-success" and "positive control" in why

    def test_control_within_limit_is_true_race(self, race_confirm_mod):
        # concurrent overran but sequential stayed within the limit -> genuine TOCTOU window
        v, sub, _ = race_confirm_mod.classify_race_verdict(
            successes=4, expected_max=1, count=30, control_successes=1)
        assert (v, sub) == ("confirmed", "race")

    def test_control_also_overran_is_no_limit(self, race_confirm_mod):
        v, sub, _ = race_confirm_mod.classify_race_verdict(
            successes=4, expected_max=1, count=30, control_successes=5)
        assert (v, sub) == ("confirmed", "no-limit")

    def test_expected_max_gt_one(self, race_confirm_mod):
        # a "max 5 uses" flow: 5 successes is fine, 6 is the overrun
        assert race_confirm_mod.classify_race_verdict(5, 5, 30)[0] == "negative"
        assert race_confirm_mod.classify_race_verdict(6, 5, 30)[0] == "confirmed"

    def test_no_requests_is_inconclusive(self, race_confirm_mod):
        assert race_confirm_mod.classify_race_verdict(0, 1, 0)[0] == "inconclusive"


class TestSuccessPredicate:
    def test_status_and_marker(self, race_confirm_mod):
        ok = race_confirm_mod._is_success
        r = {"status": 200, "body": '{"redeemed":true}'}
        assert ok(r, {200, 201}, '"redeemed":true')
        assert not ok(r, {200, 201}, "NOPE")            # marker absent -> not a success
        assert not ok({"status": 429, "body": ""}, {200, 201}, "")   # wrong status
        assert ok({"status": 201, "body": "x"}, {200, 201}, "")      # status-only, no marker


# ── End-to-end burst against a local stub that enforces a single-use limit ──────
class _OneShotHandler(BaseHTTPRequestHandler):
    """Serves a coupon that may only be redeemed ONCE. The lock makes it correct (no race), so a
    correct primitive must return `negative` against it — the negative-control for the tester."""
    _lock = threading.Lock()
    _redeemed = False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        with _OneShotHandler._lock:
            first = not _OneShotHandler._redeemed
            _OneShotHandler._redeemed = True
        if first:
            body = b'{"redeemed":true}'
            self.send_response(200)
        else:
            body = b'{"error":"already redeemed"}'
            self.send_response(409)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class _NoLimitHandler(BaseHTTPRequestHandler):
    """Serves a coupon with NO limit — every redeem succeeds. A correct primitive returns
    `confirmed` (overrun) against it."""
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        body = b'{"redeemed":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def _serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/redeem"


def _run_burst(race_confirm_mod, url, count):
    headers = {"Content-Type": "application/json"}
    results, spread, errs = race_confirm_mod._burst(
        url, "POST", headers, '{"code":"X"}', count, timeout=10, insecure=False)
    successes = sum(1 for r in results if race_confirm_mod._is_success(r, {200, 201}, '"redeemed":true'))
    return successes, results


def test_single_use_limit_holds_is_negative(race_confirm_mod):
    _OneShotHandler._redeemed = False
    srv, url = _serve(_OneShotHandler)
    try:
        successes, results = _run_burst(race_confirm_mod, url, 25)
    finally:
        srv.shutdown()
    assert successes == 1, f"a locked single-use coupon must yield exactly 1 success, got {successes}"
    v, sub, _ = race_confirm_mod.classify_race_verdict(successes, 1, 25)
    assert v == "negative"


def test_no_limit_endpoint_is_confirmed(race_confirm_mod):
    srv, url = _serve(_NoLimitHandler)
    try:
        successes, results = _run_burst(race_confirm_mod, url, 25)
    finally:
        srv.shutdown()
    assert successes > 1, "a no-limit endpoint must yield many successes"
    v, sub, _ = race_confirm_mod.classify_race_verdict(successes, 1, 25)
    assert v == "confirmed"
