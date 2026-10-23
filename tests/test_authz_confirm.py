"""authz-confirm.py's verdict is the load-bearing call in every BOLA confirmation: a wrong
"confirmed" ships a non-bug, a wrong "negative" buries a real one. The 4-way differential ladder
is pure and tested here without a target. The positive-control guard (added after the first live
fire recorded a degenerate all-403 as "negative") is the one that stops a broken test setup from
masquerading as a confident negative."""

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def authz_mod():
    spec = importlib.util.spec_from_file_location(
        "grimnir_authz_confirm", REPO / "scripts" / "confirm" / "authz-confirm.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _arm(status, body="", sha="x", length=None):
    return {"status": status, "len": length if length is not None else len(body),
            "sha": sha, "snip": body[:200], "body": body}


class TestVerdictLadder:
    def test_confirmed_on_victim_marker_in_cross_200(self, authz_mod):
        own = _arm(200, "mine", sha="o")
        cross = _arm(200, "here is Lucinda's card", sha="c")
        non = _arm(404, "nf", sha="n")
        v, _ = authz_mod.classify_verdict(own, cross, non, "Lucinda")
        assert v == "confirmed"

    def test_negative_when_cross_denied_and_positive_control_good(self, authz_mod):
        own = _arm(200, "mine", sha="o")
        cross = _arm(403, "forbidden", sha="c")
        non = _arm(404, "nf", sha="n")
        v, _ = authz_mod.classify_verdict(own, cross, non, "")
        assert v == "negative"

    def test_bola_likely_when_cross_200_distinct_from_nonexistent(self, authz_mod):
        own = _arm(200, "mine", sha="o")
        cross = _arm(200, "someone else", sha="c")
        non = _arm(404, "nf", sha="n")
        v, _ = authz_mod.classify_verdict(own, cross, non, "")
        assert v == "bola-likely"

    def test_negative_when_cross_equals_own(self, authz_mod):
        own = _arm(200, "mine", sha="same")
        cross = _arm(200, "mine", sha="same")
        non = _arm(404, "nf", sha="n")
        v, why = authz_mod.classify_verdict(own, cross, non, "")
        assert v == "negative" and "own" in why

    def test_negative_when_cross_mirrors_nonexistent(self, authz_mod):
        own = _arm(200, "mine", sha="o")
        cross = _arm(404, "nf", sha="n")
        non = _arm(404, "nf", sha="n")
        v, _ = authz_mod.classify_verdict(own, cross, non, "")
        assert v == "negative"


class TestPositiveControlGuard:
    def test_all_denied_is_inconclusive_not_negative(self, authz_mod):
        # the real first-fire case: own/cross/nonexistent all 403 (a license/feature gate). A
        # "negative" here would be a false negative — we never established that our own access works.
        arm = _arm(403, "not entitled", sha="z")
        v, why = authz_mod.classify_verdict(dict(arm), dict(arm), dict(arm), "")
        assert v == "inconclusive" and "positive control" in why

    def test_bola_likely_downgraded_when_own_failed(self, authz_mod):
        own = _arm(401, "unauth", sha="o")   # our token doesn't even work
        cross = _arm(200, "data", sha="c")
        non = _arm(404, "nf", sha="n")
        v, _ = authz_mod.classify_verdict(own, cross, non, "")
        assert v == "inconclusive"

    def test_confirmed_stands_even_if_positive_control_weak(self, authz_mod):
        # a victim marker actually returned is positive evidence regardless of the own arm
        own = _arm(403, "weird", sha="o")
        cross = _arm(200, "Lucinda", sha="c")
        non = _arm(404, "nf", sha="n")
        v, _ = authz_mod.classify_verdict(own, cross, non, "Lucinda")
        assert v == "confirmed"


def test_a_page_that_ignores_the_id_is_not_bola(authz_mod):
    """Same server-rendered page for every id, differing only by per-request nonces and the
    reflected id: every arm hashes differently, and the oracle must still read it as one page."""
    import secrets
    def page(i):
        b = (f'<html><script nonce="{secrets.token_urlsafe(18)}">var rid="{secrets.token_hex(16)}";'
             f'var uid="{i}";</script>' + "<div>static drafts shell</div>" * 200 + "</html>")
        return {"status": 200, "len": len(b), "sha": secrets.token_hex(8), "snip": b[:50], "body": b, "id": i}
    v, why = authz_mod.classify_verdict(page("t2_own"), page("t2_vic"), page("t2_zzzz"), None)
    assert v == "negative" and "normalized" in why


def test_a_real_cross_read_still_reads_as_distinct(authz_mod):
    own = {"status": 200, "sha": "a", "body": '{"email":"own@x","drafts":[1,2]}', "id": "1"}
    cross = {"status": 200, "sha": "b", "body": '{"email":"victim@y","drafts":[9,8,7],"secret":"zz"}', "id": "2"}
    non = {"status": 200, "sha": "c", "body": '{"error":"not found"}', "id": "3"}
    assert authz_mod.classify_verdict(own, cross, non, None)[0] == "bola-likely"
