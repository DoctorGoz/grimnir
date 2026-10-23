"""jwt-confirm.py is the token-forgery oracle: a forged token built from the caller's own JWT that
the server ACCEPTS (same success status as the real token) is an auth bypass. The failures that would
be silent: a forgery that a correct verifier would accept anyway (not a real bug), or the dangerous
inverse — calling a rejection a `negative` when the positive control never worked (a false all-clear).
Pure surface only; no network."""
import base64
import hashlib
import hmac
import json

import pytest


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _hs256(header, payload, secret):
    si = (_b64(header) + "." + _b64(payload)).encode()
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), si, hashlib.sha256).digest()).rstrip(b"=").decode()
    return _b64(header) + "." + _b64(payload) + "." + sig


@pytest.fixture
def hs_token():
    return _hs256({"alg": "HS256", "typ": "JWT"}, {"sub": "u1", "role": "user"}, "secret")


class TestDecodeAndForge:
    def test_decode_roundtrips_header_and_payload(self, jwt_confirm_mod, hs_token):
        header, payload, sig = jwt_confirm_mod.decode_jwt(hs_token)
        assert header["alg"] == "HS256" and payload["sub"] == "u1" and sig

    def test_non_jwt_decodes_to_none(self, jwt_confirm_mod):
        assert jwt_confirm_mod.decode_jwt("not.a.jwt") is None
        assert jwt_confirm_mod.decode_jwt("only-one-segment") is None

    def test_alg_none_sets_alg_and_strips_signature(self, jwt_confirm_mod, hs_token):
        forged = jwt_confirm_mod.forge_alg_none(hs_token)
        header, _payload, sig = jwt_confirm_mod.decode_jwt(forged)
        assert header["alg"] == "none" and sig == ""

    def test_sig_stripped_keeps_alg_empties_signature(self, jwt_confirm_mod, hs_token):
        forged = jwt_confirm_mod.forge_sig_stripped(hs_token)
        header, _p, sig = jwt_confirm_mod.decode_jwt(forged)
        assert header["alg"] == "HS256" and sig == ""

    def test_tampered_claim_keeps_original_signature(self, jwt_confirm_mod, hs_token):
        forged = jwt_confirm_mod.forge_tampered_claim(hs_token)
        _h, payload, sig = jwt_confirm_mod.decode_jwt(forged)
        assert payload.get("gnf") == 1 and sig == hs_token.split(".")[2]


class TestWeakSecret:
    def test_finds_a_common_secret(self, jwt_confirm_mod, hs_token):
        assert jwt_confirm_mod.find_weak_secret(hs_token) == "secret"

    def test_strong_secret_is_not_found(self, jwt_confirm_mod):
        strong = _hs256({"alg": "HS256"}, {"sub": "u1"}, "9f3c-not-in-any-wordlist-Zx82")
        assert jwt_confirm_mod.find_weak_secret(strong) is None

    def test_resign_produces_a_token_valid_under_that_secret(self, jwt_confirm_mod, hs_token):
        resigned = jwt_confirm_mod.resign_hs(hs_token, "secret")
        assert jwt_confirm_mod.find_weak_secret(resigned) == "secret"


class TestClassify:
    def test_accepted_forgery_is_confirmed(self, jwt_confirm_mod):
        v, _why, accepted = jwt_confirm_mod.classify_jwt(200, 200, {"alg_none": 200, "sig_stripped": 401})
        assert v == "confirmed" and accepted == ["alg_none"]

    def test_all_rejected_is_negative(self, jwt_confirm_mod):
        v, _why, _a = jwt_confirm_mod.classify_jwt(200, 200, {"alg_none": 401, "sig_stripped": 403})
        assert v == "negative"

    def test_positive_control_failure_is_inconclusive(self, jwt_confirm_mod):
        # real token itself did not succeed -> a 'negative' would be false; forged 200 is meaningless
        v, _why, _a = jwt_confirm_mod.classify_jwt(403, 200, {"alg_none": 200})
        assert v == "inconclusive"


class TestHeaderPlumbing:
    def test_extract_finds_the_jwt(self, jwt_confirm_mod, hs_token):
        assert jwt_confirm_mod.extract_jwt(["Authorization: Bearer " + hs_token]) == hs_token

    def test_extract_ignores_non_jwt_auth(self, jwt_confirm_mod):
        assert jwt_confirm_mod.extract_jwt(["Authorization: Bearer opaque-token-xyz"]) is None

    def test_replace_swaps_only_the_authorization_header(self, jwt_confirm_mod, hs_token):
        out = jwt_confirm_mod.replace_token(
            ["Authorization: Bearer " + hs_token, "X-Env: prod"], "NEW")
        assert out == ["Authorization: Bearer NEW", "X-Env: prod"]
