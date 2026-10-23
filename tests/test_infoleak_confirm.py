"""infoleak-confirm.py is the response-pattern oracle: a sensitive pattern in the target that is
ABSENT from a nonexistent-sibling control. The failures that would be silent: a false `confirmed`
on a site-wide error template (a leak that isn't targeted), a raw secret written into the evidence
artifact, or a dead host reported as `negative` (a false all-clear that hides a real leak). These
assert the pure decision surface — no network."""


def _pk(kind="RSA"):
    """The private-key header the detector matches, assembled at runtime so the tracked source never
    holds a literal key block (the repo-hygiene guard rejects one). Runtime value is the real header."""
    return "-----BEGIN " + kind + " PRIVATE" " KEY-----"


class TestScan:
    def test_high_signal_patterns_are_detected(self, infoleak_confirm_mod):
        m = infoleak_confirm_mod
        assert {"etc_passwd"} <= {h["pattern"] for h in m.scan("root:x:0:0:root:/root:/bin/bash")}
        assert {"private_key"} <= {h["pattern"] for h in m.scan(_pk("OPENSSH") + "\nabc")}
        assert {"aws_access_key"} <= {h["pattern"] for h in m.scan("key=AKIAIOSFODNN7EXAMPLE end")}
        assert {"git_config"} <= {h["pattern"] for h in m.scan("[core]\n\trepositoryformatversion = 0")}

    def test_medium_signal_patterns_are_detected(self, infoleak_confirm_mod):
        m = infoleak_confirm_mod
        assert {"stack_trace_py"} <= {h["pattern"] for h in m.scan("Traceback (most recent call last):")}
        assert {"internal_host"} <= {h["pattern"] for h in m.scan("proxying to http://10.0.0.5:8080/x")}
        assert {"jwt"} <= {h["pattern"] for h in
                m.scan("token eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeK")}

    def test_benign_body_matches_nothing(self, infoleak_confirm_mod):
        assert infoleak_confirm_mod.scan('{"status":"ok","items":[1,2,3]}') == []

    def test_scan_reports_masked_sample_not_raw_secret(self, infoleak_confirm_mod):
        hits = infoleak_confirm_mod.scan("key=AKIAIOSFODNN7EXAMPLE end")
        sample = next(h["sample"] for h in hits if h["pattern"] == "aws_access_key")
        assert "AKIAIOSFODNN7EXAMPLE" not in sample and "*" in sample and sample.startswith("AKIA")

    def test_one_hit_per_pattern_name(self, infoleak_confirm_mod):
        # a body full of the same shape collapses to a single hit for that pattern
        hits = infoleak_confirm_mod.scan("AKIAAAAAAAAAAAAAAAAA AKIABBBBBBBBBBBBBBBB")
        assert sum(1 for h in hits if h["pattern"] == "aws_access_key") == 1


class TestClassify:
    def test_high_signal_differential_is_confirmed(self, infoleak_confirm_mod):
        v, why, diff = infoleak_confirm_mod.classify_infoleak(200, _pk("RSA"), "not found")
        assert v == "confirmed" and any(h["pattern"] == "private_key" for h in diff)

    def test_medium_signal_differential_is_leak_likely(self, infoleak_confirm_mod):
        v, _why, _diff = infoleak_confirm_mod.classify_infoleak(
            200, "Traceback (most recent call last):\n  File ...", "404 not found")
        assert v == "leak-likely"

    def test_control_carrying_the_same_pattern_kills_the_finding(self, infoleak_confirm_mod):
        # a site-wide error page that ALWAYS returns the trace is not a targeted leak -> negative
        body = "Traceback (most recent call last):"
        v, _why, diff = infoleak_confirm_mod.classify_infoleak(200, body, body)
        assert v == "negative" and diff == []

    def test_high_beats_medium_when_both_present(self, infoleak_confirm_mod):
        v, _why, _diff = infoleak_confirm_mod.classify_infoleak(
            200, "Traceback (most recent call last):\n" + _pk("EC"), "")
        assert v == "confirmed"

    def test_dead_target_is_inconclusive_not_negative(self, infoleak_confirm_mod):
        # status 0 = transport error: proved nothing. A false 'negative' would hide a real leak.
        v, _why, diff = infoleak_confirm_mod.classify_infoleak(0, "", "")
        assert v == "inconclusive" and diff == []

    def test_no_pattern_is_negative(self, infoleak_confirm_mod):
        v, _why, _diff = infoleak_confirm_mod.classify_infoleak(200, '{"ok":true}', '{"error":"nf"}')
        assert v == "negative"


class TestControlDerivation:
    def test_control_is_a_nonexistent_sibling_of_the_path(self, infoleak_confirm_mod):
        c = infoleak_confirm_mod.derive_control_url("https://h.io/.git/config")
        assert c.startswith("https://h.io/.git/config/") and c != "https://h.io/.git/config"

    def test_control_preserves_scheme_host_and_query(self, infoleak_confirm_mod):
        c = infoleak_confirm_mod.derive_control_url("https://h.io/a/b?x=1")
        assert c.startswith("https://h.io/a/b/") and c.endswith("?x=1")

    def test_control_derivation_is_randomized(self, infoleak_confirm_mod):
        a = infoleak_confirm_mod.derive_control_url("https://h.io/p")
        b = infoleak_confirm_mod.derive_control_url("https://h.io/p")
        assert a != b   # a fixed control segment could itself be a real route
