"""Tier differential (function-level authorization): the oracle's verdicts, the privileged-route
set, and the attribution it is built from.

The failures worth guarding are false confirmations: a page every member sees, a viewer's own name
in the page chrome, or an app shell that renders the same for any scope, each read as a bypass.
"""
import hashlib
import json


def arm(status, body):
    return {"status": status, "len": len(body), "sha": hashlib.sha256(body.encode()).hexdigest()[:16],
            "snip": body[:40], "body": body}


URL = "https://x.example/mod/acme/queue"
HIGH = arm(200, "<h1>queue for hi_user</h1> item: removal-note-7f3a reported by z")


class TestClassify:
    def test_failed_positive_control_is_inconclusive(self, tier_confirm_mod):
        v, *_ = tier_confirm_mod.classify(arm(403, "no"), HIGH, arm(403, ""), URL)
        assert v == "inconclusive"

    def test_low_tier_denied_is_negative(self, tier_confirm_mod):
        for st in (401, 403, 404, 302):
            assert tier_confirm_mod.classify(HIGH, arm(st, "no"), arm(403, ""), URL)[0] == "negative"

    def test_privileged_marker_in_low_confirms(self, tier_confirm_mod):
        low = arm(200, "<h1>queue for lo_user</h1> item: removal-note-7f3a reported by z")
        v, *_ = tier_confirm_mod.classify(HIGH, low, arm(403, ""), URL, markers=["removal-note-7f3a"])
        assert v == "confirmed"

    def test_marker_the_anonymous_caller_also_gets_does_not_confirm(self, tier_confirm_mod):
        low = arm(200, "<h1>queue for lo_user</h1> item: removal-note-7f3a reported by z")
        anon = arm(200, "public page removal-note-7f3a")
        v, *_ = tier_confirm_mod.classify(HIGH, low, anon, URL, markers=["removal-note-7f3a"],
                                          idents=["hi_user", "lo_user"])
        assert v != "confirmed"

    def test_viewer_names_are_blanked_before_comparing(self, tier_confirm_mod):
        low = arm(200, "<h1>queue for lo_user</h1> item: removal-note-7f3a reported by z")
        assert tier_confirm_mod.classify(HIGH, low, arm(403, ""), URL)[0] == "negative"   # names differ
        v, *_ = tier_confirm_mod.classify(HIGH, low, arm(403, ""), URL, idents=["hi_user", "lo_user"])
        assert v == "tier-likely"

    def test_public_page_is_negative(self, tier_confirm_mod):
        v, why, _ = tier_confirm_mod.classify(HIGH, HIGH, HIGH, URL)
        assert v == "negative" and "public" in why

    def test_restricted_view_is_negative(self, tier_confirm_mod):
        low = arm(200, "<h1>You do not have permission to view this page</h1>")
        assert tier_confirm_mod.classify(HIGH, low, arm(403, ""), URL, markers=["removal-note-7f3a"])[0] == "negative"

    def test_low_matching_the_nonexistent_scope_is_negative(self, tier_confirm_mod):
        """A big page whose privileged section is small passes the similarity bar against high; the
        nonexistent-scope arm shows low got the generic view."""
        shell = "<nav>" + "chrome " * 4000 + "</nav>"
        high = arm(200, shell + "<ul>queue item removal-note-7f3a</ul>")
        low = arm(200, shell + "<p>not a moderator</p>")
        v, *_ = tier_confirm_mod.classify(high, low, arm(403, ""), URL, scoped=low)
        assert v == "negative"

    def test_high_tier_shell_is_inconclusive_not_negative(self, tier_confirm_mod):
        """When the high tier's own page is the same for a scope that does not exist, the page holds
        no scope data (it loads from another request), so a differing low view proves nothing."""
        shell = "<nav>" + "chrome " * 4000 + "</nav>"
        high = arm(200, shell + "<b>hi_user</b>")
        low = arm(200, shell + "<p>lo_user is not a moderator</p>")
        v, why, _ = tier_confirm_mod.classify(high, low, arm(403, ""), URL, idents=["hi_user", "lo_user"],
                                              scoped=low, high_scoped=high)
        assert v == "inconclusive" and "high tier" in why

    def test_derived_markers_see_a_small_privileged_section(self, tier_confirm_mod):
        """A few-kilobyte privileged section in a 300 KB page passes the similarity bar against the
        nonexistent-scope page; the tokens only the real scope's page carries still tell low's view
        apart. Low carrying none of them is negative, not an app shell."""
        shell = "<nav>" + "chrome " * 4000 + "</nav>"
        data = "<ul>" + " ".join(f"queueitem{i} reporter{i}" for i in range(10)) + "</ul>"
        high = arm(200, shell + data + " nonce1234aa")
        again = arm(200, shell + data + " nonce5678bb")
        high_scoped = arm(200, shell + "<p>empty queue</p>")
        low = arm(200, shell + "<p>not a moderator of acme</p>")
        v, why, notes = tier_confirm_mod.classify(high, low, arm(403, ""), URL, scoped=low,
                                                  high_scoped=high_scoped, high_again=again, scope_token="acme")
        assert v == "negative" and notes["derived_markers"] == 20 and notes["low_carries"] == 0

    def test_low_carrying_the_scope_data_is_tier_likely_never_confirmed(self, tier_confirm_mod):
        shell = "<nav>" + "chrome " * 4000 + "</nav>"
        data = "<ul>" + " ".join(f"queueitem{i} reporter{i}" for i in range(10)) + "</ul>"
        high, high_scoped = arm(200, shell + data), arm(200, shell + "<p>empty queue</p>")
        low = arm(200, shell + data + "<i>lo_user</i>")
        v, *_ = tier_confirm_mod.classify(high, low, arm(403, ""), URL, high_scoped=high_scoped,
                                          high_again=high, scope_token="acme")
        assert v == "tier-likely"

    def test_noise_and_the_scope_name_are_not_derived_markers(self, tier_confirm_mod):
        """Tokens a repeat of the high request does not carry are per-request noise, and tokens
        naming the scope are echoed into every page: neither counts, so no verdict is drawn."""
        shell = "<nav>" + "chrome " * 4000 + "</nav>"
        high = arm(200, shell + " /r/acme/ acme-icon tokenAAAA1 tokenAAAA2 tokenAAAA3 tokenAAAA4 tokenAAAA5")
        again = arm(200, shell + " /r/acme/ acme-icon tokenBBBB1 tokenBBBB2 tokenBBBB3 tokenBBBB4 tokenBBBB5")
        assert tier_confirm_mod.derived_markers(high, arm(200, shell), arm(403, ""), (), again, "acme") == set()
        v, *_ = tier_confirm_mod.classify(high, arm(200, shell + " other"), arm(403, ""), URL,
                                          high_scoped=arm(200, shell), high_again=again, scope_token="acme")
        assert v == "inconclusive"

    def test_app_shell_the_same_for_a_nonexistent_scope_is_inconclusive(self, tier_confirm_mod):
        v, *_ = tier_confirm_mod.classify(HIGH, HIGH, arm(403, ""), URL, scoped=HIGH)
        assert v == "inconclusive"


def _cred(label, rank, uid, cookie, **kw):
    return {"account": label, "user_id": uid, "tier_rank": rank, "auth_headers": [f"Cookie: s={cookie}"], **kw}


class TestSynth:
    def test_privileged_set_is_high_only_routes_naming_the_scope(self, lane_synth_mod):
        traffic = [
            {"url": "https://x.example/mod/acme/queue", "method": "GET", "tags": ["authed-traffic"], "accounts": {"B": 200}},
            {"url": "https://x.example/mod/acme/log", "method": "GET", "tags": ["authed-traffic"], "accounts": {"B": 200, "A": 403}},
            {"url": "https://x.example/r/acme/feed", "method": "GET", "tags": ["authed-traffic"], "accounts": {"B": 200, "A": 200}},
            {"url": "https://x.example/docs/intro", "method": "GET", "tags": ["authed-traffic"], "accounts": {"B": 200}},
            {"url": "https://x.example/mod/acme/rules", "method": "GET", "tags": ["authed-traffic"], "accounts": {"B": 500}},
        ]
        tenants = [_cred("A", 1, "u_aaaa", "LOW"),
                   _cred("B", 2, "u_bbbb", "HIGH", tier_scope="acme", tier_markers=["note-7f3a"])]
        lanes, summary = lane_synth_mod.synth_tier_lanes(traffic, tenants)
        assert [l["url"] for l in lanes] == ["https://x.example/mod/acme/queue"], summary
        lane = lanes[0]
        assert lane["class"] == "tier" and lane["headers"] == ["Cookie: s=HIGH"]
        assert lane["other_headers"] == ["Cookie: s=LOW"] and lane["scope_token"] == "acme"
        assert lane["privileged_markers"] == ["note-7f3a"] and {"u_aaaa", "u_bbbb"} <= set(lane["idents"])

    def test_graphql_reads_only_the_high_tier_made_become_post_lanes(self, lane_synth_mod):
        def op(name, kind, accts, scope="acme"):
            return {"url": "https://x.example/graphql", "operation": name, "kind": kind, "accounts": accts,
                    "samples": {"B": {"operation": name, "variables": {"sub": scope}, "csrf_token": ""}},
                    "blanked": ["csrf_token"]}
        ops = [op("ModQueue", "read-likely", {"B": 200}),
               op("BanUser", "write-likely", {"B": 200}),            # never a read lane
               op("SubredditRules", "read-likely", {"B": 200, "A": 200}),   # the member reads it too
               op("Trophies", "read-likely", {"B": 200}, scope="other")]    # not about the scope
        tenants = [_cred("A", 1, "u_aaaa", "LOW"), _cred("B", 2, "u_bbbb", "HIGH", tier_scope="acme")]
        lanes, summary = lane_synth_mod.synth_tier_lanes([], tenants, graphql_ops=ops)
        assert [l["graphql_operation"] for l in lanes] == ["ModQueue"], summary
        lane = lanes[0]
        assert lane["method"] == "POST" and json.loads(lane["body"])["operation"] == "ModQueue"
        assert lane["csrf_field"] == lane["csrf_cookie"] == "csrf_token" and lane["scope_token"] == "acme"

    def test_one_tier_is_not_enough(self, lane_synth_mod):
        lanes, summary = lane_synth_mod.synth_tier_lanes(
            [{"url": "https://x.example/a", "accounts": {"B": 200}, "tags": ["authed-traffic"]}],
            [_cred("A", 1, "u_aaaa", "L"), _cred("B", 1, "u_bbbb", "H")])
        assert not lanes and "tier_rank" in summary["reason"]


class TestAttribution:
    def test_jwt_subject_names_the_account(self, caido_export_mod):
        import base64
        b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        tok = f"{b({'alg': 'RS256'})}.{b({'sub': 'u_bbbb'})}.sig"
        index = [("A", {"u_aaaa"}), ("B", {"u_bbbb"})]
        assert caido_export_mod.account_of([("Cookie", f"x=1; s={tok}")], index, {}) == "B"
        assert caido_export_mod.account_of([("Authorization", "Bearer opaque-token-0123456789")], index,
                                           {"opaque-token-0123456789": "A"}) == "A"
        assert caido_export_mod.account_of([("Cookie", "x=1")], index, {}) == ""
