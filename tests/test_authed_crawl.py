"""authed-crawl.py drives an authenticated read-only crawl into asset-map endpoints[]. The Playwright
driver is a thin I/O shell (exercised by a live smoke test, not here); everything that carries a SAFETY
guarantee is pure and tested here: (1) scope containment (host allow/deny, fail-closed on empty allow),
(2) read-only navigation (mutating verbs + logout/delete paths refused), (3) frontier dedup/bounds,
(4) request->endpoint normalization keeps the real url locally but records only field NAMES from bodies,
(5) merge unions params without dropping prior recon, (6) refresh classification picks the right keep-
alive strategy so a human re-login is asked for only when it is genuinely needed."""

import json



class TestScopeContainment:
    def test_wildcard_matches_apex_and_sub(self, authed_crawl_mod):
        assert authed_crawl_mod.host_allowed("api.acme.com", ["*.acme.com"], [])
        assert authed_crawl_mod.host_allowed("acme.com", ["*.acme.com"], [])

    def test_off_scope_and_denied_blocked(self, authed_crawl_mod):
        assert not authed_crawl_mod.host_allowed("evil.com", ["*.acme.com"], [])
        assert not authed_crawl_mod.host_allowed("cdn.acme.com", ["*.acme.com"], ["cdn.acme.com"])

    def test_empty_allow_is_fail_closed(self, authed_crawl_mod):
        assert not authed_crawl_mod.host_allowed("api.acme.com", [], [])

    def test_ip_and_single_label_scoped_exactly(self, authed_crawl_mod):
        assert authed_crawl_mod._default_allow(["http://127.0.0.1:8080/x"]) == ["127.0.0.1"]
        assert authed_crawl_mod._default_allow(["http://localhost/x"]) == ["localhost"]
        assert authed_crawl_mod._default_allow(["https://api.acme.com/x"]) == ["*.acme.com"]

    def test_country_code_second_level_is_not_the_apex(self, authed_crawl_mod):
        """*.com.co would put every .com.co site in scope; the registrant's apex is one label deeper."""
        assert authed_crawl_mod._default_allow(["https://www.acme.com.co/x"]) == ["*.acme.com.co"]
        assert authed_crawl_mod._default_allow(["https://shop.acme.co.uk/"]) == ["*.acme.co.uk"]
        assert authed_crawl_mod._default_allow(["https://www.acme.io/"]) == ["*.acme.io"]
        assert authed_crawl_mod._default_allow(["https://acme.com.co/"]) == ["*.acme.com.co"]

    def test_engagement_scope_governs_with_its_exclusions(self, authed_crawl_mod, tmp_path):
        (tmp_path / "scope.json").write_text(json.dumps(
            {"in_scope": ["*.acme.com.co", "acme.com.co"], "out_of_scope": ["blog.acme.com.co"]}))
        allow = authed_crawl_mod._scope_allow(str(tmp_path))
        assert len(allow) == 1
        assert authed_crawl_mod.host_allowed("api.acme.com.co", allow, [])
        assert authed_crawl_mod.host_allowed("acme.com.co", allow, [])
        assert not authed_crawl_mod.host_allowed("blog.acme.com.co", allow, [])    # scope's exclusion
        assert not authed_crawl_mod.host_allowed("other.com.co", allow, [])        # never *.com.co
        assert not authed_crawl_mod.host_allowed("api.acme.com.co", allow, ["api.acme.com.co"])
        assert authed_crawl_mod._allow_desc(allow) == ["scope:scope.json"]

    def test_path_exclusion_on_an_in_scope_host_is_enforced(self, authed_crawl_mod, tmp_path):
        """host_allowed sees only the host; a banned route on an allowed host must still be refused,
        both when the scope is the allow list and when --allow-host narrowed it (the scope is the gate)."""
        (tmp_path / "scope.md").write_text(
            "## In scope\n- `app.acme.com`\n\n## Out of scope\n- `https://app.acme.com/api/ai_tasks`\n")
        sc = authed_crawl_mod._scope_allow(str(tmp_path))
        assert sc
        m = authed_crawl_mod
        for allow, gate in ((sc, ()), (["app.acme.com"], sc)):
            assert m.classify_route("GET", "https://app.acme.com/api/files", allow, [], gate) == "continue"
            assert m.classify_route("GET", "https://app.acme.com/api/ai_tasks", allow, [], gate) == "abort"
            assert m.classify_route("GET", "https://app.acme.com/api/ai_tasks/7/run", allow, [], gate) == "abort"
            assert not m.should_enqueue("https://app.acme.com/api/ai_tasks", set(), 1, 3, allow, [], gate)
            assert m.should_enqueue("https://app.acme.com/api/files", set(), 1, 3, allow, [], gate)
        # without the gate, --allow-host alone lets the banned route out: the gap this closes
        assert m.classify_route("GET", "https://app.acme.com/api/ai_tasks", ["app.acme.com"], []) == "continue"

    def test_spa_route_change_only_within_one_loaded_origin(self, authed_crawl_mod):
        f = authed_crawl_mod.spa_route_change
        assert f("https://app.acme.com/ui/a", "https://app.acme.com/ui/b?x=1")
        assert not f("https://app.acme.com/ui/a", "https://api.acme.com/ui/b")    # other host
        assert not f("http://app.acme.com/", "https://app.acme.com/ui/b")          # other scheme
        assert not f("about:blank", "https://app.acme.com/ui/b")                   # nothing loaded yet

    def test_cached_static_headers_drop_encoding_length_and_cookies(self, authed_crawl_mod):
        h = authed_crawl_mod.cacheable_headers({"Content-Type": "text/javascript", "Content-Encoding": "br",
                                                "content-length": "10", "Set-Cookie": "a=b", "ETag": "x"})
        assert h == {"Content-Type": "text/javascript", "ETag": "x"}

    def test_no_engagement_scope_falls_back_to_the_start_hosts(self, authed_crawl_mod, tmp_path):
        assert authed_crawl_mod._scope_allow(str(tmp_path)) == []


class TestReadOnlyNavigation:
    def test_mutating_verbs_refused(self, authed_crawl_mod):
        assert authed_crawl_mod.is_safe_nav("GET", "https://a/x")
        for m in ("POST", "PUT", "PATCH", "DELETE"):
            assert not authed_crawl_mod.is_safe_nav(m, "https://a/x")

    def test_logout_and_destructive_paths_refused(self, authed_crawl_mod):
        for p in ("/account/logout", "/signout", "/orgs/1/delete", "/tokens/revoke",
                  "/users/9/deactivate", "/settings/reset"):
            assert not authed_crawl_mod.is_safe_nav("GET", "https://a" + p), p
        assert authed_crawl_mod.is_safe_nav("GET", "https://a/orgs/1/members")


class TestFrontier:
    def test_id_values_collapse_fragment_dropped(self, authed_crawl_mod):
        c = authed_crawl_mod.canonical
        assert c("https://a/p?id=1#frag") == c("https://a/p?id=2")
        assert c("https://a/p") != c("https://a/p?x=1")

    def test_should_enqueue_enforces_scope_depth_dedup(self, authed_crawl_mod):
        se = authed_crawl_mod.should_enqueue
        assert se("https://x.acme.com/new", set(), 1, 3, ["*.acme.com"], [])
        assert not se("https://evil.com/new", set(), 1, 3, ["*.acme.com"], [])          # off scope
        assert not se("https://x.acme.com/deep", set(), 4, 3, ["*.acme.com"], [])        # too deep
        seen = {authed_crawl_mod.canonical("https://x.acme.com/seen")}
        assert not se("https://x.acme.com/seen", seen, 1, 3, ["*.acme.com"], [])         # already seen


class TestRequestNormalization:
    def test_body_field_names_only_no_values(self, authed_crawl_mod):
        f = authed_crawl_mod.extract_body_field_names
        assert f("application/json", '{"role":"admin","user":{"id":9,"plan":"pro"}}') == \
            ["role", "user", "user.id", "user.plan"]
        assert f("application/x-www-form-urlencoded", "role=admin&note=x") == ["role", "note"]
        assert f("application/json", "not json") == []
        assert f("application/json", "") == []

    def test_request_to_endpoint_keeps_real_url_records_shape(self, authed_crawl_mod):
        ep = authed_crawl_mod.request_to_endpoint(
            "PATCH", "https://api.acme.com/orgs/9/members?expand=roles", True, 200,
            "application/json", '{"role":"admin"}')
        assert ep["url"].endswith("expand=roles")          # full fidelity kept LOCALLY (masking is later)
        assert ep["method"] == "PATCH" and ep["parameters"] == ["expand"]
        assert ep["body_fields"] == ["role"] and ep["auth_required"] is True
        assert ep["status_code"] == 200 and ep["source"] == "authed-crawl"

    def test_merge_unions_without_dropping_prior_recon(self, authed_crawl_mod):
        existing = [{"url": "https://a/orgs/9/members", "method": "GET",
                     "parameters": ["expand"], "source": "huginn"}]
        crawled = [{"url": "https://a/orgs/9/members", "method": "GET", "parameters": ["page"],
                    "status_code": 200, "auth_required": True, "source": "authed-crawl"},
                   {"url": "https://a/fetch?u=1", "method": "GET", "parameters": ["u"],
                    "source": "authed-crawl"}]
        m = authed_crawl_mod.merge_endpoints(existing, crawled)
        assert len(m) == 2
        row = next(e for e in m if e["url"].endswith("/members"))
        assert row["parameters"] == ["expand", "page"] and row["status_code"] == 200
        assert row["source"] == "authed-crawl" and row["auth_required"] is True


class TestSpiderInteractionSafety:
    """--spider clicks interactive elements (not just <a href>); these assert the read-only guarantee
    holds at the DOM-interaction layer: destructive-labelled elements and form submits are never clicked,
    and a click that fires a mutating request is route-aborted but has its shape recorded."""

    def test_destructive_labels_not_clicked(self, authed_crawl_mod):
        safe = authed_crawl_mod.is_safe_interaction
        assert safe("View details") and safe("Insights tab") and safe("Expand row")
        for bad in ("Delete account", "Pay now", "Submit", "Checkout", "Invite teammate", "Confirm",
                    "Deactivate", "Log out", "Sign out", "Revoke token", "Remove", "Send message",
                    "Buy credits", "Place order", "Unsubscribe"):
            assert not safe(bad), bad

    def test_moderation_actions_not_clicked_but_their_lists_are(self, authed_crawl_mod):
        """A crawl run as a moderator must not act as one; the lists those actions fill are the
        privileged reads the crawl is for."""
        safe = authed_crawl_mod.is_safe_interaction
        for bad in ("Approve", "Ban user", "Mute", "Leave as moderator", "Lock post", "Block", "Report"):
            assert not safe(bad), bad
        for ok in ("Approved users", "Banned", "Muted", "Mod log", "Moderators"):
            assert safe(ok), ok

    def test_form_auto_submit_refused(self, authed_crawl_mod):
        wsf = authed_crawl_mod.would_submit_form
        ssc = authed_crawl_mod.spider_should_click
        assert wsf("input", "submit", False) and wsf("input", "image", False)
        assert wsf("button", "", True)                    # bare <button> inside a form defaults to submit
        assert not wsf("button", "button", True)          # explicit type=button is safe
        assert not wsf("button", "", False)               # not inside a form
        assert not ssc("button", "", "", True, "Save")    # form submit refused even with a benign label
        assert ssc("div", "button", "", False, "Expand row")

    def test_mutating_click_route_aborted_and_recorded(self, authed_crawl_mod):
        cr = authed_crawl_mod.classify_route
        assert cr("GET", "https://x.acme.com/api/list", ["*.acme.com"], []) == "continue"
        assert cr("POST", "https://x.acme.com/api/pay", ["*.acme.com"], []) == "abort"   # fired click
        assert cr("GET", "https://evil.com/x", ["*.acme.com"], []) == "abort"            # off-scope
        assert cr("GET", "https://x.acme.com/account/logout", ["*.acme.com"], []) == "abort"
        rec = authed_crawl_mod.request_to_endpoint(
            "POST", "https://x.acme.com/api/pay", True, None,
            "application/json", '{"amount":5,"to":"acct_9"}', observed_not_executed=True)
        assert rec["observed_not_executed"] is True and rec["method"] == "POST"
        assert rec["body_fields"] == ["amount", "to"]     # shape recorded (field NAMES only)...
        assert "status_code" not in rec                   # ...but the request was never executed
        assert "observed-not-executed" in rec["tags"]

    def test_heavy_static_assets_dropped_endpoints_kept(self, authed_crawl_mod):
        block = authed_crawl_mod.should_block_resource
        for t in ("image", "media", "font", "IMAGE"):           # bulk of page volume, never endpoints
            assert block(t), t
        for t in ("document", "script", "stylesheet", "xhr", "fetch", "websocket", ""):
            assert not block(t), t                              # endpoint-bearing types are always kept


class TestSessionAndRefresh:
    def test_normalize_keeps_only_auth_headers(self, authed_crawl_mod):
        s = authed_crawl_mod.normalize_session(
            {"cookies": [{"name": "sid", "value": "x"}],
             "headers": {"Authorization": "Bearer x", "User-Agent": "z", "Cookie": "sid=x"}})
        assert set(s["auth_headers"]) == {"Authorization", "Cookie"}   # UA dropped

    def test_refresh_strategy_by_material(self, authed_crawl_mod):
        cr = authed_crawl_mod.classify_refresh
        assert cr({"refresh": {"refresh_token": "r", "token_endpoint": "/oauth/token"}}) == "oauth-refresh"
        assert cr({"cookies": [{"name": "sid"}]}) == "cookie-warm"
        assert cr({}) == "re-login"


class TestFingerprintParity:
    """--spider can present as the real browser that produced the captured/replayed traffic (own-account,
    read-only, throttled self-crawl). These assert we pin only browser-identity headers, not auth or
    per-request ones, and that the session bundle carries UA + client hints through normalization."""

    def test_only_browser_identity_headers_pinned(self, authed_crawl_mod):
        f = authed_crawl_mod.select_fingerprint_headers
        got = f({"User-Agent": "UA", "sec-ch-ua": '"X";v="1"', "Sec-CH-UA-Platform": '"Linux"',
                 "sec-ch-ua-mobile": "?0", "Accept-Language": "en-US", "Accept": "text/html",
                 "sec-fetch-mode": "navigate", "Authorization": "Bearer x", "Cookie": "sid=1"})
        assert got == {"accept-language": "en-US", "sec-ch-ua": '"X";v="1"',
                       "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Linux"'}
        # UA, auth, and per-request headers are NOT returned here (UA goes via context user_agent)
        for excluded in ("user-agent", "authorization", "cookie", "accept", "sec-fetch-mode"):
            assert excluded not in got
        assert f({}) == {}

    def test_session_carries_ua_and_client_hints(self, authed_crawl_mod):
        s = authed_crawl_mod.normalize_session(
            {"cookies": [], "user_agent": "Mozilla/5.0 ... Chrome/155",
             "fingerprint_headers": {"sec-ch-ua": "x", "accept-language": "en-US"}})
        assert s["user_agent"] == "Mozilla/5.0 ... Chrome/155"
        assert s["fingerprint_headers"] == {"sec-ch-ua": "x", "accept-language": "en-US"}


class TestGraphqlReads:
    """--allow-graphql-reads lets a GraphQL READ out of the route interceptor and nothing else."""

    def test_only_reads_on_in_scope_graphql_pass(self, authed_crawl_mod):
        gr = authed_crawl_mod.graphql_read_route
        allow = ["*.acme.com"]
        assert gr("POST", "https://x.acme.com/graphql", '{"query": "query Q { me { id } }"}', allow, [])
        assert gr("POST", "https://x.acme.com/svc/graphql", '{"operation": "ModQueueItems"}', allow, [])
        assert not gr("POST", "https://x.acme.com/graphql", '{"query": "mutation M { x }"}', allow, [])
        assert not gr("POST", "https://x.acme.com/graphql", '{"operation": "BanUser"}', allow, [])
        assert not gr("POST", "https://x.acme.com/graphql", '{"operation": "ModerationAction"}', allow, [])
        assert not gr("POST", "https://evil.com/graphql", '{"query": "{ me { id } }"}', allow, [])
        assert not gr("POST", "https://x.acme.com/api/pay", '{"amount": 5}', allow, [])
        assert not gr("PUT", "https://x.acme.com/graphql", '{"query": "{ me { id } }"}', allow, [])

    def test_operation_names_are_recorded_apart_by_execution(self, authed_crawl_mod):
        r2e = authed_crawl_mod.request_to_endpoint
        sent = r2e("POST", "https://x.acme.com/graphql", True, 200, "application/json", '{"operation": "ModQueue"}')
        held = r2e("POST", "https://x.acme.com/graphql", True, None, "application/json", '{"operation": "BanUser"}',
                   observed_not_executed=True)
        assert sent["graphql_ops"] == ["ModQueue"] and "graphql_ops_not_executed" not in sent
        assert held["graphql_ops_not_executed"] == ["BanUser"] and "graphql_ops" not in held
        merged = authed_crawl_mod.merge_endpoints([sent], [held])
        assert len(merged) == 1 and merged[0]["graphql_ops"] == ["ModQueue"]
        assert merged[0]["graphql_ops_not_executed"] == ["BanUser"]


class TestAuthedTrafficProvenance:
    """The crawl's authenticated requests are authed traffic, like the proxy's: authn lanes replay
    them. A request the interceptor aborted was never sent, and an anonymous one proves nothing."""

    def test_sent_with_auth_is_tagged(self, authed_crawl_mod):
        ep = authed_crawl_mod.request_to_endpoint("GET", "https://api.acme.com/me", True, 200)
        assert "authed-traffic" in ep["tags"]

    def test_anonymous_and_aborted_are_not(self, authed_crawl_mod):
        anon = authed_crawl_mod.request_to_endpoint("GET", "https://api.acme.com/pub", False, 200)
        aborted = authed_crawl_mod.request_to_endpoint("POST", "https://api.acme.com/pay", True, None,
                                                       observed_not_executed=True)
        assert "authed-traffic" not in anon["tags"]
        assert "authed-traffic" not in aborted["tags"]

    def test_a_crawled_read_synthesizes_an_authn_lane(self, authed_crawl_mod):
        from conftest import _load
        synth = _load("grimnir_lane_synth", "scripts/lane-synth.py")
        ep = authed_crawl_mod.request_to_endpoint("GET", "https://api.acme.com/v1/me/orders", True, 200)
        tenant = {"account": "a", "token": "tok-a", "headers": ["Authorization: Bearer tok-a"]}
        lanes, summary = synth.synth_authn_lanes({"endpoints": [ep]}, [tenant])
        assert summary["authed_reads"] == 1 and len(lanes) == 1, summary
        assert lanes[0]["class"] == "authn" and lanes[0]["url"] == "https://api.acme.com/v1/me/orders"
