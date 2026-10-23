"""Coverage decides whether an engagement can be closed.

Its failure mode is silent inflation: an item counted TESTED that nobody touched turns
"22 of 811 endpoints" into "airtight". Four such bugs shipped before the gate was tested.
"""


class TestHostNormalization:
    def test_scheme_and_trailing_slash_are_stripped(self, coverage_mod):
        n = coverage_mod.normalize_host
        assert n("https://api.example.com/") == n("api.example.com") == n("http://api.example.com")

    def test_case_is_normalized(self, coverage_mod):
        assert coverage_mod.normalize_host("API.Example.COM") == coverage_mod.normalize_host("api.example.com")

    def test_port_and_path_do_not_split_one_host_into_two(self, coverage_mod):
        base = coverage_mod.normalize_host("api.example.com")
        assert coverage_mod.normalize_host("https://api.example.com/v1/orders") == base


class TestBoundaryMatch:
    def test_substring_alone_is_not_a_match(self, coverage_mod):
        """The inflation bug in one word: 'api.example.com' must not be marked tested
        because the corpus mentions 'notapi.example.com'."""
        assert not coverage_mod._boundary_match("api.example.com", "notapi.example.com was scanned")

    def test_a_real_mention_matches(self, coverage_mod):
        assert coverage_mod._boundary_match("api.example.com", "tested api.example.com for BOLA")

    def test_match_at_string_edges(self, coverage_mod):
        assert coverage_mod._boundary_match("api.example.com", "api.example.com")


class TestScopeParsing:
    def test_in_scope_and_out_of_scope_are_separated(self, coverage_mod, tmp_path):
        p = tmp_path / "scope.md"
        p.write_text(
            "# Scope\n\n## In Scope\n- api.example.com\n- app.example.com\n\n"
            "## Out of Scope\n- blog.example.com\n"
        )
        items = coverage_mod.parse_scope_md(p)
        hosts = {i["item"] for i in items}
        assert "api.example.com" in hosts
        assert "blog.example.com" not in hosts, \
            "an out-of-scope host must never become a must-cover item"

    def test_missing_file_returns_empty_not_crash(self, coverage_mod, tmp_path):
        assert coverage_mod.parse_scope_md(tmp_path / "nope.md") == []

    def test_empty_scope_file_is_empty(self, coverage_mod, tmp_path):
        p = tmp_path / "scope.md"
        p.write_text("")
        assert coverage_mod.parse_scope_md(p) == []


class TestKeywords:
    def test_stopwords_and_short_tokens_are_dropped(self, coverage_mod):
        kw = coverage_mod.extract_keywords("the API for the orders endpoint")
        assert "the" not in kw
        assert all(len(k) > 2 for k in kw)

    def test_empty_text_yields_no_keywords(self, coverage_mod):
        assert coverage_mod.extract_keywords("") == []


class TestAppIdVsDomain:
    """Bundle ids are reverse-DNS (com.acme.app); hostnames end in a TLD. Confusing the
    two sends a scope item to the wrong corpus, so it resolves UNTOUCHED when it was
    tested (or the reverse) -- the coverage gate's silent-inflation failure mode."""

    def _kind(self, coverage_mod, tmp_path, line):
        p = tmp_path / "scope.md"
        p.write_text(f"# Scope\n\n## In Scope\n- {line}\n")
        items = coverage_mod.parse_scope_md(p)
        return items[0]["scope_kind"] if items else None

    def test_bare_app_subdomain_is_a_domain(self, coverage_mod, tmp_path):
        """`app.<domain>` is one of the most common hostnames in any scope. Its own first
        label supplies 'app' context, and a bare bullet supplies no domain context, so it
        was classified as a mobile bundle id."""
        assert self._kind(coverage_mod, tmp_path, "`app.example.com`") == "domain"

    def test_bare_api_subdomain_is_a_domain(self, coverage_mod, tmp_path):
        assert self._kind(coverage_mod, tmp_path, "`api.example.com`") == "domain"

    def test_reverse_dns_bundle_id_is_still_an_app_id(self, coverage_mod, tmp_path):
        assert self._kind(coverage_mod, tmp_path, "`com.example.android` - Android app") == "app-id"

    def test_bundle_id_ending_in_app_is_still_an_app_id(self, coverage_mod, tmp_path):
        assert self._kind(coverage_mod, tmp_path, "`com.acme.app` - Play Store package") == "app-id"

    def test_app_subdomain_with_explicit_app_context_is_still_a_domain(self, coverage_mod, tmp_path):
        """Even when the row mentions mobile, a name ending in a web TLD is a host."""
        assert self._kind(coverage_mod, tmp_path, "`app.example.com` - mobile web view") == "domain"
