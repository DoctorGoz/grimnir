"""scope.py is the one in-scope decision for recon, corpus build, lane synthesis, and firing.

Its failure modes are asymmetric. Over-excluding loses a lane; over-including fires at a host the
program never authorized. So these tests lean on the exclusion side: an excluded subdomain under a
wildcard, a third-party host, a prose summary that over-generalizes, and an engagement with no scope
at all (fail closed, never `in`).
"""
import json

import pytest


def _scope(scope_mod, *inc, out=()):
    return scope_mod.Scope(project_dir="",
                           in_patterns=[scope_mod.parse_pattern(t, "t") for t in inc],
                           out_patterns=[scope_mod.parse_pattern(t, "t") for t in out])


class TestPatternParsing:
    @pytest.mark.parametrize("tok", ["*", "*.com", "acme.*", "app.js", "notes.md", "alice@acme.example",
                                     "two words", "localhost", "127.0.0.1", "com"])
    def test_non_targets_are_rejected(self, scope_mod, tok):
        assert scope_mod.parse_pattern(tok, "t") is None

    def test_scheme_port_and_bold_are_stripped(self, scope_mod):
        p = scope_mod.parse_pattern("**https://api.acme.example:443/**", "t")
        assert p.host == "api.acme.example" and p.path == ""

    def test_loopback_only_with_opt_in(self, scope_mod):
        assert scope_mod.parse_pattern("127.0.0.1", "t", allow_loopback=True) is not None

    def test_private_cidr_is_allowed(self, scope_mod):
        assert scope_mod.parse_pattern("10.10.10.0/24", "t") is not None


class TestMatching:
    def test_wildcard_matches_subdomains_not_apex(self, scope_mod):
        s = _scope(scope_mod, "*.acme.example")
        assert s.check("https://a.b.acme.example/x").in_scope
        assert not s.check("https://acme.example/").in_scope

    def test_exact_exclusion_beats_wildcard(self, scope_mod):
        s = _scope(scope_mod, "*.acme.example", out=("pay.acme.example",))
        v = s.check("https://pay.acme.example/checkout")
        assert not v.in_scope and v.code == "oos" and "excluded" in v.reason

    def test_exact_inclusion_beats_broad_exclusion(self, scope_mod):
        s = _scope(scope_mod, "api.acme.example", out=("*.acme.example",))
        assert s.check("https://api.acme.example/v1").in_scope
        assert not s.check("https://blog.acme.example/").in_scope

    def test_tie_goes_to_exclusion(self, scope_mod):
        s = _scope(scope_mod, "api.acme.example", out=("api.acme.example",))
        assert not s.check("https://api.acme.example/").in_scope

    def test_path_exclusion_is_more_specific_than_its_host(self, scope_mod):
        s = _scope(scope_mod, "api.acme.example", out=("api.acme.example/admin",))
        assert s.check("https://api.acme.example/v1/users").in_scope
        assert not s.check("https://api.acme.example/admin/users").in_scope

    def test_mid_label_wildcard_matches_one_label(self, scope_mod):
        s = _scope(scope_mod, "gw.*.acme.example")
        assert s.check("https://gw.eu-1.acme.example/").in_scope
        assert not s.check("https://gw.a.b.acme.example/").in_scope

    def test_third_party_host_is_out(self, scope_mod):
        assert _scope(scope_mod, "*.acme.example").check("https://cdn.thirdparty.example/x").code == "oos"

    def test_cidr(self, scope_mod):
        s = _scope(scope_mod, "10.10.10.0/24")
        assert s.check("http://10.10.10.5:8080/").in_scope and not s.check("http://10.10.11.5/").in_scope

    def test_no_scope_fails_closed(self, scope_mod):
        v = _scope(scope_mod).check("https://api.acme.example/")
        assert not v.in_scope and v.code == "no-scope"

    def test_garbage_url(self, scope_mod):
        assert _scope(scope_mod, "*.acme.example").check("").code == "bad-url"


SCOPE_MD = """# Scope — acme

## In scope
| Asset | Type | Notes |
|-------|------|-------|
| `*.acme.example` | WILDCARD | mirrors `cdn.vendor.example` |
| `api.acme.example` | URL | primary |
- partner.acme-partner.example (all paths)

## Auth / credentials
- Login via `login.idp.example` (third-party IdP)

## Out of scope
`pay.acme.example` (billing), `status.acme.example`
- *.legacy.acme.example
- Self-XSS, clickjacking

## Rate limit / proxy
- Proxy at `http://127.0.0.1:8080`
"""


H1_SCOPE_MD = """# Scope — acme

## In scope (bounty-eligible)
- [URL] api.acme.example
- [WILDCARD] *.acme.example
- [GOOGLE_PLAY_APP_ID] com.acme.android
- [APPLE_STORE_APP_ID] com.acme.ios
- [HARDWARE] Acme Terminal
- [OTHER] Leaked Credentials

## In scope, NO bounty
- [WILDCARD] *.acme-legacy.example
- [WILDCARD] acmeexperience.com.*

## Out of scope
- [URL] status.acme.example
- Deeplinks: acme://webview?url=
"""


class TestH1AssetTypeTags:
    """The shape a HackerOne structured-scope pull produces. Every bullet leads with its asset
    type, which `_line_tokens` took as the lead token — `[URL]` is not a host, so parse_pattern
    rejected every line and the file failed closed to no-scope."""

    def test_tagged_scope_md_parses(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(H1_SCOPE_MD)
        s = scope_mod.load(str(tmp_path))
        assert s.ok
        assert s.summary()["in_scope"] == ["*.acme.example", "api.acme.example"]
        out = s.summary()["out_of_scope"]
        # "no bounty" is an out-of-scope heading, so its wildcard is an exclusion...
        assert "status.acme.example" in out and "*.acme-legacy.example" in out
        # ...while an app id names no network asset on either side of the gate.
        assert not any(r.startswith("com.acme.") for r in out)
        # A wildcard registrable tail parses to nothing: fail closed, never a scope of its own.
        assert not any(r.startswith("acmeexperience") for r in out)

    def test_check_verdicts_on_tagged_scope(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(H1_SCOPE_MD)
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://shop.acme.example/x").in_scope
        assert not s.check("https://www.acme-legacy.example/").in_scope
        assert not s.check("https://com.acme.android/").in_scope
        # The exact exclusion beats the wildcard that would otherwise cover status.
        v = s.check("https://status.acme.example/")
        assert not v.in_scope and v.code == "oos" and "excluded by" in v.reason

    def test_tag_in_a_table_row_first_cell(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(
            "## In scope\n| Asset | Type |\n|---|---|\n| [URL] api.acme.example | notes |\n")
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://api.acme.example/v1").in_scope
        assert not s.check("https://other.acme.example/").in_scope

    def test_backticked_and_bold_tag_variants(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(
            "## In scope\n"
            "- `[URL]` api.acme.example\n"
            "- **[WILDCARD]** *.acme.example\n"
            "- **[API]** api2.acme.example\n"
            "- `[GOOGLE_PLAY_APP_ID]` com.acme.android\n")
        s = scope_mod.load(str(tmp_path))
        # An unknown TYPE strips and parses; a backticked non-network tag still yields nothing.
        assert s.summary()["in_scope"] == ["*.acme.example", "api.acme.example", "api2.acme.example"]

    def test_apex_url_tag_covers_only_the_apex(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text("## In scope\n- [URL] acme.example\n")
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://acme.example/").in_scope
        assert not s.check("https://www.acme.example/").in_scope

    def test_app_id_tag_is_no_exclusion_either(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(
            "## In scope\n- [URL] api.acme.example\n\n"
            "## Out of scope\n- [GOOGLE_PLAY_APP_ID] com.acme.android\n"
            "- [APPLE_STORE_APP_ID] `com.acme.ios`\n")
        s = scope_mod.load(str(tmp_path))
        assert s.summary()["out_of_scope"] == []

    def test_non_asset_sections_still_contribute_no_tagged_tokens(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(
            "## In scope\n- [URL] api.acme.example\n\n"
            "## Auth / credentials\n- [URL] login.idp.example\n")
        s = scope_mod.load(str(tmp_path))
        assert s.summary()["in_scope"] == ["api.acme.example"]


class TestScopeMd:
    def test_sections_rows_and_notes(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(SCOPE_MD)
        s = scope_mod.load(str(tmp_path))
        inc = s.summary()["in_scope"]
        out = s.summary()["out_of_scope"]
        assert "*.acme.example" in inc and "api.acme.example" in inc
        assert "partner.acme-partner.example" in inc
        # A notes column, an auth section, and a proxy bullet never put a host in scope.
        assert not any("vendor" in r or "idp" in r or "127.0.0.1" in r for r in inc)
        assert {"pay.acme.example", "status.acme.example", "*.legacy.acme.example"} <= set(out)
        assert not s.check("https://pay.acme.example/").in_scope
        assert not s.check("https://old.legacy.acme.example/").in_scope
        assert s.check("https://www.acme.example/").in_scope

    def test_out_of_scope_prose_naming_an_in_scope_wildcard_is_not_an_exclusion(self, scope_mod, tmp_path):
        (tmp_path / "scope.md").write_text(
            "## In scope\n| Asset | Type |\n|---|---|\n| `*.acme.example` | WILDCARD |\n\n"
            "## Out of scope\nNote `*.acme.example` is a wildcard but the exclusions govern.\n"
            "- `pay.acme.example`\n")
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://www.acme.example/").in_scope
        assert not s.check("https://pay.acme.example/").in_scope
        assert s.summary()["ignored_self_references"] == ["*.acme.example"]

    @pytest.mark.parametrize("note", ["not listed OOS, so tested", "not marked as out of scope",
                                      "absent from the program exclusion list"])
    def test_negated_oos_note_on_an_in_scope_line_keeps_it_in_scope(self, scope_mod, tmp_path, note):
        (tmp_path / "scope.md").write_text(
            f"## In scope\n- `www.acme.example`\n- `s3.acme.example` ({note})\n"
            "- `old.acme.example` (OOS since the migration)\n")
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://s3.acme.example/").in_scope
        assert not s.check("https://old.acme.example/").in_scope

    def test_missing_scope_md_is_no_scope(self, scope_mod, tmp_path):
        s = scope_mod.load(str(tmp_path))
        assert not s.ok and s.check("https://api.acme.example/").code == "no-scope"


class TestMachineSources:
    def test_structured_scope_is_authoritative_for_inclusion(self, scope_mod, tmp_path):
        """A prose summary ("all `*.acme.example`") must not widen an explicit-host-list program."""
        (tmp_path / "scope.md").write_text("## Scope summary\n- all `*.acme.example` hosts\n")
        (tmp_path / "recon").mkdir()
        (tmp_path / "recon" / "h1-structured-scopes.json").write_text(json.dumps({"data": {"team": {
            "structured_scopes": {"edges": [
                {"node": {"asset_identifier": "www.acme.example", "asset_type": "URL",
                          "eligible_for_submission": True}},
                {"node": {"asset_identifier": "pay.acme.example", "asset_type": "URL",
                          "eligible_for_submission": False}},
                {"node": {"asset_identifier": "com.acme.app", "asset_type": "GOOGLE_PLAY_APP_ID",
                          "eligible_for_submission": True}}]}}}}))
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://www.acme.example/").in_scope
        assert not s.check("https://other.acme.example/").in_scope
        assert not s.check("https://pay.acme.example/").in_scope
        assert "com.acme.app" not in s.summary()["in_scope"]

    def test_rest_and_bare_list_shapes(self, scope_mod, tmp_path):
        item = {"attributes": {"asset_identifier": "http://api.acme.example, admin.acme.example",
                               "asset_type": "URL", "eligible_for_submission": True}}
        (tmp_path / "h1-scope.json").write_text(json.dumps([item]))
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://api.acme.example/").in_scope and s.check("https://admin.acme.example/").in_scope
        (tmp_path / "h1-scope.json").write_text(json.dumps({"data": [item]}))
        assert scope_mod.load(str(tmp_path)).check("https://api.acme.example/").in_scope

    def test_plain_lists_and_scope_json_override(self, scope_mod, tmp_path):
        (tmp_path / "recon").mkdir()
        (tmp_path / "recon" / "in-scope-urls.txt").write_text("# hosts\nwww.acme.example\napi.acme.example\n")
        (tmp_path / "recon" / "out-of-scope.txt").write_text("api.acme.example\n")
        (tmp_path / "scope.json").write_text(json.dumps({"in_scope": ["lab.acme.example"]}))
        s = scope_mod.load(str(tmp_path))
        assert s.check("https://www.acme.example/").in_scope
        assert not s.check("https://api.acme.example/").in_scope
        assert s.check("https://lab.acme.example/").in_scope


class TestCli:
    def test_check_exit_codes(self, tmp_path):
        import subprocess, sys
        from pathlib import Path
        script = str(Path(__file__).resolve().parent.parent / "scripts" / "scope.py")
        run = lambda *a: subprocess.run([sys.executable, script, *a], capture_output=True, text=True)
        assert run("check", "--project-dir", str(tmp_path), "https://a.acme.example").returncode == 4
        (tmp_path / "scope.json").write_text(json.dumps({"in_scope": ["*.acme.example"]}))
        assert run("check", "--project-dir", str(tmp_path), "https://a.acme.example").returncode == 0
        assert run("check", "--project-dir", str(tmp_path), "https://x.other.example").returncode == 3
        p = subprocess.run([sys.executable, script, "filter", "--project-dir", str(tmp_path)],
                           input="a.acme.example\nx.other.example\n", capture_output=True, text=True)
        assert p.stdout.split() == ["a.acme.example"]
