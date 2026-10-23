"""WAF arsenal — offline, deterministic tests.

The arsenal's whole value is being a scalpel, not a sprayer: variant selection must be
gated by reflection context and ordered by WAF effectiveness, reproducibly and with no
network. A silent regression here (SQL comments leaking into an HTML context, a
technique mis-tagged, fingerprint confidence drifting) turns targeted evasion back into
noise, so these are pinned.
"""
import sys
from pathlib import Path

# the arsenal is a package under specter/scripts/waf
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "specter" / "scripts"))
from waf import catalog, context, fingerprint  # noqa: E402


class TestEncodingCatalog:
    def test_original_is_rank_zero(self):
        vs = catalog.encode_payload("' OR 1=1-- -", contexts=["sql_string"])
        assert vs[0].rank == 0 and vs[0].technique == "original"
        assert vs[0].payload == "' OR 1=1-- -"

    def test_can_drop_original(self):
        vs = catalog.encode_payload("abc", include_original=False)
        assert all(v.technique != "original" for v in vs)

    def test_context_gate_excludes_sql_comment_in_html(self):
        names = [v.technique for v in
                 catalog.encode_payload("' OR 1=1 x", contexts=["html_text"])]
        assert "sql_comment_ws" not in names  # SQL technique must not fire in HTML

    def test_context_gate_includes_sql_comment_in_sql(self):
        names = [v.technique for v in
                 catalog.encode_payload("' OR 1=1 x", contexts=["sql_string"])]
        assert "sql_comment_ws" in names

    def test_js_context_excludes_html_entities(self):
        names = [v.technique for v in
                 catalog.encode_payload('";alert(1)//', contexts=["script_dq"])]
        assert "html_entity_dec" not in names and "html_entity_hex" not in names

    def test_waf_effectiveness_pulls_technique_forward(self):
        # double_url_encode is effective vs cloudflare; it should outrank a generic-only
        # technique when the WAF is cloudflare.
        vs = catalog.encode_payload("<x>", waf="cloudflare", contexts=["html_text"])
        ranks = {v.technique: v.rank for v in vs}
        assert ranks.get("double_url_encode", 99) < ranks.get("null_byte", 100)

    def test_noop_encoder_dropped(self):
        # mixed_case on a payload with no keyword/letters changes nothing -> excluded
        vs = catalog.encode_payload("1234", contexts=["sql_string"])
        assert "mixed_case" not in [v.technique for v in vs]

    def test_max_variants_and_tier_respected(self):
        vs = catalog.encode_payload("<script>alert(1)</script>", max_variants=4)
        assert len(vs) <= 4
        vs2 = catalog.encode_payload("<script>alert(1)</script>", max_tier=1,
                                     include_original=False)
        assert all(v.tier <= 1 for v in vs2)

    def test_deterministic(self):
        a = catalog.encode_payload("' OR 1=1", waf="modsecurity", contexts=["sql_string"])
        b = catalog.encode_payload("' OR 1=1", waf="modsecurity", contexts=["sql_string"])
        assert [(v.technique, v.payload) for v in a] == [(v.technique, v.payload) for v in b]

    def test_url_encode_actually_encodes(self):
        vs = catalog.encode_payload("<x>", contexts=["html_text"])
        url = next(v for v in vs if v.technique == "url_encode")
        assert url.payload == "%3C%78%3E"


class TestReflectionContext:
    def test_html_attribute_double_quote(self):
        body = '<input value="grzABC123">'
        res = context.analyze_reflection(body, "grzABC123")
        assert "html_attr_dq" in res["contexts"] and res["reflected"]

    def test_script_single_quote(self):
        body = "<script>var x='grzABC123';</script>"
        res = context.analyze_reflection(body, "grzABC123")
        assert "script_sq" in res["contexts"]

    def test_html_text(self):
        body = "<div>grzABC123</div>"
        assert "html_text" in context.analyze_reflection(body, "grzABC123")["contexts"]

    def test_sql_error_inferred_without_reflection(self):
        body = "You have an error in your SQL syntax near '1"
        res = context.analyze_reflection(body, "grzNOTHERE")
        assert "sql_error" in res["contexts"]
        assert res["reflected"] is False

    def test_no_reflection(self):
        res = context.analyze_reflection("<html>nothing here</html>", "grzABC123")
        assert res["contexts"] == ["none"] and res["reflected"] is False

    def test_breakouts_known_and_unknown(self):
        assert context.breakouts_for("html_attr_dq")  # non-empty
        assert context.breakouts_for("not_a_context") == []

    def test_probe_is_unique_and_alnum(self):
        p1, p2 = context.new_probe(), context.new_probe()
        assert p1 != p2 and p1.isalnum()


class TestFingerprint:
    def test_cloudflare(self):
        r = fingerprint.passive_fingerprint({"Server": "cloudflare", "CF-RAY": "84xx-DFW"},
                                    body="Attention Required! | Cloudflare", status=403)
        assert r["waf"] == "cloudflare" and r["confidence"] >= 0.4

    def test_aws_waf(self):
        r = fingerprint.passive_fingerprint({"x-amzn-requestid": "abc", "x-amzn-trace-id": "z"},
                                    status=403)
        assert r["waf"] == "aws_waf"

    def test_modsecurity_from_body(self):
        r = fingerprint.passive_fingerprint({"Server": "Apache"},
                                    body="This error was generated by Mod_Security", status=406)
        assert r["waf"] == "modsecurity"

    def test_none_when_no_signal(self):
        r = fingerprint.passive_fingerprint({"Server": "nginx", "Content-Type": "text/html"},
                                    body="<h1>Welcome</h1>", status=200)
        assert r["waf"] == "none"

    def test_status_alone_does_not_trigger(self):
        # a bare 403 with no product signal must not be called a WAF
        r = fingerprint.passive_fingerprint({"Server": "nginx"}, body="", status=403)
        assert r["waf"] == "none"

    def test_branded_beats_generic(self):
        # imperva signals plus a generic "Access Denied" -> imperva, not generic
        r = fingerprint.passive_fingerprint({"Set-Cookie": "visid_incap_123=abc; incap_ses_1=z"},
                                    body="Access Denied - Incapsula incident ID 123", status=403)
        assert r["waf"] == "imperva"


class TestArsenalCLI:
    def test_encode_cli_emits_json(self, capsys):
        from waf import arsenal
        rc = arsenal.main(["encode", "--payload", "' OR 1=1-- -",
                           "--context", "sql_string", "--max-variants", "5"])
        assert rc == 0
        import json
        out = json.loads(capsys.readouterr().out)
        assert out["mode"] == "encode" and out["variant_count"] <= 5
        assert out["variants"][0]["technique"] == "original"
