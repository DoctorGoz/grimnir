"""bopla-confirm.py is the mass-assignment oracle: a 3-step differential (baseline -> write with an
injected privileged property -> read back) on the caller's OWN resource. The false positives it must
avoid: a property that ALREADY held the injected value (the write proved nothing) and a write that
silently failed. The false negative it must avoid: reporting `negative`/`confirmed` off a write that
never succeeded. Pure surface only; no network."""


class TestParseValue:
    def test_json_literals_parse_to_types(self, bopla_confirm_mod):
        m = bopla_confirm_mod
        assert m.parse_value("true") is True
        assert m.parse_value("123") == 123
        assert m.parse_value('"x"') == "x"

    def test_bare_string_stays_a_string(self, bopla_confirm_mod):
        assert bopla_confirm_mod.parse_value("admin") == "admin"


class TestExtractField:
    def test_top_level_field(self, bopla_confirm_mod):
        assert bopla_confirm_mod.extract_field('{"role":"admin","x":1}', "role") == "admin"

    def test_nested_under_a_common_wrapper(self, bopla_confirm_mod):
        assert bopla_confirm_mod.extract_field('{"user":{"role":"admin"}}', "role") == "admin"
        assert bopla_confirm_mod.extract_field('{"data":{"verified":true}}', "verified") is True

    def test_missing_field_is_the_sentinel(self, bopla_confirm_mod):
        assert bopla_confirm_mod.extract_field('{"x":1}', "role") is bopla_confirm_mod._MISSING

    def test_non_json_is_the_sentinel(self, bopla_confirm_mod):
        assert bopla_confirm_mod.extract_field("<html>nope", "role") is bopla_confirm_mod._MISSING


class TestClassify:
    def test_value_took_and_differs_from_baseline_is_confirmed(self, bopla_confirm_mod):
        v, _why = bopla_confirm_mod.classify_bopla(200, "user", "admin", "admin")
        assert v == "confirmed"

    def test_value_ignored_is_negative(self, bopla_confirm_mod):
        v, _why = bopla_confirm_mod.classify_bopla(200, "user", "user", "admin")
        assert v == "negative"

    def test_failed_write_is_inconclusive(self, bopla_confirm_mod):
        v, why = bopla_confirm_mod.classify_bopla(403, "user", "user", "admin")
        assert v == "inconclusive" and "write" in why

    def test_baseline_already_the_value_is_inconclusive(self, bopla_confirm_mod):
        # cannot attribute an already-admin field to our write -> not a false confirm
        v, why = bopla_confirm_mod.classify_bopla(200, "admin", "admin", "admin")
        assert v == "inconclusive" and "already" in why

    def test_unreadable_readback_is_inconclusive(self, bopla_confirm_mod):
        v, _why = bopla_confirm_mod.classify_bopla(200, "user", bopla_confirm_mod._MISSING, "admin")
        assert v == "inconclusive"

    def test_boolean_flip_is_confirmed(self, bopla_confirm_mod):
        v, _why = bopla_confirm_mod.classify_bopla(200, False, True, True)
        assert v == "confirmed"


class TestGraphQLReadback:
    """The GraphQL shape: the field lives under data.<op>.<field>, deeper than the REST wrappers.
    _deep_find must resolve it, and a top-level/REST field must still win over a deep coincidence."""

    def test_deep_find_resolves_graphql_nesting(self, bopla_confirm_mod):
        body = '{"data":{"me":{"role":"admin","org":{"role":"member"}}}}'
        assert bopla_confirm_mod.extract_field(body, "role") == "admin"

    def test_top_level_still_wins_over_deep(self, bopla_confirm_mod):
        # a REST body with the field at top level is unaffected by the deep fallback
        body = '{"role":"admin","nested":{"role":"member"}}'
        assert bopla_confirm_mod.extract_field(body, "role") == "admin"

    def test_deep_find_missing_is_sentinel(self, bopla_confirm_mod):
        assert bopla_confirm_mod._deep_find({"data": {"me": {"x": 1}}}, "role") is bopla_confirm_mod._MISSING

    def test_graphql_mass_assignment_end_to_end(self, bopla_confirm_mod, tmp_path, monkeypatch):
        """--write-body drives a mutation, --read-body drives the read-back query; the differential
        confirms only when the injected value sticks. Network stubbed."""
        m = bopla_confirm_mod
        calls = []
        reads = {"n": 0}

        def fake_request(method, url, headers, body=None):
            calls.append((method, body))
            if body and "mutation" in body:              # the write succeeds
                return 200, '{"data":{"updateUser":{"role":"ADMIN"}}}'
            reads["n"] += 1                              # 1st read = baseline, 2nd = read-back
            role = "member" if reads["n"] == 1 else "ADMIN"
            return 200, '{"data":{"me":{"role":"%s"}}}' % role

        monkeypatch.setattr(m, "_request", fake_request)
        monkeypatch.setattr("sys.argv", [
            "bopla-confirm.py", "--finding-id", "SPE-001", "--project-dir", str(tmp_path),
            "--method", "POST", "--url", "https://api/graphql", "--read-method", "POST",
            "--field", "role", "--value", "ADMIN",
            "--write-body", '{"query":"mutation{updateUser(input:{role:ADMIN}){role}}"}',
            "--read-body", '{"query":"{me{role}}"}'])
        m.main()
        import json as _j
        rec = _j.load(open(tmp_path / "evidence" / "SPE-001" / "bopla.json"))
        assert rec["verdict"] == "confirmed"
        # the read-back request carried the query body (not a bodyless REST GET)
        assert any(b == '{"query":"{me{role}}"}' for _mth, b in calls)
