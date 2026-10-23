"""graphql-probe.py — introspection-off schema recovery via the field-suggestion error oracle.

The load-bearing, silently-wrong-able code is the pure oracle: reading graphql-js validation errors
into exists/type/kind/suggestions, and driving the BFS reconstruction from them. These tests pin the
error-message parsing against the canonical phrasings and the read-only SAFETY invariant (query-mode
only issues `query` operations; mutation harvesting only ever sends MANGLED names that cannot resolve),
so a reword that breaks recovery — or an edit that lets a real mutation execute — fails the suite. No
network: the transport is a scripted stub."""


# ── extract_suggestions ─────────────────────────────────────────────────────────
class TestExtractSuggestions:
    def test_one_two_three_forms(self, graphql_probe_mod):
        m = graphql_probe_mod
        assert m.extract_suggestions('Did you mean "user"?')[0] == ["user"]
        assert m.extract_suggestions('Did you mean "user" or "users"?')[0] == ["user", "users"]
        assert m.extract_suggestions('Did you mean "a", "b", or "c"?')[0] == ["a", "b", "c"]

    def test_inline_fragment_is_flagged_as_types(self, graphql_probe_mod):
        names, is_type = graphql_probe_mod.extract_suggestions(
            'Did you mean to use an inline fragment on "User" or "Org"?')
        assert is_type and names == ["User", "Org"]

    def test_subfield_hint_yields_no_bogus_name(self, graphql_probe_mod):
        # "user { ... }" is not a bare identifier -> dropped
        assert graphql_probe_mod.extract_suggestions('Did you mean "user { ... }"?')[0] == []

    def test_no_clause_returns_empty(self, graphql_probe_mod):
        assert graphql_probe_mod.extract_suggestions("some other error")[0] == []

    def test_dedup_preserves_order(self, graphql_probe_mod):
        assert graphql_probe_mod.extract_suggestions('Did you mean "a", "a", or "b"?')[0] == ["a", "b"]


# ── classify_field_probe ─────────────────────────────────────────────────────────
class TestClassify:
    def test_unknown_field_not_exists_with_container_and_suggestions(self, graphql_probe_mod):
        i = graphql_probe_mod.classify_field_probe(
            ['Cannot query field "usr" on type "Query". Did you mean "user" or "users"?'], "usr")
        assert i["exists"] is False
        assert i["container_type"] == "Query"
        assert i["field_suggestions"] == ["user", "users"]

    def test_object_field_reveals_type_and_kind(self, graphql_probe_mod):
        i = graphql_probe_mod.classify_field_probe(
            ['Field "me" of type "User!" must have a selection of subfields.'], "me")
        assert i["exists"] and i["type"] == "User!" and i["kind"] == "object"

    def test_scalar_field(self, graphql_probe_mod):
        i = graphql_probe_mod.classify_field_probe(
            ['Field "email" must not have a selection since type "String" has no subfields.'], "email")
        assert i["exists"] and i["kind"] == "scalar" and i["type"] == "String"

    def test_required_args_captured(self, graphql_probe_mod):
        i = graphql_probe_mod.classify_field_probe(
            ['Field "user" argument "id" of type "ID!" is required, but it was not provided.'], "user")
        assert i["exists"] and i["required_args"] == ["id"]

    def test_runtime_or_auth_error_means_field_exists(self, graphql_probe_mod):
        # a non-validation error (field passed existence check) -> exists True
        i = graphql_probe_mod.classify_field_probe(['Not authorized to access "me".'], "me")
        assert i["exists"] is True and i["kind"] is None

    def test_clean_return_means_exists(self, graphql_probe_mod):
        assert graphql_probe_mod.classify_field_probe([], "me")["exists"] is True

    def test_error_about_a_different_field_does_not_touch_ours(self, graphql_probe_mod):
        i = graphql_probe_mod.classify_field_probe(
            ['Cannot query field "other" on type "Query". Did you mean "me"?'], "me")
        # our field wasn't the unknown one -> it exists; "me" harvested as a suggestion
        assert i["exists"] is True and i["field_suggestions"] == ["me"]


# ── small pure helpers ───────────────────────────────────────────────────────────
class TestHelpers:
    def test_strip_type_unwraps(self, graphql_probe_mod):
        m = graphql_probe_mod
        assert m.strip_type("[User!]!") == "User"
        assert m.strip_type("String") == "String"
        assert m.strip_type(None) is None

    def test_build_query_nests(self, graphql_probe_mod):
        m = graphql_probe_mod
        assert m.build_query("query", [], "me") == "{ me }"
        assert m.build_query("query", ["me"], "email") == "{ me { email } }"
        assert m.build_query("mutation", [], "x") == "mutation { x }"

    def test_messages_of_is_robust(self, graphql_probe_mod):
        m = graphql_probe_mod
        assert m.messages_of({"json": None}) == []
        assert m.messages_of({"json": {"data": {}}}) == []
        assert m.messages_of({"json": {"errors": [{"message": "boom"}, {}]}}) == ["boom", ""]


# ── scripted server (introspection OFF, graphql-js phrasing) ─────────────────────
def _fake_server(schema, *, log=None, introspection=False):
    """schema = {TypeName: {field: [childfields] | None}}; None = scalar, [] or list = object."""
    def fake(query):
        if log is not None:
            log.append(query)
        q = query.replace(" ", "")
        if "__typename" in q:
            return {"status": 200, "json": {"data": {"__typename": "Query"}}}
        if "__schema" in q:
            if introspection:
                return {"status": 200, "json": {"data": {"__schema": {"types": []}}}}
            return {"status": 400, "json": {"errors": [{"message": "introspection is not allowed"}]}}
        leaves = __import__("re").findall(r'\{([A-Za-z_][A-Za-z0-9_]*)\}', q)
        parents = __import__("re").findall(r'([A-Za-z_][A-Za-z0-9_]*)\{', q)
        leaf = leaves[-1] if leaves else ""
        container = "Query"
        if parents and parents[-1] in schema.get("Query", {}):
            # descended: container is the type of that parent field
            container = {"user": "User"}.get(parents[-1], "Query")
        fields = schema.get(container, {})
        if leaf in fields:
            if fields[leaf] is not None:   # object
                return {"status": 400, "json": {"errors": [
                    {"message": f'Field "{leaf}" of type "User" must have a selection of subfields.'}]}}
            return {"status": 400, "json": {"errors": [
                {"message": f'Field "{leaf}" must not have a selection since type "String" has no subfields.'}]}}
        near = ", ".join(f'"{k}"' for k in fields)
        clause = f" Did you mean {near}?" if near else ""
        return {"status": 400, "json": {"errors": [
            {"message": f'Cannot query field "{leaf}" on type "{container}".{clause}'}]}}
    return fake


class TestRun:
    def test_reconstructs_and_descends(self, graphql_probe_mod):
        schema = {"Query": {"user": ["email"], "viewer": None}, "User": {"email": None, "role": None}}
        r = graphql_probe_mod.run("http://fake/graphql", [], wordlist=["user", "viewer", "zzz"],
                                  max_requests=200, depth=2, delay=0, mutations=False,
                                  post_fn=_fake_server(schema))
        assert r["introspection"] == "disabled"
        qf = {f["name"] for f in r["types"]["Query"]["fields"]}
        uf = {f["name"] for f in r["types"]["User"]["fields"]}
        assert {"user", "viewer"} <= qf
        assert {"email", "role"} <= uf
        assert r["stats"]["fields_found"] >= 4

    def test_depth_one_stays_at_root(self, graphql_probe_mod):
        schema = {"Query": {"user": ["email"]}, "User": {"email": None}}
        r = graphql_probe_mod.run("http://fake/graphql", [], wordlist=["user"],
                                  max_requests=200, depth=1, delay=0, mutations=False,
                                  post_fn=_fake_server(schema))
        assert "User" not in r["types"]  # no descent at depth 1

    def test_introspection_enabled_short_circuits(self, graphql_probe_mod):
        r = graphql_probe_mod.run("http://fake/graphql", [], wordlist=["user"], max_requests=200,
                                  depth=2, delay=0, mutations=False,
                                  post_fn=_fake_server({"Query": {}}, introspection=True))
        assert r["introspection"] == "enabled"

    def test_not_graphql(self, graphql_probe_mod):
        r = graphql_probe_mod.run("http://fake", [], wordlist=[], max_requests=200, depth=2,
                                  delay=0, mutations=False,
                                  post_fn=lambda q: {"status": 404, "json": None, "text": "<html>"})
        assert r["introspection"] == "not-graphql"

    def test_budget_is_respected(self, graphql_probe_mod):
        schema = {"Query": {f"f{i}": None for i in range(50)}}
        log = []
        r = graphql_probe_mod.run("http://fake/graphql", [], wordlist=[f"f{i}" for i in range(50)],
                                  max_requests=8, depth=2, delay=0, mutations=False,
                                  post_fn=_fake_server(schema, log=log))
        assert r["stats"]["requests"] <= 8
        assert len(log) <= 8
        assert any("budget" in n for n in r["notes"])

    # ── the read-only safety invariant ──────────────────────────────────────────
    def test_query_mode_never_issues_a_mutation(self, graphql_probe_mod):
        schema = {"Query": {"user": ["email"], "viewer": None}, "User": {"email": None}}
        log = []
        graphql_probe_mod.run("http://fake/graphql", [], wordlist=["user", "viewer"],
                              max_requests=200, depth=2, delay=0, mutations=False,
                              post_fn=_fake_server(schema, log=log))
        # every recon query is a query op — none begins a mutation
        assert not any(q.lstrip().startswith("mutation") for q in log)

    def test_mutation_harvest_only_sends_mangled_names(self, graphql_probe_mod):
        schema = {"Query": {"me": None}, "Mutation": {"deleteUser": None, "createUser": None}}
        log = []
        graphql_probe_mod.run("http://fake/graphql", [], wordlist=["deleteUser", "createUser"],
                              max_requests=200, depth=1, delay=0, mutations=True,
                              post_fn=_fake_server(schema, log=log))
        mutation_qs = [q for q in log if q.lstrip().startswith("mutation")]
        assert mutation_qs, "expected mutation-root probes when --mutations is set"
        # a real mutation name must NEVER appear un-mangled in a mutation op (would execute it)
        for q in mutation_qs:
            assert "deleteUser " not in q.replace("mutation", "") or "_zzq" in q
            assert "_zzq" in q  # every mutation probe is a mangled near-miss
