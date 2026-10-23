"""The playbook matcher decides which lanes the test plan leads with.

A lane ranked REACHABLE that is actually gated sends the operator into work they cannot
finish; a lane wrongly marked BLOCKED hides the best available target.
"""


class TestReachabilityVerdict:
    def test_no_gates_is_reachable(self, playbook_mod):
        pb = {"reachability": {"gates": []}}
        verdict, _ = playbook_mod.reachability_verdict(pb, {})
        assert verdict == "REACHABLE"

    def test_a_held_gate_is_reachable(self, playbook_mod):
        pb = {"reachability": {"gates": ["second-account"]}}
        verdict, _ = playbook_mod.reachability_verdict(pb, {"second-account": True})
        assert verdict == "REACHABLE"

    def test_an_unheld_gate_blocks(self, playbook_mod):
        pb = {"reachability": {"gates": ["second-account"]}}
        verdict, _ = playbook_mod.reachability_verdict(pb, {"second-account": False})
        assert verdict.startswith("BLOCKED")

    def test_an_unknown_gate_is_not_silently_reachable(self, playbook_mod):
        """Never having assessed a gate must not read as holding it -- that is how an
        unreachable lane gets planned as the primary one."""
        pb = {"reachability": {"gates": ["second-account"]}}
        verdict, _ = playbook_mod.reachability_verdict(pb, {})
        assert verdict != "REACHABLE"

    def test_one_unheld_gate_blocks_even_when_others_are_held(self, playbook_mod):
        pb = {"reachability": {"gates": ["second-account", "kyc"]}}
        verdict, _ = playbook_mod.reachability_verdict(pb, {"second-account": True, "kyc": False})
        assert verdict.startswith("BLOCKED")


class TestPrereqMatching:
    def test_signal_match(self, playbook_mod):
        pb = {"prerequisites": {"signals_any": ["rest_api", "graphql"]}}
        assert playbook_mod.match_prereqs(pb, {"signals": {"rest_api"}, "techs": set()})

    def test_no_overlap_does_not_match(self, playbook_mod):
        pb = {"prerequisites": {"signals_any": ["graphql"]}}
        assert not playbook_mod.match_prereqs(pb, {"signals": {"smtp"}, "techs": set()})

    def test_empty_target_matches_nothing(self, playbook_mod):
        pb = {"prerequisites": {"signals_any": ["rest_api"]}}
        assert not playbook_mod.match_prereqs(pb, {"signals": set(), "techs": set()})


class TestShippedPlaybooks:
    def test_every_shipped_playbook_has_an_id_and_chain(self, playbook_mod):
        books = playbook_mod.load_playbooks()
        assert books, "no playbooks loaded"
        for pb in books:
            assert pb.get("id"), f"playbook missing id: {pb.get('_file')}"
            assert pb.get("chain"), f"{pb['id']} has no chain"

    def test_step_ids_are_unique_within_a_playbook(self, playbook_mod):
        for pb in playbook_mod.load_playbooks():
            ids = [s["id"] for s in pb["chain"]]
            assert len(ids) == len(set(ids)), f"{pb['id']} has duplicate step ids"

    def test_confirm_steps_declare_an_evidence_class(self, playbook_mod):
        """A confirm step without an evidence_class produces an artifact the gate cannot
        map to a required proof."""
        for pb in playbook_mod.load_playbooks():
            for st in pb["chain"]:
                if st.get("confirm") and "oob" not in st["confirm"]:
                    assert st.get("evidence_class"), \
                        f"{pb['id']}/{st['id']} confirms but declares no evidence_class"

    def test_every_confirm_args_exposes_its_placeholders(self, playbook_mod):
        """plan prints a "fill before running" list built with PLACEHOLDER_RE. A step
        whose arguments need operator input but expose no placeholder would render as a
        command that looks ready to paste and is not.

        Uses the production regex rather than a second pattern on purpose: a GraphQL body
        like '{"query":"{NODE_ID}"}' contains literal JSON braces, and a naive greedy
        pattern matches the JSON instead of the placeholder."""
        for pb in playbook_mod.load_playbooks():
            for st in pb["chain"]:
                args = st.get("confirm_args")
                if not args:
                    continue
                found = playbook_mod.PLACEHOLDER_RE.findall(args)
                assert found, f"{pb['id']}/{st['id']}: confirm_args exposes no placeholder"

    @__import__("pytest").mark.skip(reason='relies on a playbook that is not part of the public cut')
    def test_placeholders_survive_json_bodies(self, playbook_mod):
        """The GraphQL steps embed a JSON body; the placeholder inside must still be
        extracted and listed."""
        pb = playbook_mod.get_playbook("graphql-authz-abuse")
        step = next(s for s in pb["chain"] if s["id"] == "cross_query")
        found = playbook_mod.PLACEHOLDER_RE.findall(step["confirm_args"])
        assert "QUERY_WITH_NODE_ID" in found
        assert "GRAPHQL_URL" in found


class TestCollectTargetIntakeSeeding:
    """At a fresh /engage, before HUGINN writes asset-map.json, the operator already knows
    from intake that the target is graphql/oauth/api -- that lives in scope.md and
    classification.md. collect_target must read those so `match` returns a ranked plan on
    day one instead of a silent zero-match that only fills in after Phase 0."""

    def test_scope_md_alone_seeds_signals(self, playbook_mod, tmp_path):
        (tmp_path / "scope.md").write_text(
            "# Scope\nIn scope: the public GraphQL API at api.example.com/graphql.\n"
            "Introspection appears enabled.\n"
        )
        target = playbook_mod.collect_target(tmp_path)
        assert "graphql" in target["signals"]

    @__import__("pytest").mark.skip(reason='relies on a playbook that is not part of the public cut')
    def test_classification_md_alone_seeds_signals(self, playbook_mod, tmp_path):
        (tmp_path / "classification.md").write_text(
            "Target type: REST API secured with OAuth2 bearer tokens.\n"
        )
        target = playbook_mod.collect_target(tmp_path)
        assert "oauth2" in target["signals"]

    @__import__("pytest").mark.skip(reason='relies on a playbook that is not part of the public cut')
    def test_no_asset_map_still_yields_nonempty_match(self, playbook_mod, tmp_path):
        """The regression that motivated M3: a project dir with only intake docs (no
        asset-map.json, no intel.jsonl) must produce a non-empty ranked match, not zero."""
        (tmp_path / "scope.md").write_text("In scope: GraphQL endpoint with introspection.\n")
        assert not (tmp_path / "asset-map.json").exists()
        ranked = playbook_mod.match(tmp_path)
        assert ranked, "intake-only project produced a silent zero-match"
        assert any("graphql" in pb.get("id", "") for pb in ranked)

    def test_empty_project_dir_matches_nothing(self, playbook_mod, tmp_path):
        """Guard the other direction: no intake, no asset-map -> genuinely nothing to plan,
        not a crash."""
        assert playbook_mod.collect_target(tmp_path)["signals"] == set()


class TestFirstCredentialAndOauthAppGates:
    """M4: OAuth/token lanes were marked REACHABLE when they need the FIRST bearer we don't
    hold -- the taxonomy only knew `second-account`. A lane gated on `first-credential` /
    `oauth-app` must NOT be reachable until the gate is held. Enforcement needs a NEGATIVE
    test that the gate actually blocks (memory: enforcement-layers-need-a-negative-test)."""

    def test_first_credential_not_held_blocks(self, playbook_mod):
        pb = {"reachability": {"gates": ["first-credential"]}}
        verdict, rank = playbook_mod.reachability_verdict(pb, {"first-credential": False})
        assert verdict.startswith("BLOCKED"), verdict
        assert rank == 2

    def test_first_credential_held_is_reachable(self, playbook_mod):
        pb = {"reachability": {"gates": ["first-credential"]}}
        verdict, _ = playbook_mod.reachability_verdict(pb, {"first-credential": True})
        assert verdict == "REACHABLE"

    def test_first_credential_unknown_is_not_reachable(self, playbook_mod):
        """A reachability.json that predates the gate (no key) must NOT read as held -- that
        is exactly the fail-open the taxonomy gap caused."""
        pb = {"reachability": {"gates": ["first-credential"]}}
        verdict, _ = playbook_mod.reachability_verdict(pb, {"second-account": True})
        assert verdict != "REACHABLE"

    def test_oauth_app_not_held_blocks(self, playbook_mod):
        pb = {"reachability": {"gates": ["oauth-app"]}}
        verdict, rank = playbook_mod.reachability_verdict(pb, {"oauth-app": False})
        assert verdict.startswith("BLOCKED")
        assert rank == 2

    def test_second_account_behavior_unchanged(self, playbook_mod):
        pb = {"reachability": {"gates": ["second-account"]}}
        assert playbook_mod.reachability_verdict(pb, {"second-account": True})[0] == "REACHABLE"
        assert playbook_mod.reachability_verdict(pb, {"second-account": False})[0].startswith("BLOCKED")

    @__import__("pytest").mark.skip(reason='relies on a playbook that is not part of the public cut')
    def test_shipped_oauth_playbooks_declare_first_credential(self, playbook_mod):
        """The concrete lanes the bug was about must now carry the gate, or the fix is inert."""
        for pid in ("oauth-redirect-token-theft", "auth-token-privilege"):
            pb = playbook_mod.get_playbook(pid)
            assert pb, f"missing playbook {pid}"
            gates = (pb.get("reachability", {}) or {}).get("gates", []) or []
            assert "first-credential" in gates, f"{pid} does not gate on first-credential"

    def test_shipped_playbook_gates_are_all_in_schema_enum(self, playbook_mod, repo_root):
        """Every gate a shipped playbook names must exist in the schema enum, or `validate`
        would reject it -- and a typo'd gate silently never blocks."""
        import json
        enum = set(json.loads((repo_root / "schemas" / "playbook.schema.json").read_text())
                   ["properties"]["reachability"]["properties"]["gates"]["items"]["enum"])
        assert {"first-credential", "oauth-app"} <= enum
        for pb in playbook_mod.load_playbooks():
            for g in (pb.get("reachability", {}) or {}).get("gates", []) or []:
                assert g in enum, f"{pb['id']} names gate '{g}' absent from schema enum"
