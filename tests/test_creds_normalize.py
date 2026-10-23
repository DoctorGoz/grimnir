"""creds-normalize.py turns human-authored freeform cred files into the structured credentials.jsonl
that lane-synth consumes. The silent failures to guard: a format the parser misreads (tenants lost,
0 lanes that look like 'nothing to test'), a token bound to the wrong field, secrets leaking into a
log, or clobbering the operator's curated vault. Deterministic parse is the default; the cloud LLM
fallback is opt-in and must never be invoked implicitly."""

import json


class TestDeterministicParse:
    def test_kv_block_two_records_with_resource_ids(self, creds_normalize_mod):
        text = ("[userA]\nemail: a@x.io\npassword: p1\nobject_id: 1001\ndevice_id: DB-A\n\n"
                "[userB]\nemail: b@x.io\npassword: p2\nobject_id: 1002\ndevice_id: DB-B")
        recs = creds_normalize_mod.parse_freeform(text)
        assert len(recs) == 2
        assert recs[0]["object_id"] == "1001" and recs[0]["email"] == "a@x.io"
        assert recs[0]["account"] == "userA"                      # [userA] header seeds the account
        assert recs[0]["resource_ids"] == {"device": "DB-A"}     # owned-resource id, singularized

    def test_token_keys_normalize_to_access_token(self, creds_normalize_mod):
        for k in ("token", "access_token", "jwt", "bearer"):
            recs = creds_normalize_mod.parse_freeform(f"{k}: SECRET123\nobject_id: 9")
            assert recs and recs[0]["access_token"] == "SECRET123"

    def test_account_id_keys_are_object_ids_not_resource_ids(self, creds_normalize_mod):
        # user_id/org_id end in _id but are the ACCOUNT id, never a resource id.
        recs = creds_normalize_mod.parse_freeform("token: T\nuser_id: 500")
        assert recs[0]["object_id"] == "500" and "resource_ids" not in recs[0]

    def test_user_pass_lines(self, creds_normalize_mod):
        recs = creds_normalize_mod.parse_freeform("a@x.io:secretpass\nb@x.io / otherpass")
        assert len(recs) == 2
        assert recs[0]["email"] == "a@x.io" and recs[0]["password"] == "secretpass"
        assert recs[1]["email"] == "b@x.io" and recs[1]["password"] == "otherpass"

    def test_json_array_and_object(self, creds_normalize_mod):
        arr = creds_normalize_mod.parse_freeform('[{"account":"A","token":"T1","object_id":"1"}]')
        assert arr and arr[0]["access_token"] == "T1" and arr[0]["object_id"] == "1"
        obj = creds_normalize_mod.parse_freeform('{"token":"T2","object_id":"2"}')
        assert obj and obj[0]["access_token"] == "T2"

    def test_jsonl(self, creds_normalize_mod):
        recs = creds_normalize_mod.parse_freeform('{"token":"A","object_id":"1"}\n{"token":"B","object_id":"2"}')
        assert len(recs) == 2

    def test_auth_headers_survive_normalization_list_and_dict(self, creds_normalize_mod):
        # a two-part auth identity (Basic + app-id header) must NOT be dropped as an unknown list key
        recs = creds_normalize_mod.parse_freeform(
            '[{"account":"A","object_id":"1","auth_headers":["Authorization: Basic QQ==","privy-app-id: a1"]}]')
        assert recs and recs[0]["auth_headers"] == ["Authorization: Basic QQ==", "privy-app-id: a1"]
        # dict form normalizes to "Name: Value" strings
        recs2 = creds_normalize_mod.parse_freeform(
            '{"object_id":"2","auth_headers":{"X-Api-Key":"k1"}}')
        assert recs2 and recs2[0]["auth_headers"] == ["X-Api-Key: k1"]

    def test_cookie_domains_list_survives_normalization(self, creds_normalize_mod):
        # host scoping must not be dropped as an unknown list key, or the key goes to every host
        recs = creds_normalize_mod.parse_freeform(
            '[{"account":"A","object_id":"1","cookie_domains":["A.acme.example"," "]}]')
        assert recs and recs[0]["cookie_domains"] == ["a.acme.example"]

    def test_auth_headers_alone_make_a_record_usable(self, creds_normalize_mod):
        # a credential with only a two-part-auth identity (no bare token/object_id) is still usable
        assert creds_normalize_mod.record_usable({"auth_headers": ["Authorization: Basic QQ=="]})

    def test_empty_and_junk_yield_nothing(self, creds_normalize_mod):
        assert creds_normalize_mod.parse_freeform("") == []
        assert creds_normalize_mod.parse_freeform("   \n\n") == []
        # a note with no cred-shaped content -> no usable records
        assert creds_normalize_mod.parse_freeform("just some notes about the target") == []


class TestUsableAndRedaction:
    def test_record_usable(self, creds_normalize_mod):
        m = creds_normalize_mod
        assert m.record_usable({"access_token": "x"})
        assert m.record_usable({"object_id": "1"})
        assert m.record_usable({"email": "a@x.io", "password": "p"})
        assert not m.record_usable({"email": "a@x.io"})       # login name alone can't bind a lane
        assert not m.record_usable({})

    def test_redaction_masks_secrets_keeps_identity(self, creds_normalize_mod):
        red = creds_normalize_mod._redact(
            {"access_token": "supersecretvalue", "password": "hunter2", "email": "a@x.io"})
        assert "***" in red["access_token"] and "supersecret" not in red["access_token"]
        assert "***" in red["password"] and red["email"] == "a@x.io"


class TestLLMSeam:
    def test_default_command_is_grimnir_dev_sonnet(self, creds_normalize_mod):
        cmd = creds_normalize_mod._llm_command("claude-sonnet-4-6")
        assert cmd == ["claude", "--model", "claude-sonnet-4-6", "-p"]

    def test_command_override_via_env(self, creds_normalize_mod, monkeypatch):
        monkeypatch.setenv("GRIMNIR_CREDS_LLM_CMD", "my-llm-cli --model ds -p")
        assert creds_normalize_mod._llm_command("ignored") == ["my-llm-cli", "--model", "ds", "-p"]

    def test_output_parser_tolerates_prose_and_fences(self, creds_normalize_mod):
        out = 'here you go:\n```\n{"object_id":"9","token":"z"}\nchatter line\n```'
        recs = creds_normalize_mod.parse_llm_output(out)
        assert len(recs) == 1 and recs[0]["access_token"] == "z"

    def test_normalize_never_calls_llm_without_flag(self, creds_normalize_mod, tmp_path, monkeypatch):
        # An unparseable file + use_llm=False must NOT shell out; it is recorded as unparsed.
        (tmp_path / "creds.txt").write_text("\x00\x01 not parseable structured content \x02")
        called = {"n": 0}
        monkeypatch.setattr(creds_normalize_mod, "llm_extract",
                            lambda *a, **k: called.__setitem__("n", called["n"] + 1) or [])
        recs, summary = creds_normalize_mod.normalize(str(tmp_path), use_llm=False, model="m")
        assert called["n"] == 0 and summary["llm"] == 0


class TestDiscoveryAndWrite:
    def test_discover_root_and_subdir(self, creds_normalize_mod, tmp_path):
        (tmp_path / "creds.txt").write_text("a@x.io:p")
        (tmp_path / "aws-creds.txt").write_text("b@x.io:p")
        sub = tmp_path / "specter"; sub.mkdir()
        (sub / "creds.txt").write_text("c@x.io:p")
        found = creds_normalize_mod.discover_freeform(str(tmp_path))
        assert len(found) == 3

    def test_normalize_writes_vault_and_dedups(self, creds_normalize_mod, tmp_path):
        (tmp_path / "creds.txt").write_text(
            "token: T1\nobject_id: 1\n\ntoken: T2\nobject_id: 2\n\ntoken: T1\nobject_id: 1")
        recs, summary = creds_normalize_mod.normalize(str(tmp_path), use_llm=False, model="m")
        assert summary["records"] == 2            # the duplicate T1 collapses
        out = str(tmp_path / "credentials.jsonl")
        added, _ = creds_normalize_mod.write_vault(recs, out, force=False)
        assert added == 2
        lines = [json.loads(l) for l in open(out) if l.strip()]
        assert {r["access_token"] for r in lines} == {"T1", "T2"}

    def test_write_vault_stamps_captured_at_on_token_records_only(self, creds_normalize_mod, tmp_path):
        # A captured token ages on a timer, so it gets a captured_at downstream tooling freshness check can
        # read; a standing-only cred (no token) must NOT get a false freshness stamp.
        out = str(tmp_path / "credentials.jsonl")
        creds_normalize_mod.write_vault(
            [{"access_token": "T1", "object_id": "1"},
             {"username": "u", "password": "p"}], out, force=False)
        lines = [json.loads(l) for l in open(out) if l.strip()]
        tok = next(r for r in lines if r.get("access_token") == "T1")
        standing = next(r for r in lines if r.get("password") == "p")
        assert tok.get("captured_at", "").endswith("Z")
        assert "captured_at" not in standing

    def test_write_refuses_to_clobber_without_force(self, creds_normalize_mod, tmp_path):
        out = tmp_path / "credentials.jsonl"
        out.write_text('{"access_token":"EXISTING","object_id":"9"}\n')
        added, msg = creds_normalize_mod.write_vault(
            [{"access_token": "NEW", "object_id": "1"}], str(out), force=False)
        assert added == 0 and "refusing" in msg
        assert "EXISTING" in out.read_text() and "NEW" not in out.read_text()

    def test_vault_is_owner_only_on_create_and_merge(self, creds_normalize_mod, tmp_path):
        import os, stat
        out = tmp_path / "credentials.jsonl"
        creds_normalize_mod.write_vault([{"access_token": "T1", "object_id": "1"}], str(out), force=False)
        assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
        os.chmod(out, 0o644)
        creds_normalize_mod.write_vault([{"access_token": "T2", "object_id": "2"}], str(out), force=True)
        assert stat.S_IMODE(os.stat(out).st_mode) == 0o600

    def test_write_force_merges_preserving_existing(self, creds_normalize_mod, tmp_path):
        out = tmp_path / "credentials.jsonl"
        out.write_text('{"access_token":"EXISTING","object_id":"9"}\n')
        added, _ = creds_normalize_mod.write_vault(
            [{"access_token": "EXISTING", "object_id": "9"},   # dup -> skipped
             {"access_token": "NEW", "object_id": "1"}], str(out), force=True)
        assert added == 1
        toks = {json.loads(l)["access_token"] for l in open(out) if l.strip()}
        assert toks == {"EXISTING", "NEW"}


class TestLLMAbsent:
    """In a build without ai_log, --llm refuses clearly and the deterministic path still works."""

    def test_llm_flag_exits_nonzero_with_clear_message(self, creds_normalize_mod, tmp_path, monkeypatch, capsys):
        monkeypatch.setitem(__import__("sys").modules, "ai_log", None)      # makes `import ai_log` raise ImportError
        a = type("A", (), {"project_dir": str(tmp_path), "llm": True, "model": "m", "json": False,
                           "dry_run": True, "force": False, "out": None})
        assert creds_normalize_mod._cmd_normalize(a) == 2
        assert "LLM fallback not available in this build" in capsys.readouterr().err

    def test_deterministic_parser_works_without_ai_log(self, creds_normalize_mod, tmp_path, monkeypatch):
        monkeypatch.setitem(__import__("sys").modules, "ai_log", None)
        (tmp_path / "creds.txt").write_text("email: a@example.com\npassword: pw1\n")
        recs, summary = creds_normalize_mod.normalize(str(tmp_path), use_llm=False, model="m")
        assert summary["llm"] == 0
