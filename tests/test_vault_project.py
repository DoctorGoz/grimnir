"""vault-project.py renders a read-only Obsidian projection of engagement data. The invariants:
severity-ordered findings, markdown/YAML-safe escaping, the victim-data marker survives into the
page, and the safety guard refuses any vault that would clobber source or the repo."""


class TestPureRender:
    def test_severity_rank_orders_critical_first(self, vault_project_mod):
        m = vault_project_mod
        assert m.severity_rank("critical") < m.severity_rank("high") < m.severity_rank("info")
        assert m.severity_rank("nonsense") == len(m.SEV_ORDER)

    def test_findings_sort_by_severity_then_newest(self, vault_project_mod):
        m = vault_project_mod
        findings = [
            {"id": "A", "severity": "low", "created_at": "2026-01-01"},
            {"id": "B", "severity": "critical", "created_at": "2026-01-01"},
            {"id": "C", "severity": "high", "created_at": "2026-02-01"},
            {"id": "D", "severity": "high", "created_at": "2026-03-01"},
        ]
        norm = m.normalize_engagement({"project_name": "p"}, findings, [])
        # critical first; within high, the newer (D, March) precedes the older (C, Feb)
        assert [f["id"] for f in norm["findings"]] == ["B", "D", "C", "A"]

    def test_page_escapes_pipes_and_keeps_victim_marker(self, vault_project_mod):
        m = vault_project_mod
        norm = m.normalize_engagement(
            {"project_name": "acme", "status": "in_progress", "target": {"primary": "https://a.test"}},
            [{"id": "SPE-1", "severity": "high", "title": "BOLA a | b",
              "validation": {"state": "confirmed", "victim_data": True}}], [])
        norm["slug"] = "acme"
        page = m.render_engagement_page(norm)
        assert "# acme" in page and "https://a.test" in page
        assert "BOLA a \\| b" in page          # pipe escaped so the table survives
        assert "| yes |" in page               # victim-data marker rendered

    def test_survives_string_typed_target_and_nondict_rows(self, vault_project_mod):
        m = vault_project_mod
        norm = m.normalize_engagement(
            {"project_name": "p", "target": "https://str.test", "agents": []},
            [{"id": "X", "severity": "low"}, "not-a-dict"],
            ["bad", {"discovery_type": "e", "tags": ["t"]}])
        assert norm["target"] == "https://str.test" and norm["agents"] == {}
        assert [f["id"] for f in norm["findings"]] == ["X"]      # non-dict finding dropped
        assert len(norm["intel_recent"]) == 1                    # non-dict intel dropped

    def test_render_handles_string_agent_value(self, vault_project_mod):
        m = vault_project_mod
        n = m.normalize_engagement(
            {"project_name": "s", "agents": {"specter": "done", "huginn": {"phase": "recon"}}}, [], [])
        n["slug"] = "s"
        page = m.render_engagement_page(n)
        assert "done" in page and "recon" in page

    def test_index_uses_alias_link_when_slug_differs(self, vault_project_mod):
        m = vault_project_mod
        norm = m.normalize_engagement({"project_name": "acme-og", "status": "shelved"}, [], [])
        norm["slug"] = "acme"                # dir name != project_name
        idx = m.render_index([norm])
        assert "[[acme|acme-og]]" in idx     # link targets the page, displays the program name


class TestSafetyGuard:
    def test_refuses_workspace_repo_and_parents(self, vault_project_mod):
        m = vault_project_mod
        assert m.is_safe_vault("/h/vault", "/h/ws", "/h/ws/grimnir")[0] is True
        assert m.is_safe_vault("/h/ws", "/h/ws", None)[0] is False                     # equals workspace
        assert m.is_safe_vault("/h/ws/sub", "/h/ws", None)[0] is False                 # inside workspace
        assert m.is_safe_vault("/h", "/h/ws", None)[0] is False                        # parent of workspace
        assert m.is_safe_vault("/h/ws/grimnir/v", "/h/ws", "/h/ws/grimnir")[0] is False  # inside the repo
