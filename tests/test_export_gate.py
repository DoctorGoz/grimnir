"""The export gate decides what leaves the engagement.

`/report` and export-findings.py must agree on which findings are shippable. A gate that
drifts wide leaks theoretical findings into a deliverable; a gate that drifts narrow
silently drops proven work.
"""
import json


def _f(fid, state, **kw):
    d = {"id": fid, "agent": "specter", "title": f"finding {fid}", "severity": "high",
         "description": "d", "validation": {"state": state}}
    d.update(kw)
    return d


class TestGate:
    def test_only_confirmed_and_validated_pass_by_default(self, export_mod):
        rows = [_f("SPE-001", "confirmed"), _f("SPE-002", "validated"),
                _f("SPE-003", "theoretical"), _f("SPE-004", "refuted")]
        got = {f["id"] for f in export_mod.select(rows, False, False)}
        assert got == {"SPE-001", "SPE-002"}

    def test_include_theoretical_widens_but_still_drops_refuted(self, export_mod):
        rows = [_f("SPE-001", "confirmed"), _f("SPE-003", "theoretical"),
                _f("SPE-004", "refuted")]
        got = {f["id"] for f in export_mod.select(rows, True, False)}
        assert "SPE-003" in got
        assert "SPE-004" not in got, "refuted is a disproof; it must never ride --include-theoretical"

    def test_include_all_takes_everything(self, export_mod):
        rows = [_f("SPE-001", "confirmed"), _f("SPE-004", "refuted")]
        assert len(export_mod.select(rows, False, True)) == 2

    def test_missing_validation_block_is_treated_as_theoretical(self, export_mod):
        """A hand-written finding with no validation block must not default to shippable."""
        row = {"id": "SPE-009", "title": "legacy hand-written", "severity": "high"}
        assert export_mod.select([row], False, False) == []
        assert len(export_mod.select([row], True, False)) == 1


class TestImpactSummary:
    def test_object_shape(self, export_mod):
        assert export_mod._impact_summary({"impact": {"summary": "reads victim orders"}}) == "reads victim orders"

    def test_bare_string_shape_does_not_crash(self, export_mod):
        """Legacy and hand-written findings carry a bare string. Assuming the object shape
        raised AttributeError and lost the ENTIRE export over one malformed record."""
        assert export_mod._impact_summary({"impact": "reads victim orders"}) == "reads victim orders"

    def test_missing_and_null(self, export_mod):
        assert export_mod._impact_summary({}) == ""
        assert export_mod._impact_summary({"impact": None}) == ""


class TestSarif:
    def test_shape_is_valid_sarif_210(self, export_mod):
        doc = export_mod.to_sarif([_f("SPE-001", "confirmed", severity="critical")], "acme")
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["tool"]["driver"]["name"]
        assert len(doc["runs"][0]["results"]) == 1

    def test_empty_input_still_emits_a_valid_run(self, export_mod):
        doc = export_mod.to_sarif([], "acme")
        assert doc["runs"][0]["results"] == []

    def test_result_message_falls_back_when_impact_is_empty(self, export_mod):
        doc = export_mod.to_sarif([_f("SPE-001", "confirmed", impact={"summary": ""})], "acme")
        msg = doc["runs"][0]["results"][0]["message"]["text"]
        assert msg, "an empty impact must fall back to description/title, not emit a blank message"
