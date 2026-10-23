"""Offline tests for specter/scripts/sf-guest-map.py using synthetic recorded-shape responses."""
import importlib.util
import json
import os
import subprocess
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "specter" / "scripts" / "sf-guest-map.py"
FIX = json.loads((REPO / "tests" / "fixtures" / "salesforce" / "responses.json").read_text())
BASE = "https://site.example.com"


@pytest.fixture(scope="module")
def sf():
    spec = importlib.util.spec_from_file_location("grimnir_sf_guest_map", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def descriptor_of(body):
    form = urllib.parse.parse_qs(body)
    return json.loads(form["message"][0])["actions"][0], json.loads(form["aura.context"][0]), form


class FakeSite:
    """Routes a request to a fixture by method/endpoint/descriptor; records every call."""

    def __init__(self, live_endpoint="/s/sfsites/aura", sync_fail_once=False, flaky_once=False):
        self.calls, self.live, self.sync_fail_once, self.flaky_once = [], live_endpoint, sync_fail_once, flaky_once

    def __call__(self, method, url, body):
        self.calls.append((method, url, body))
        assert url.startswith(BASE), url
        if method == "GET":
            return 200, FIX["bootstrap"]
        if url != BASE + self.live:
            return 404, "not found"
        act, ctx, form = descriptor_of(body)
        assert form["aura.token"] == ["undefined"]
        assert ctx["fwuid"] == "FWUID_SYNTH_001" and ctx["loaded"][
            "APPLICATION@markup://siteforce:communityApp"] == "1706_SYNTHAPPID"
        if self.sync_fail_once:
            self.sync_fail_once = False
            return 200, FIX["out_of_sync"]
        d, p = act["descriptor"], act["params"]
        if d.endswith("getConfigData"):
            if self.flaky_once:
                self.flaky_once = False
                return 500, "busy"
            return 200, FIX["config"]
        if d.endswith("getItems"):
            return 200, FIX["items_rows"] if p["entityNameOrId"] == "Widget__c" else FIX["items_empty"]
        if d.endswith("getObjectInfo"):
            return 200, FIX["info"] if p["objectApiName"] == "Partner_Key__c" else FIX["denied"]
        raise AssertionError(f"unexpected descriptor {d}")


def run(sf, tmp_path, site, **kw):
    sleeps = []
    m = sf.Mapper(BASE, str(tmp_path), site, delay=0.5, cooldown=7, sleep=sleeps.append, **kw)
    return m.run(), m, sleeps


class TestParsing:
    def test_extract_context_encoded(self, sf):
        assert sf.extract_context(FIX["bootstrap"]) == ("FWUID_SYNTH_001", "1706_SYNTHAPPID")

    def test_extract_context_missing(self, sf):
        assert sf.extract_context("<html>nothing</html>") == (None, None)

    def test_parse_aura_guard_prefix(self, sf):
        state, rv, _ = sf.first_action(sf.parse_aura(FIX["items_empty"]))
        assert state == "SUCCESS" and sf.row_count(rv) == 0

    def test_out_of_sync_state(self, sf):
        assert sf.first_action(sf.parse_aura(FIX["out_of_sync"]))[0] == "OUT_OF_SYNC"

    def test_not_json(self, sf):
        assert sf.first_action(sf.parse_aura("<html>"))[0] == "NO_JSON"

    def test_harvest_apex(self, sf):
        got = sf.harvest_apex([FIX["bootstrap"], "x apex%3a%2f%2fOtherCtrl%2FACTION%24go y"])
        assert "PortalSearchCtrl.findRecords" in got["apex_refs"]
        assert "OtherCtrl.go" in got["apex_refs"]
        assert got["custom_components"] == ["PortalSearch"]


class TestMapping:
    def test_full_map(self, sf, tmp_path):
        rec, m, sleeps = run(sf, tmp_path, FakeSite())
        assert rec["endpoint"] == "/s/sfsites/aura"
        assert set(rec["objects"]) >= {"Account", "Widget__c", "Partner_Key__c"}
        assert rec["control"]["rows"] == 0
        assert rec["objects"]["Widget__c"]["rows"] == 3
        assert rec["objects"]["Account"]["rows"] == 0
        assert rec["objects"]["Partner_Key__c"]["flagged_fields"] == ["Api_Key__c"]
        assert rec["leads"] == ["Partner_Key__c", "Widget__c"] or set(rec["leads"]) == {"Widget__c", "Partner_Key__c"}
        assert "PortalSearchCtrl.findRecords" in rec["apex"]["apex_refs"]
        assert all(s == 0.5 for s in sleeps) and len(sleeps) == rec["requests"] - 1

    def test_read_only_descriptors_only(self, sf, tmp_path):
        site = FakeSite()
        run(sf, tmp_path, site)
        seen = {json.loads(urllib.parse.parse_qs(b)["message"][0])["actions"][0]["descriptor"].rsplit("$", 1)[1]
                for _, _, b in site.calls if b}
        assert seen <= {"getConfigData", "getItems", "getObjectInfo"}
        assert {m for m, _, _ in site.calls} <= {"GET", "POST"}
        page_sizes = {json.loads(urllib.parse.parse_qs(b)["message"][0])["actions"][0]["params"].get("pageSize")
                      for _, _, b in site.calls if b and "getItems" in b}
        assert page_sizes == {1}

    def test_evidence_saved_for_every_response(self, sf, tmp_path):
        rec, m, _ = run(sf, tmp_path, FakeSite())
        files = sorted(os.listdir(tmp_path / "evidence"))
        assert len(files) == len(rec["evidence_index"]) >= rec["requests"]
        assert json.loads((tmp_path / "summary.json").read_text())["base"] == BASE
        first = (tmp_path / "evidence" / files[0]).read_text()
        assert first.startswith("GET https://site.example.com/s/")

    def test_endpoint_fallback(self, sf, tmp_path):
        rec, _, _ = run(sf, tmp_path, FakeSite(live_endpoint="/aura"))
        assert rec["endpoint"] == "/aura"

    def test_resync_once(self, sf, tmp_path):
        site = FakeSite(sync_fail_once=True)
        rec, _, _ = run(sf, tmp_path, site)
        assert rec["endpoint"] == "/s/sfsites/aura"
        assert sum(1 for m, _, _ in site.calls if m == "GET") == 2

    def test_5xx_cools_down_and_retries(self, sf, tmp_path):
        rec, _, sleeps = run(sf, tmp_path, FakeSite(flaky_once=True))
        assert 7 in sleeps and rec["endpoint"] == "/s/sfsites/aura"

    def test_budget_stops_with_partial_note(self, sf, tmp_path):
        rec, _, _ = run(sf, tmp_path, FakeSite(), max_requests=4)
        assert rec["requests"] == 4 and any("partial" in n for n in rec["notes"])

    def test_not_a_site(self, sf, tmp_path):
        rec, _, _ = run(sf, tmp_path, lambda m, u, b: (200, "<html>plain</html>"))
        assert rec["endpoint"] is None and rec["objects"] == {} and any("fwuid" in n for n in rec["notes"])

    def test_no_endpoint_answers(self, sf, tmp_path):
        rec, _, _ = run(sf, tmp_path, FakeSite(live_endpoint="/nowhere"))
        assert rec["endpoint"] is None and any("no aura endpoint" in n for n in rec["notes"])


class TestEgress:
    def test_refuses_unusable_proxy(self, tmp_path):
        env = {**os.environ, "GRIMNIR_PROXY": "not-a-proxy"}
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), BASE, "--out", str(tmp_path / "o")],
                           capture_output=True, text=True, timeout=60, env=env)
        assert p.returncode == 4 and "refusing" in p.stderr
        assert not (tmp_path / "o").exists()
