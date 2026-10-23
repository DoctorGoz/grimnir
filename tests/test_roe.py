"""Rules of engagement: loading, the pre-fire check, pacing, and the batch loop that obeys them.

The silent failures: a missing or malformed roe.json read as "no limits", a batch that outruns a
program's rate or budget, or a throttled target hammered instead of backed off.
"""
import json
import multiprocessing
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _write(pd, name, obj):
    (Path(pd) / name).write_text(json.dumps(obj))


class TestLoad:
    def test_missing_file_is_conservative(self, roe_mod, tmp_path):
        r = roe_mod.load(str(tmp_path))
        assert r["_file"] is None and r["max_rps_per_host"] == 1.0
        # No roe.json is deny-by-default for unattended auto-fire: auto_fire_allowed is False and
        # the gate refuses an unattended lane while still letting a human run one.
        assert r["daily_request_budget"] == 300 and r["auto_fire_allowed"] is False
        assert not roe_mod.check_lane(str(tmp_path), {"class": "authz"}, unattended=True)[0]
        assert roe_mod.check_lane(str(tmp_path), {"class": "authz"}, unattended=False)[0]

    @pytest.mark.parametrize("bad", [
        {"max_rps_per_host": 0}, {"max_rps_per_host": "fast"}, {"daily_request_budget": -1},
        {"auto_fire_allowed": "no"}, {"max_rps_per_host": True},
    ])
    def test_bad_values_keep_the_default(self, roe_mod, tmp_path, bad):
        _write(tmp_path, "roe.json", bad)
        r = roe_mod.load(str(tmp_path))
        assert r["_errors"]
        assert r["max_rps_per_host"] == 1.0 and r["daily_request_budget"] == 300
        # A bad value keeps the conservative default, which for auto_fire_allowed is now False:
        # a malformed switch must never loosen into unattended firing.
        assert r["auto_fire_allowed"] is False

    def test_unparseable_quiet_hours_fail_closed(self, roe_mod, tmp_path):
        _write(tmp_path, "roe.json", {"quiet_hours_utc": "evenings"})
        r = roe_mod.load(str(tmp_path))
        assert r["_errors"] and roe_mod.in_quiet_hours(r)

    def test_non_object_file_is_defaults(self, roe_mod, tmp_path):
        (tmp_path / "roe.json").write_text("[1, 2]")
        r = roe_mod.load(str(tmp_path))
        assert r["_file"] is None and r["_errors"]

    def test_required_headers_overlay_legacy_file(self, roe_mod, tmp_path):
        _write(tmp_path, "request-headers.json", {"User-Agent": "old", "X-Device": "d1"})
        _write(tmp_path, "roe.json", {"required_headers": {"user-agent": "new"}})
        r = roe_mod.load(str(tmp_path))
        assert r["required_headers"]["user-agent"] == "new" and r["required_headers"]["X-Device"] == "d1"

    def test_legacy_list_headers(self, roe_mod, tmp_path):
        _write(tmp_path, "request-headers.json", ["User-Agent: researcher-tag"])
        assert roe_mod.required_header_lines(str(tmp_path)) == ["User-Agent: researcher-tag"]


class TestQuietHours:
    @pytest.mark.parametrize("spec,hour,quiet", [
        ("22-06", 23, True), ("22-06", 3, True), ("22-06", 12, False),
        ("22:00-06:00", 5, True), ([9, 17], 10, True), ([9, 17], 17, False), ("8-8", 8, False),
    ])
    def test_windows(self, roe_mod, spec, hour, quiet):
        now = datetime(2026, 1, 1, hour, tzinfo=timezone.utc)
        assert roe_mod.in_quiet_hours({"quiet_hours_utc": spec}, now) is quiet


class TestCheckLane:
    def test_supervised_program_parks_unattended_only(self, roe_mod, tmp_path):
        _write(tmp_path, "roe.json", {"auto_fire_allowed": False})
        assert not roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=True)[0]
        assert roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=False)[0]

    def test_roe_json_without_explicit_true_is_supervised(self, roe_mod, tmp_path):
        # The gate needs an explicit true; a roe.json that exists but omits auto_fire_allowed does
        # not auto-fire (the operator must deliberately opt the program in).
        _write(tmp_path, "roe.json", {"daily_request_budget": 1000})
        ok, why = roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=True)
        assert not ok and "auto_fire_allowed is not true" in why
        assert roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=False)[0]

    def test_roe_json_with_explicit_true_auto_fires(self, roe_mod, tmp_path):
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True})
        assert roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=True)[0]

    def test_no_roe_json_names_the_missing_file(self, roe_mod, tmp_path):
        block = roe_mod.global_block(str(tmp_path), unattended=True)
        assert block and "no roe.json" in block

    def test_quiet_hours_bind_the_operator_too(self, roe_mod, tmp_path):
        _write(tmp_path, "roe.json", {"quiet_hours_utc": [0, 24]})
        assert not roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=False)[0]

    def test_scanning_ban_refuses_costly_unattended_lanes(self, roe_mod, tmp_path):
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True, "automated_scanning_banned": True})
        assert roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=True)[0]   # ~2
        assert not roe_mod.check_lane(str(tmp_path), {"class": "jwt"}, unattended=True)[0]    # ~6
        assert roe_mod.check_lane(str(tmp_path), {"class": "jwt"}, unattended=False)[0]

    def test_budget(self, roe_mod, tmp_path):
        _write(tmp_path, "roe.json", {"daily_request_budget": 5, "max_rps_per_host": 1000})
        for _ in range(3):
            roe_mod.pace(str(tmp_path), "https://a.example.com/")
        assert roe_mod.check_lane(str(tmp_path), {"class": "infoleak"}, unattended=False)[0]   # 3+2
        assert not roe_mod.check_lane(str(tmp_path), {"class": "authz"}, unattended=False)[0]  # 3+4
        roe_mod.pace(str(tmp_path), "https://a.example.com/")
        roe_mod.pace(str(tmp_path), "https://a.example.com/")
        assert "spent" in roe_mod.global_block(str(tmp_path), unattended=False)


def _pace_n(args):
    pd, n = args
    import importlib.util
    spec = importlib.util.spec_from_file_location("roe_child", REPO / "scripts" / "roe.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    stamps = []
    for _ in range(n):
        m.pace(pd, "https://api.example.com/x")
        stamps.append(time.time())
    return stamps


class TestPacing:
    def test_rate_holds_across_processes(self, tmp_path):
        _write(tmp_path, "roe.json", {"max_rps_per_host": 10})
        with multiprocessing.get_context("fork").Pool(3) as pool:
            stamps = sorted(s for chunk in pool.map(_pace_n, [(str(tmp_path), 3)] * 3) for s in chunk)
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        assert min(gaps) >= 0.09, gaps          # 10 rps = 0.1s, small scheduler slack

    def test_hosts_are_paced_independently(self, roe_mod, tmp_path):
        slept = []
        r = roe_mod.load(str(tmp_path))
        roe_mod.pace(str(tmp_path), "https://a.example.com/", r, _sleep=slept.append)
        roe_mod.pace(str(tmp_path), "https://b.example.com/", r, _sleep=slept.append)
        assert slept == []

    def test_throttle_streak_resets_on_success(self, roe_mod, tmp_path):
        roe_mod.note_status(str(tmp_path), "https://a/", 429)
        roe_mod.note_status(str(tmp_path), "https://a/", 503)
        assert roe_mod.usage(str(tmp_path))["throttle_streak"] == 2
        roe_mod.note_status(str(tmp_path), "https://a/", 200)
        u = roe_mod.usage(str(tmp_path))
        assert u["throttle_streak"] == 0 and u["throttled"] == 2

    def test_day_rolls_over(self, roe_mod, tmp_path):
        _write(tmp_path, ".roe-state.json", {"date": "2000-01-01", "requests": 999, "throttled": 5})
        assert roe_mod.usage(str(tmp_path))["requests"] == 0
        roe_mod.pace(str(tmp_path), "https://a/", roe_mod.load(str(tmp_path)))
        assert roe_mod.usage(str(tmp_path))["requests"] == 1


class TestInitCli:
    def test_init_migrates_headers_and_refuses_overwrite(self, roe_mod, tmp_path):
        _write(tmp_path, "request-headers.json", {"User-Agent": "tag"})
        a = type("A", (), {"project_dir": str(tmp_path), "force": False})
        assert roe_mod.cmd_init(a) == 0
        body = json.loads((tmp_path / "roe.json").read_text())
        assert body["required_headers"] == {"User-Agent": "tag"} and body["source"] == ["operator"]
        assert roe_mod.cmd_init(a) == 1


# ── Batch firing ─────────────────────────────────────────────────────────────
def _leak_lanes(pd, n, cls="infoleak"):
    _write(pd, "scope.json", {"in_scope": ["api.example.com"]})
    lines = [json.dumps({"id": f"{cls}-{i}", "class": cls, "action_class": "read-only",
                         "method": "GET", "url": f"https://api.example.com/p{i}", "severity": "high"})
             for i in range(n)]
    with open(Path(pd) / "test-lanes.jsonl", "a") as fh:
        fh.write("\n".join(lines) + "\n")


def _fake_run(lane_runner_mod, roe_mod, script):
    """cmd_run stand-in: pops (disposition, status) per call, records the status as a response."""
    calls = []

    def run(ns):
        disp, status = script.pop(0) if script else ("negative", 200)
        calls.append(ns.lane)
        if status:
            roe_mod.note_status(ns.project_dir, "https://api.example.com/", status)
        fired = disp in ("negative", "confirmed", "candidate", "inconclusive")
        print(json.dumps({"lane": ns.lane, "fired": fired, "disposition": disp,
                          "finding_id": "SPE-001" if disp == "confirmed" else None}))
        return lane_runner_mod.EXIT_ROE_REFUSED if disp == "refused-roe" else 0
    return run, calls


def _batch(lane_runner_mod, pd, mx=5, sleeps=None):
    a = type("A", (), {"project_dir": str(pd), "max": mx, "dry_run": False})
    return lane_runner_mod.cmd_batch(a, _sleep=(sleeps.append if sleeps is not None else lambda s: None))


class TestBatch:
    def test_order_interleaves_classes_by_severity(self, lane_runner_mod):
        d = [{"id": "a1", "class": "authz", "severity": "high", "safe": True, "fireable": True},
             {"id": "a2", "class": "authz", "severity": "high", "safe": True, "fireable": True},
             {"id": "i1", "class": "infoleak", "severity": "critical", "safe": True, "fireable": True},
             {"id": "i2", "class": "infoleak", "severity": "low", "safe": True, "fireable": True},
             {"id": "x", "class": "authz", "severity": "critical", "safe": False, "fireable": True}]
        assert [x["id"] for x in lane_runner_mod.batch_order(d)] == ["i1", "a1", "i2", "a2"]

    def test_without_roe_json_refuses_unattended(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch):
        # No roe.json: the RoE gate refuses the first lane, global_block reports the missing file,
        # and the batch stops without firing the rest.
        _leak_lanes(tmp_path, 4)
        run, calls = _fake_run(lane_runner_mod, roe_mod, [("refused-roe", 0)] * 4)
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        assert _batch(lane_runner_mod, tmp_path) == lane_runner_mod.EXIT_ROE_REFUSED
        assert len(calls) == 1

    def test_with_roe_json_fires_up_to_max(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch):
        _leak_lanes(tmp_path, 6)
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True, "daily_request_budget": 1000})
        run, calls = _fake_run(lane_runner_mod, roe_mod, [])
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        _batch(lane_runner_mod, tmp_path, mx=4)
        assert len(calls) == 4

    def test_scanning_ban_caps_at_one(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch):
        _leak_lanes(tmp_path, 3)
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True, "automated_scanning_banned": True})
        run, calls = _fake_run(lane_runner_mod, roe_mod, [])
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        _batch(lane_runner_mod, tmp_path)
        assert len(calls) == 1

    def test_stops_at_first_confirmed(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch, capsys):
        _leak_lanes(tmp_path, 5)
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True})
        run, calls = _fake_run(lane_runner_mod, roe_mod, [("negative", 200), ("confirmed", 200)])
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        _batch(lane_runner_mod, tmp_path)
        assert len(calls) == 2
        summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert summary["stopped"].startswith("confirmed -> SPE-001")

    def test_backs_off_then_parks_on_throttling(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch):
        _leak_lanes(tmp_path, 6)
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True})
        run, calls = _fake_run(lane_runner_mod, roe_mod, [("negative", 429)] * 6)
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        sleeps = []
        _batch(lane_runner_mod, tmp_path, sleeps=sleeps)
        assert len(calls) == 3 and sleeps == [5.0, 10.0]
        acts = [json.loads(l) for l in (tmp_path / "activity.jsonl").read_text().splitlines()]
        assert acts[-1]["kind"] == "blocked" and "throttled" in acts[-1]["summary"]

    def test_throttle_streak_resets_between_lanes(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch):
        _leak_lanes(tmp_path, 5)
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True})
        script = [("negative", 429), ("negative", 429), ("negative", 200), ("negative", 429), ("negative", 200)]
        run, calls = _fake_run(lane_runner_mod, roe_mod, script)
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        sleeps = []
        _batch(lane_runner_mod, tmp_path, sleeps=sleeps)
        assert len(calls) == 5 and sleeps == [5.0, 10.0, 5.0]

    def test_global_roe_refusal_stops_and_exits_4(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch):
        _leak_lanes(tmp_path, 3)
        _write(tmp_path, "roe.json", {"auto_fire_allowed": False})
        run, calls = _fake_run(lane_runner_mod, roe_mod, [("refused-roe", 0)] * 3)
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        assert _batch(lane_runner_mod, tmp_path) == lane_runner_mod.EXIT_ROE_REFUSED
        assert len(calls) == 1


class TestRunEnforcesRoe:
    @__import__("pytest").mark.skip(reason='exercises a component that is not part of this cut')
    def test_supervised_program_refuses_unattended_run(self, tmp_path):
        import subprocess
        _leak_lanes(tmp_path, 1)
        _write(tmp_path, "roe.json", {"auto_fire_allowed": False})
        p = subprocess.run(["python3", str(REPO / "scripts" / "lane-runner.py"), "run",
                            "--project-dir", str(tmp_path), "--lane", "infoleak-0"],
                           capture_output=True, text=True, timeout=60)
        assert p.returncode == 4, p.stdout + p.stderr
        assert json.loads(p.stdout.strip().splitlines()[-1])["disposition"] == "refused-roe"
        assert not (tmp_path / ".lane-runs.jsonl").exists()

    @__import__("pytest").mark.skip(reason='exercises a component that is not part of this cut')
    def test_no_roe_json_refuses_unattended_run(self, tmp_path):
        import subprocess
        _leak_lanes(tmp_path, 1)   # no roe.json written at all
        p = subprocess.run(["python3", str(REPO / "scripts" / "lane-runner.py"), "run",
                            "--project-dir", str(tmp_path), "--lane", "infoleak-0"],
                           capture_output=True, text=True, timeout=60)
        assert p.returncode == 4, p.stdout + p.stderr
        res = json.loads(p.stdout.strip().splitlines()[-1])
        assert res["disposition"] == "refused-roe" and "no roe.json" in p.stdout


class TestUnauthedOnly:
    def test_lane_authed(self, lane_runner_mod):
        f = lane_runner_mod.lane_authed
        assert not f({"class": "infoleak", "url": "https://a/x"})
        assert not f({"headers": ["User-Agent: researcher", "Accept: */*"]})
        assert f({"headers": ["Cookie: s=1"]}) and f({"other_headers": ["Authorization: Bearer x"]})
        assert f({"headers": {"X-Api-Key": "k"}}) and f({"accounts": ["A", "B"]})
        assert f({"headers": [["odd", "shape"]]})                    # not understood -> authed
        assert f({"url": "https://a/x"}, required_headers=["X-Api-Key: k"])

    def test_batch_unauthed_only_holds_authed_lanes(self, lane_runner_mod, roe_mod, tmp_path, monkeypatch, capsys):
        _leak_lanes(tmp_path, 2)
        with open(tmp_path / "test-lanes.jsonl", "a") as fh:
            fh.write(json.dumps({"id": "authed-0", "class": "infoleak", "action_class": "read-only",
                                 "method": "GET", "url": "https://api.example.com/me", "severity": "critical",
                                 "headers": ["Cookie: s=stale"]}) + "\n")
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True, "daily_request_budget": 1000})
        run, calls = _fake_run(lane_runner_mod, roe_mod, [])
        monkeypatch.setattr(lane_runner_mod, "cmd_run", run)
        a = type("A", (), {"project_dir": str(tmp_path), "max": 5, "dry_run": False, "unauthed_only": True})
        assert lane_runner_mod.cmd_batch(a, _sleep=lambda s: None) == 0
        assert "authed-0" not in calls and len(calls) == 2
        assert '"authed_held": 1' in capsys.readouterr().out


class TestAudit:
    """roe.py audit: every onboarded program lands in exactly one state, and a file that does not
    mean what it says (false with no reason, an unconfirmed template, a shelved program still set
    to auto-fire) is flagged."""
    @pytest.fixture(autouse=True)
    def _needs_roe_ops(self, roe_mod):
        if not hasattr(roe_mod, "audit"):
            pytest.skip("roe_ops.py is not part of this build")


    def _prog(self, ws, name, roe=None):
        pd = ws / name
        pd.mkdir()
        if roe is not None:
            _write(pd, "roe.json", roe)
        return str(pd)

    def test_states_and_issues(self, roe_mod, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        self._prog(ws, "auto", {"auto_fire_allowed": True, "policy_checked": "2099-01-01"})
        self._prog(ws, "parked", {"auto_fire_allowed": False})
        self._prog(ws, "shelf", {"auto_fire_allowed": False, "parked_reason": "shelved: tested out"})
        self._prog(ws, "tmpl", {"_note": roe_mod.TEMPLATE_MARK + ", then confirm."})
        miss = self._prog(ws, "missing")
        eng = tmp_path / "engaged.tsv"
        eng.write_text(f"# h\nmiss-h\t2026-01-01T00:00:00Z\t{miss}\tengaged via /engage\th1\n"
                       f"gone\t2026-01-01T00:00:00Z\t{ws}/gone\tSHELVED\n")
        rows = {r["program"]: r for r in roe_mod.audit(str(ws), str(eng))}
        assert rows["auto"]["state"] == "AUTO" and not rows["auto"]["issues"]
        assert rows["parked"]["state"] == "PARKED"
        assert any("no parked_reason" in i for i in rows["parked"]["issues"])
        assert rows["shelf"]["state"] == "SHELVED" and not any("parked_reason" in i for i in rows["shelf"]["issues"])
        assert any("template" in i for i in rows["tmpl"]["issues"])
        assert rows["missing"]["state"] == "MISSING" and rows["missing"]["handles"] == ["miss-h"]
        assert "gone" not in rows

    def test_shelved_in_index_but_auto_is_flagged(self, roe_mod, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        pd = self._prog(ws, "p", {"auto_fire_allowed": True, "policy_checked": "2099-01-01"})
        eng = tmp_path / "engaged.tsv"
        eng.write_text(f"p\t2026-01-01T00:00:00Z\t{pd}\tSHELVED-WARM 2026-10-14\n")
        (row,) = roe_mod.audit(str(ws), str(eng))
        assert any("engaged index says shelved" in i for i in row["issues"])

    def test_stale_policy_check(self, roe_mod, tmp_path):
        pd = self._prog(tmp_path, "p", {"policy_checked": "2020-01-01"})
        assert any("old" in i for i in roe_mod.audit_row(pd)["issues"])

    def test_markdown_lists_missing_separately(self, roe_mod, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        self._prog(ws, "a", {"auto_fire_allowed": True})
        md = roe_mod.audit_markdown(roe_mod.audit(str(ws)), "now")
        assert "| a | AUTO |" in md and "AUTO 1 |" in md


class TestPolicyCheck:
    """policy-check re-stamps policy_checked only while the live policy hash matches; a changed
    policy is flagged (never re-stamped) and a fetch error writes nothing."""
    @pytest.fixture(autouse=True)
    def _needs_roe_ops(self, roe_mod):
        if not hasattr(roe_mod, "audit"):
            pytest.skip("roe_ops.py is not part of this build")


    def _pd(self, tmp_path, **kw):
        _write(tmp_path, "roe.json", {"auto_fire_allowed": True, **kw})
        return str(tmp_path)

    def _read(self, tmp_path):
        return json.loads((tmp_path / "roe.json").read_text())

    def test_baseline_then_unchanged(self, roe_mod, tmp_path):
        pd = self._pd(tmp_path)
        assert roe_mod.policy_check(pd, "h", fetch=lambda h: "P", today="2026-01-01")["status"] == "baseline"
        assert roe_mod.policy_check(pd, "h", fetch=lambda h: "P", today="2026-02-01")["status"] == "unchanged"
        assert self._read(tmp_path)["policy_checked"] == "2026-02-01"

    def test_changed_is_flagged_not_restamped(self, roe_mod, tmp_path):
        pd = self._pd(tmp_path)
        roe_mod.policy_check(pd, "h", fetch=lambda h: "P1", today="2026-01-01")
        assert roe_mod.policy_check(pd, "h", fetch=lambda h: "P2", today="2026-03-01")["status"] == "changed"
        d = self._read(tmp_path)
        assert d["policy_checked"] == "2026-01-01" and d["policy_changed"].startswith("2026-03-01")
        assert any("policy changed" in i for i in roe_mod.audit_row(pd)["issues"])

    def test_fetch_error_writes_nothing(self, roe_mod, tmp_path):
        pd = self._pd(tmp_path)
        before = (tmp_path / "roe.json").read_text()
        def boom(h):
            raise OSError("down")
        assert roe_mod.policy_check(pd, "h", fetch=boom)["status"] == "error"
        assert (tmp_path / "roe.json").read_text() == before

    def test_no_file(self, roe_mod, tmp_path):
        assert roe_mod.policy_check(str(tmp_path), "h", fetch=lambda h: "P")["status"] == "no-file"
