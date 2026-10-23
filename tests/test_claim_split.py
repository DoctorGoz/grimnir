"""Claim-split verification: a finding is filed at its floor, not retracted as a unit.

The floor walk is the logic whose failure is silent (a wrong severity that still exits 0), so
it gets case-by-case tests; the shell tools are exercised end to end in a throwaway project.
"""
import json
import os
import subprocess
import time

import pytest


def _c(cid, kind, sev, verdict):
    return {"id": cid, "kind": kind, "text": cid, "severity_if_true": sev,
            "control": "x", "verdict": verdict, "evidence": []}


def _f(claims, sev="high", state="confirmed"):
    d = {"id": "SPE-001", "severity": sev, "validation": {"state": state}}
    if claims is not None:
        d["claims"] = claims
    return d


class TestFloorWalk:
    def test_all_survived_reaches_top(self, state_mod):
        f = _f([_c("C1", "base", "low", "survived"), _c("C2", "escalation", "medium", "survived"),
                _c("C3", "escalation", "high", "survived")])
        assert state_mod.floor_severity(f) == "high"

    def test_refuted_middle_escalation_is_skipped_not_fatal(self, state_mod):
        f = _f([_c("C1", "base", "low", "survived"), _c("C2", "escalation", "medium", "refuted"),
                _c("C3", "escalation", "high", "survived")])
        assert state_mod.floor_severity(f) == "high"

    def test_refuted_top_escalation_lowers_floor_to_base(self, state_mod):
        f = _f([_c("C1", "base", "medium", "survived"), _c("C2", "escalation", "high", "refuted")])
        assert state_mod.floor_severity(f) == "medium"

    def test_untested_stops_the_walk(self, state_mod):
        f = _f([_c("C1", "base", "low", "survived"), _c("C2", "escalation", "medium", "untested"),
                _c("C3", "escalation", "high", "survived")])
        assert state_mod.floor_severity(f) == "low"

    def test_base_refuted_or_untested_is_none(self, state_mod):
        for v in ("refuted", "untested"):
            f = _f([_c("C1", "base", "low", v), _c("C2", "escalation", "high", "survived")])
            assert state_mod.floor_severity(f) is None

    def test_missing_base_is_none(self, state_mod):
        assert state_mod.floor_severity(_f([_c("C2", "escalation", "high", "survived")])) is None

    def test_input_order_does_not_matter(self, state_mod):
        f = _f([_c("C3", "escalation", "high", "survived"), _c("C1", "base", "low", "survived"),
                _c("C2", "escalation", "medium", "untested")])
        assert state_mod.floor_severity(f) == "low"

    def test_no_claims_back_compat(self, state_mod):
        assert state_mod.floor_severity(_f(None, sev="High")) == "high"
        assert state_mod.floor_severity(_f(None, state="validated")) is None
        assert state_mod.floor_severity(_f([])) == "high"


@pytest.fixture
def project(tmp_path, repo_root):
    def sh(script, *args):
        return subprocess.run(["bash", str(repo_root / "scripts" / script), *args],
                              capture_output=True, text=True, env={**os.environ, "GRIMNIR_HOME": str(tmp_path / "h")})
    p = tmp_path / "proj"
    p.mkdir()
    return p, sh


def _create(project, *extra):
    p, sh = project
    r = sh("finding.sh", "--project-dir", str(p), "--agent", "specter", "--severity", "high",
           "--title", "Sample finding title", "--class", "authz", *extra)
    assert r.returncode == 0, r.stderr
    return p / "specter" / "findings" / "SPE-001.json"


CLAIMS = ["--claim", "base|medium|object is readable|negative control",
          "--claim", "escalation|high|reaches internal network|out-of-band probe"]


class TestFindingSh:
    def test_claim_seeds_untested_claims(self, project):
        d = json.loads(_create(project, *CLAIMS).read_text())
        assert [(c["id"], c["kind"], c["verdict"]) for c in d["claims"]] == \
            [("C1", "base", "untested"), ("C2", "escalation", "untested")]
        assert d["claims"][1]["control"] == "out-of-band probe"

    def test_claim_requires_exactly_one_base(self, project):
        p, sh = project
        r = sh("finding.sh", "--project-dir", str(p), "--agent", "specter", "--severity", "low",
               "--title", "Sample finding title", "--claim", "escalation|high|x|y")
        assert r.returncode != 0 and "base" in r.stderr

    def test_claim_rejects_bad_severity(self, project):
        p, sh = project
        r = sh("finding.sh", "--project-dir", str(p), "--agent", "specter", "--severity", "low",
               "--title", "Sample finding title", "--claim", "base|huge|x|y")
        assert r.returncode != 0

    def test_repro_scaffold_is_runnable_template_without_real_values(self, project):
        _create(project, "--repro")
        script = project[0] / "repro" / "SPE-001.sh"
        text = script.read_text()
        assert os.access(script, os.X_OK) and "set -euo pipefail" in text
        assert "credentials.jsonl" in text and "EXPECTED" in text and "ACTUAL" in text
        assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
        # No credential row, so it must stop on the missing label, not send anything.
        (project[0] / "credentials.jsonl").write_text("")
        r = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                           env={**os.environ, "PROJECT_DIR": str(project[0])})
        assert r.returncode == 2 and "no credential labelled" in r.stderr


def _validate(project, *extra):
    p, sh = project
    return sh("validate-finding.sh", "--project-dir", str(p), "--agent", "specter", "--id", "SPE-001",
              "--state", "confirmed", "--negative-control", "other account got 403", *extra)


class TestValidateFinding:
    def test_confirm_refused_while_base_untested(self, project):
        fp = _create(project, *CLAIMS)
        r = _validate(project)
        assert r.returncode != 0 and "base claim has not survived" in r.stderr
        assert json.loads(fp.read_text())["validation"]["state"] == "theoretical"

    def test_confirm_refused_when_base_refuted(self, project):
        fp = _create(project, *CLAIMS)
        r = _validate(project, "--claim-verdict", "C1=refuted")
        assert r.returncode != 0
        assert json.loads(fp.read_text())["validation"]["state"] == "theoretical"

    def test_confirm_writes_floor_when_escalation_refuted(self, project):
        fp = _create(project, *CLAIMS)
        r = _validate(project, "--claim-verdict", "C1=survived", "--claim-verdict", "C2=refuted")
        assert r.returncode == 0, r.stderr
        assert "floor severity: medium" in r.stdout
        d = json.loads(fp.read_text())
        assert d["floor_severity"] == "medium" and d["validation"]["state"] == "confirmed"
        assert d["claims"][1]["verdict"] == "refuted"


    def test_unknown_claim_or_verdict_rejected(self, project):
        _create(project, *CLAIMS)
        assert _validate(project, "--claim-verdict", "C9=survived").returncode != 0
        assert _validate(project, "--claim-verdict", "C1=maybe").returncode != 0

    def test_no_claims_back_compat_floor_is_own_severity(self, project):
        fp = _create(project)
        r = _validate(project)
        assert r.returncode == 0, r.stderr
        assert json.loads(fp.read_text())["floor_severity"] == "high"

    def test_cli_show_prints_claims_and_floor(self, project, repo_root):
        _create(project, *CLAIMS)
        _validate(project, "--claim-verdict", "C1=survived", "--claim-verdict", "C2=refuted")
        r = subprocess.run(["python3", str(repo_root / "scripts" / "finding_state.py"), "show",
                            "--project-dir", str(project[0]), "--id", "SPE-001"], capture_output=True, text=True)
        assert r.returncode == 0 and "floor: medium" in r.stdout and "refuted" in r.stdout


class TestFreshEyes:
    def _ready(self, project):
        fp = _create(project, "--repro", *CLAIMS)
        p = project[0]
        (p / "evidence").mkdir()
        (p / "evidence" / "proof.txt").write_text("proof")
        (p / "notes.md").write_text("engagement notes, must not travel")
        (p / "intel.jsonl").write_text("{}")
        d = json.loads(fp.read_text())
        d["claims"][0]["verdict"] = "survived"
        d["floor_severity"] = "medium"
        d["claims"][0]["evidence"] = ["evidence/proof.txt", "../outside.txt"]
        fp.write_text(json.dumps(d))
        return p

    def test_packet_holds_only_allowed_files(self, project, fresh_mod):
        p = self._ready(project)
        packet, copied, missing = fresh_mod.build_packet(p, "SPE-001", p / "specter/findings/SPE-001.json")
        files = sorted(str(f.relative_to(packet)) for f in packet.rglob("*") if f.is_file())
        assert files == ["SPE-001.json", "evidence/proof.txt", "repro/SPE-001.sh"]
        assert missing == ["../outside.txt"]
        d = json.loads((packet / "SPE-001.json").read_text())
        assert "floor_severity" not in d and all(c["verdict"] == "untested" for c in d["claims"])

    def test_dry_run_launches_nothing(self, project, repo_root):
        p = self._ready(project)
        marker = p / "launched"
        env = {**os.environ, "GRIMNIR_REVIEWER_CMD": f"touch {marker}"}
        r = subprocess.run(["python3", str(repo_root / "scripts" / "fresh-eyes.py"), "--project-dir", str(p),
                            "--id", "SPE-001", "--dry-run"], capture_output=True, text=True, env=env)
        assert r.returncode == 0 and "dry-run" in r.stdout and f"touch {marker}" in r.stdout
        assert not marker.exists() and (p / "reviews" / "SPE-001-packet").is_dir()

    def test_launch_uses_configured_command_in_packet_dir(self, project, repo_root):
        p = self._ready(project)
        env = {**os.environ, "GRIMNIR_REVIEWER_CMD": "bash -c pwd"}
        r = subprocess.run(["python3", str(repo_root / "scripts" / "fresh-eyes.py"), "--project-dir", str(p),
                            "--id", "SPE-001", "--timebox-min", "1"], capture_output=True, text=True, env=env)
        assert r.returncode == 0 and "not blocked" in r.stdout
        log = p / "reviews" / "SPE-001-fresh-eyes.log"
        for _ in range(50):
            if log.exists() and log.read_text().strip():
                break
            time.sleep(0.1)
        assert log.read_text().strip().endswith("SPE-001-packet")


class TestReportHygieneFloor:
    def _run(self, repo_root, finding, report):
        return subprocess.run(["bash", str(repo_root / "scripts" / "check-report-hygiene.sh"),
                               "--finding", str(finding), str(report)], capture_output=True, text=True)

    def test_warns_when_severity_exceeds_floor(self, tmp_path, repo_root):
        f = tmp_path / "f.json"
        f.write_text(json.dumps({"floor_severity": "medium"}))
        r = tmp_path / "r.md"
        r.write_text("# Report\n\n**Severity**: High\n")
        out = self._run(repo_root, f, r)
        assert "finding floor is medium" in out.stdout and out.returncode == 0

    def test_silent_at_or_below_floor(self, tmp_path, repo_root):
        f = tmp_path / "f.json"
        f.write_text(json.dumps({"floor_severity": "high"}))
        r = tmp_path / "r.md"
        r.write_text("Severity: Medium\n")
        assert "RESULT: clean." in self._run(repo_root, f, r).stdout

    def test_warns_when_no_floor_recorded(self, tmp_path, repo_root):
        f = tmp_path / "f.json"
        f.write_text("{}")
        r = tmp_path / "r.md"
        r.write_text("Severity: Low\n")
        assert "no floor_severity" in self._run(repo_root, f, r).stdout
