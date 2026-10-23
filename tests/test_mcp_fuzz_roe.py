"""mcp-fuzz.py under a program's rules of engagement: scanning ban, pacing, egress."""
import json
import os

import mcp_fixture_server as fx
import mcp_layout as layout


def _fuzz(url, tmp_path, roe, *extra, env=None):
    d = tmp_path / "eng"
    d.mkdir(exist_ok=True)
    (d / "roe.json").write_text(json.dumps(roe))
    return layout.run("fuzz", url, "--i-understand-this-calls-tools", "--project-dir", str(d),
                      "--rate", "1000", "--timeout", "5", *extra, env=env), d


def _server(variant="vuln"):
    srv, url, calls = fx.start(variant)
    return srv, url, calls


def test_fuzz_refuses_when_roe_bans_scanning(tmp_path):
    srv, url, calls = _server()
    try:
        r, _ = _fuzz(url, tmp_path, {"automated_scanning_banned": True})
    finally:
        srv.shutdown()
    assert r.returncode == 4 and "bans automated scanning" in r.stderr and calls == []


def test_fuzz_paces_through_roe_and_writes_under_the_engagement(tmp_path):
    srv, url, calls = _server()
    try:
        r, d = _fuzz(url, tmp_path, {"max_rps_per_host": 1000, "daily_request_budget": 100000},
                     "--tool", "get_weather")
    finally:
        srv.shutdown()
    assert r.returncode == 0, r.stderr
    assert json.loads((d / ".roe-state.json").read_text())["requests"] >= len(calls) > 0
    assert list((d / "artemis" / "recon").glob("mcp-fuzz-*/fuzz-report.md"))


def test_fuzz_refuses_an_unusable_egress_proxy(tmp_path):
    srv, url, calls = _server()
    try:
        r, _ = _fuzz(url, tmp_path, {"max_rps_per_host": 1000}, env={"GRIMNIR_PROXY": "ftp://nowhere.invalid:1"})
    finally:
        srv.shutdown()
    assert r.returncode == 4 and "refusing" in r.stderr and calls == []


def test_fuzz_still_requires_the_opt_in_flag_under_a_project(tmp_path):
    srv, url, calls = _server()
    try:
        d = tmp_path / "eng"
        d.mkdir()
        r = layout.run("fuzz", url, "--project-dir", str(d))
    finally:
        srv.shutdown()
    assert r.returncode == 2 and calls == []
