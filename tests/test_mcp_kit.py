"""Offline tests: every server is a localhost fixture; nothing leaves the machine."""
import json
import os
import subprocess
import sys

import pytest

import mcp_fixture_server as fx
import mcp_layout as layout

ROOT = layout.ROOT


def run(*args, cwd=None, env=None, timeout=120):
    return layout.run(*args, cwd=cwd, env=env, timeout=timeout)


@pytest.fixture
def server():
    started = []

    def make(variant="clean"):
        srv, url, calls = fx.start(variant)
        started.append(srv)
        return url, calls
    yield make
    for s in started:
        s.shutdown()


def enum(server, variant, tmp_path, name=None):
    url, calls = server(variant)
    out = tmp_path / (name or variant)
    r = run("enum", url, "--out", str(out), "--timeout", "5")
    assert r.returncode == 0, r.stdout + r.stderr
    return json.loads((out / "mcp-assets.json").read_text()), str(out / "mcp-assets.json")


# ── enum ──
def test_enum_clean_has_no_poison_flags(server, tmp_path):
    assets, _ = enum(server, "clean", tmp_path)
    assert assets["is_mcp"] and len(assets["tools"]) == 5
    assert assets["poisoning_flags"] == []


def test_enum_flags_poisoned_tool(server, tmp_path):
    assets, _ = enum(server, "poisoned", tmp_path)
    flagged = {p["tool"]: p for p in assets["poisoning_flags"]}
    assert "add_numbers" in flagged and flagged["add_numbers"]["band"] in ("high", "critical")
    assert "invisible-unicode" in flagged["add_numbers"]["flags"]
    assert "get_weather" not in flagged


def test_enum_non_mcp_exits_3(tmp_path):
    r = run("enum", "http://127.0.0.1:9/mcp", "--out", str(tmp_path / "o"), "--timeout", "2", "--transport", "streamable")
    assert r.returncode == 3


# ── poison-scan ──
def test_poison_scan_positive_and_negative(server, tmp_path):
    _, bad = enum(server, "poisoned", tmp_path)
    _, good = enum(server, "clean", tmp_path)
    r = run("poison-scan", "scan", bad, "--out", str(tmp_path / "ps-bad"))
    assert r.returncode == 0 and "add_numbers" in r.stdout
    rec = json.loads((tmp_path / "ps-bad" / "poison-scan.json").read_text())
    top = rec["scored"][0]
    assert top["tool"] == "add_numbers" and top["score"] >= 60
    r = run("poison-scan", "scan", good, "--out", str(tmp_path / "ps-good"))
    assert "flagged 0" in r.stdout


def test_shadow_across_servers(server, tmp_path):
    _, clean = enum(server, "clean", tmp_path)
    _, shadow = enum(server, "shadow", tmp_path)
    run("poison-scan", "scan", clean, shadow, "--out", str(tmp_path / "x"))
    rec = json.loads((tmp_path / "x" / "poison-scan.json").read_text())
    assert any(f["tool"] == "calculator" and f["references_foreign_tool"] == "get_weather"
               for f in rec["cross_server_shadowing"])
    assert "get_weather" in rec["duplicate_tool_names"]
    # negative: two copies of the clean server do not shadow each other's tools by description
    _, clean2 = enum(server, "clean", tmp_path, "clean2")
    run("poison-scan", "scan", clean, clean2, "--out", str(tmp_path / "y"))
    assert json.loads((tmp_path / "y" / "poison-scan.json").read_text())["cross_server_shadowing"] == []


def test_rugpull_diff(server, tmp_path):
    _, base = enum(server, "clean", tmp_path)
    _, new = enum(server, "rugpull", tmp_path)
    r = run("poison-scan", "diff", "--baseline", base, "--current", new, "--out", str(tmp_path / "d"))
    assert "RUG-PULL" in r.stdout
    rec = json.loads((tmp_path / "d" / "rugpull-diff.json").read_text())
    assert [m["tool"] for m in rec["mutated_tools"]] == ["get_weather"]
    r = run("poison-scan", "diff", "--baseline", base, "--current", base, "--out", str(tmp_path / "d2"))
    assert "stable" in r.stdout


# ── call ──
def test_call_tool(server):
    url, _ = server()
    r = run("call", url, "--tool", "get_weather", "--args", '{"city":"Oslo"}')
    assert r.returncode == 0 and "Sunny in Oslo" in r.stdout
    assert run("call", url, "--tool", "nope").returncode == 1


# ── probe ──
def test_probe_finds_traversal_and_skips_destructive(server, tmp_path):
    url, calls = server()
    _, assets = enum(server, "clean", tmp_path)
    calls.clear()
    out = tmp_path / "probe"
    r = run("probe", url, "--assets", assets, "--mode", "traversal", "--out", str(out), "--timeout", "5")
    assert r.returncode == 0, r.stderr
    results = [json.loads(l) for l in (out / "probe-results.jsonl").read_text().splitlines()]
    assert any(x["tool"] == "read_note" and x["verdict"] == "SIGNAL" for x in results)
    assert "delete_note" not in calls
    assert not any(x["tool"] == "get_weather" and x["verdict"] == "SIGNAL" for x in results)


# ── confirm ──
def test_confirm_authz_confirmed_and_negative(server, tmp_path):
    url, _ = server()
    flags, out = layout.confirm_out(tmp_path, "authz")
    r = run("confirm", "authz", "--base-url", url, "--tool", "get_record", "--id-param", "recordId",
            "--own-id", "1001", "--victim-id", "1002", "--nonexistent-id", "999999",
            "--victim-marker", "Lucinda", *flags)
    assert r.returncode == 0, r.stderr
    assert json.loads(out.read_text())["verdict"] == "confirmed"
    # negative control: a marker that is not in the victim record must not confirm
    r = run("confirm", "authz", "--base-url", url, "--tool", "get_record", "--id-param", "recordId",
            "--own-id", "1001", "--victim-id", "1002", "--nonexistent-id", "999999", "--victim-marker", "zzz-absent",
            *layout.confirm_out(tmp_path, "authz-neg")[0])
    assert '"confirmed"' not in r.stdout


def test_confirm_ssrf_via_local_oob(server, tmp_path):
    import threading
    log = tmp_path / "hits.jsonl"
    oob = layout.start_oob(log)
    base = f"http://127.0.0.1:{oob.server_port}"
    url, _ = server()
    r = run("confirm", "ssrf", "--base-url", url, "--tool", "fetch_url", "--param", "url",
            "--oob-base", base, "--poll", "5", *layout.confirm_out(tmp_path, "ssrf")[0], env=layout.oob_env(log))
    oob.shutdown()
    assert '"verdict": "confirmed"' in r.stdout, r.stdout + r.stderr
    # negative: a tool that never fetches yields inconclusive
    oob2 = layout.start_oob(log)
    r = run("confirm", "ssrf", "--base-url", url, "--tool", "get_weather", "--param", "city",
            "--oob-base", f"http://127.0.0.1:{oob2.server_port}", "--poll", "2",
            *layout.confirm_out(tmp_path, "ssrf-neg")[0], env=layout.oob_env(log))
    oob2.shutdown()
    assert '"verdict": "inconclusive"' in r.stdout


# ── read-only broker (ported write-floor tests) ──
def test_broker_selftest():
    assert run("safe", "--selftest").returncode == 0


def test_broker_refuses_state_changing_call(server):
    url, calls = server()
    r = run("safe", "call", url, "--tool", "delete_note", "--args", '{"id":"1"}')
    assert r.returncode == 3 and "delete_note" not in calls
    assert run("safe", "call", url, "--tool", "get_weather", "--args", '{"city":"x"}').returncode == 0


def test_broker_strips_include_write_and_caps(server, tmp_path):
    url, calls = server()
    _, assets = enum(server, "clean", tmp_path)
    calls.clear()
    run("safe", "probe", url, "--assets", assets, "--include-write", "--mode", "traversal",
        "--out", str(tmp_path / "p"), "--timeout", "5", env=layout.max_calls_env(7))
    assert "delete_note" not in calls and 0 < len(calls) <= 7


def _outbound_assets(tmp_path, hint):
    t = {"name": "feedback-to-devs", "inputSchema": S_("text")}
    if hint:
        t["annotations"] = {"readOnlyHint": True}
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"tools": [{"name": "get_weather", "inputSchema": S_("city")}, t]}))
    return str(p)


def test_probe_skips_outbound_tool(server, tmp_path):
    url, calls = server()
    run("probe", url, "--assets", _outbound_assets(tmp_path, False), "--mode", "traversal",
        "--out", str(tmp_path / "o"), "--timeout", "5")
    assert "feedback-to-devs" not in calls and "get_weather" in calls


def test_broker_skips_outbound_tool_even_if_server_marks_it_read_only(server, tmp_path):
    url, calls = server()
    run("safe", "probe", url, "--assets", _outbound_assets(tmp_path, True), "--mode", "traversal",
        "--out", str(tmp_path / "o"), "--timeout", "5")
    assert "feedback-to-devs" not in calls and "get_weather" in calls


def S_(p):
    return {"type": "object", "properties": {p: {"type": "string"}}}


# ── shadow-scan (endpoint discovery) ──
def test_shadow_scan_finds_endpoint(server, tmp_path):
    url, _ = server()
    origin = url.rsplit("/mcp", 1)[0]
    paths = tmp_path / "paths.txt"
    paths.write_text("/nope\n/mcp\n")
    out = tmp_path / "ss"
    r = run("shadow-scan", origin, "--paths", str(paths), "--out", str(out))
    assert r.returncode == 0
    hits = (out / "shadow-hits.jsonl").read_text()
    assert "/mcp" in hits and "mcp-open" in hits and "/nope" not in hits


# ── fuzz ──
def fuzz(url, tmp_path, *extra, env=None):
    return run("fuzz", url, "--i-understand-this-calls-tools", "--out", str(tmp_path / "fz"), "--rate", "200",
               "--timeout", "5", *layout.fuzz_flags(tmp_path), *extra, env=env)


def test_fuzz_refuses_without_ack(server):
    url, calls = server("vuln")
    r = run("fuzz", url)
    assert r.returncode == 2 and "refusing" in r.stderr and calls == []


def test_fuzz_candidates_on_vulnerable_tools_not_clean_ones(server, tmp_path):
    log = tmp_path / "hits.jsonl"
    oob = layout.start_oob(log)
    url, calls = server("vuln")
    r = fuzz(url, tmp_path, "--oob-base", f"http://127.0.0.1:{oob.server_port}", env=layout.oob_env(log))
    oob.shutdown()
    assert r.returncode == 0, r.stderr
    res = [json.loads(l) for l in (tmp_path / "fz" / "fuzz-results.jsonl").read_text().splitlines()]
    sig = {(x["tool"], s) for x in res for s in x["signals"]}
    assert ("read_note", "passwd-content") in sig
    assert ("fetch_url", "oob-callback") in sig
    assert ("render_greeting", "template-evaluated") in sig
    assert ("ping_host", "cmd-evaluated") in sig
    assert ("parse_age", "error-leak") in sig
    assert not [x for x in res if x["tool"] in ("get_weather", "get_record") and x["signals"]]   # negatives
    assert "delete_note" not in calls and "skipped `delete_note`" in (tmp_path / "fz" / "fuzz-report.md").read_text()
    for tool in {x["tool"] for x in res}:
        assert sum(1 for x in res if x["tool"] == tool) <= 40


def test_fuzz_single_tool_and_destructive_opt_in(server, tmp_path):
    url, calls = server("vuln")
    fuzz(url, tmp_path, "--tool", "get_weather")
    assert set(calls) == {"get_weather"}
    calls.clear()
    fuzz(url, tmp_path, "--tool", "delete_note")
    assert calls == []
    fuzz(url, tmp_path, "--tool", "delete_note", "--include-destructive")
    assert set(calls) == {"delete_note"}
