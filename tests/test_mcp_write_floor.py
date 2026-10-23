"""The read-only MCP broker's write floor, end to end against a local stub server.

The failure worth guarding is an outbound write: a tool that carries a message to people at the
target (a feedback form, a support ticket) fuzzed or called by an unattended run. Its name matches
no destructive verb, and the server under test may even mark it readOnlyHint.
"""
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROKER = os.path.join(REPO, "artemis", "scripts", "mcp-readonly-broker.sh")
PROBE = os.path.join(REPO, "artemis", "scripts", "mcp-probe.sh")


class _Stub(BaseHTTPRequestHandler):
    calls: list = []

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        if msg.get("method") == "tools/call":
            _Stub.calls.append(msg["params"]["name"])
        res = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "stub"}} \
            if msg.get("method") == "initialize" else {"content": [{"type": "text", "text": "ok"}]}
        body = json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": res}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve():
    srv = HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/mcp"


def _assets(tmp_path):
    tools = [
        {"name": "search-flight", "inputSchema": {"type": "object", "properties": {"origin": {"type": "string"}}}},
        {"name": "feedback-to-devs", "annotations": {"readOnlyHint": True},
         "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
    ]
    p = tmp_path / "mcp-assets.json"
    p.write_text(json.dumps({"tools": tools}))
    (tmp_path / "payloads.txt").write_text("../../etc/passwd\n")
    return str(p)


def _env():
    return {k: v for k, v in os.environ.items() if k not in ("GRIMNIR_MCP_AUTH", "GN_SKIP_RE", "HTTPS_PROXY", "HTTP_PROXY")}


def test_broker_selftest():
    assert subprocess.run(["bash", BROKER, "--selftest"], capture_output=True).returncode == 0


def test_broker_refuses_calling_or_fuzzing_an_outbound_tool():
    for sub in ("call", "probe"):
        r = subprocess.run(["bash", BROKER, sub, "http://127.0.0.1:9/mcp", "--tool", "feedback-to-devs",
                            "--param", "text", "--args", "{}"], capture_output=True, text=True, env=_env())
        assert r.returncode == 3, (sub, r.stderr)


def test_broker_probe_skips_an_outbound_tool_the_server_marks_read_only(tmp_path):
    _Stub.calls = []
    srv, url = _serve()
    try:
        r = subprocess.run(["bash", BROKER, "probe", url, "--assets", _assets(tmp_path), "--payloads", str(tmp_path / "payloads.txt"),
                            "--max-calls", "20", "--out", str(tmp_path / "out"), "--timeout", "5"],
                           capture_output=True, text=True, env=_env(), timeout=120)
    finally:
        srv.shutdown()
    assert r.returncode == 0, r.stderr[-500:]
    assert "search-flight" in _Stub.calls
    assert "feedback-to-devs" not in _Stub.calls


def test_probe_alone_skips_outbound_tools_without_include_write(tmp_path):
    """Manual runs too: a canary into a feedback channel lands in someone's inbox."""
    _Stub.calls = []
    assets = json.loads(open(_assets(tmp_path)).read())
    assets["tools"][1].pop("annotations")
    (tmp_path / "mcp-assets.json").write_text(json.dumps(assets))
    srv, url = _serve()
    try:
        r = subprocess.run(["bash", PROBE, url, "--assets", str(tmp_path / "mcp-assets.json"), "--payloads", str(tmp_path / "payloads.txt"),
                            "--max-calls", "20", "--out", str(tmp_path / "out"), "--timeout", "5"],
                           capture_output=True, text=True, env=_env(), timeout=120)
    finally:
        srv.shutdown()
    assert r.returncode == 0, r.stderr[-500:]
    assert "feedback-to-devs" not in _Stub.calls and "search-flight" in _Stub.calls


def test_broker_caps_the_fuzz_budget(tmp_path):
    _Stub.calls = []
    (tmp_path / "many.txt").write_text("".join(f"../x{i}\n" for i in range(30)))
    srv, url = _serve()
    try:
        subprocess.run(["bash", BROKER, "probe", url, "--assets", _assets(tmp_path), "--payloads",
                        str(tmp_path / "many.txt"), "--max-calls", "400", "--out", str(tmp_path / "out"),
                        "--timeout", "5"], capture_output=True, text=True,
                       env={**_env(), "GRIMNIR_MCP_MAX_CALLS": "7"}, timeout=120)
    finally:
        srv.shutdown()
    assert 0 < len(_Stub.calls) <= 7


def test_broker_writes_enum_output_under_the_engagement(tmp_path):
    srv, url = _serve()
    proj = tmp_path / "eng"
    proj.mkdir()
    try:
        subprocess.run(["bash", BROKER, "enum", url, "--timeout", "5"], capture_output=True, text=True,
                       cwd=str(tmp_path), env={**_env(), "GRIMNIR_MCP_PROJECT_DIR": str(proj)}, timeout=120)
    finally:
        srv.shutdown()
    assert list((proj / "artemis" / "recon").glob("mcp-enum-*"))
    assert not (tmp_path / "reports").exists()


NEW_FINDING = os.path.join(REPO, "artemis", "scripts", "new-finding.sh")


def test_new_finding_records_detail_but_cannot_promote(tmp_path):
    """The confined specialist records a candidate in one call; it may describe it, never promote it."""
    (tmp_path / "artemis" / "findings").mkdir(parents=True)
    env = {**_env(), "GRIMNIR_DAEMON": "off", "GRIMNIR_ACTIVITY_ROLLUP": str(tmp_path / "r.jsonl")}
    r = subprocess.run(["bash", NEW_FINDING, str(tmp_path), "Error leaks model name", "MCP01", "Info",
                        "--description", "repro: broker call; negative control: valid date"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    f = json.loads(next((tmp_path / "artemis" / "findings").glob("*.json")).read_text())
    assert "negative control" in f["description"] and f["validation"]["state"] == "theoretical"
    for flag in ("--validation-state", "--status"):
        r = subprocess.run(["bash", NEW_FINDING, str(tmp_path), "T", "MCP01", "Info", flag, "confirmed"],
                           capture_output=True, text=True, env=env)
        assert r.returncode == 1 and "not accepted" in r.stderr
