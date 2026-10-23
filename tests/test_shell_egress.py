"""Shell tooling honors the program's egress proxy, or refuses (scripts/egress.py CLI + egress-env.sh).

Same contract as test_egress.py, for the shell side: with a proxy configured, a script routes through
it or exits; the load-bearing case is the dead proxy, which must leave ZERO direct hits at the
target. Everything is loopback.

Target addressing: egress.py exports NO_PROXY=localhost,127.0.0.1,::1 (a proxied program's own
loopback services must not be sent out). A target at 127.0.0.1 would therefore bypass the proxy by
design and prove nothing, so the stub MCP server listens on 127.0.0.2, which is loopback on Linux but
not in that list. The stub proxy forwards what it receives to the target named in the request line.
"""
import json
import os
import subprocess
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
EGRESS_PY = REPO / "scripts" / "egress.py"
EGRESS_SH = REPO / "scripts" / "egress-env.sh"
BROKER = REPO / "artemis" / "scripts" / "mcp-readonly-broker.sh"

_ENV_DROP = ("GRIMNIR_PROXY", "ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY",
             "http_proxy", "NO_PROXY", "no_proxy", "GRIMNIR_MCP_AUTH", "GRIMNIR_MCP_PROJECT_DIR")


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in _ENV_DROP}
    env.update(extra)
    return env


def _project(tmp_path, proxy=None):
    d = tmp_path / "proj"
    d.mkdir(exist_ok=True)
    if proxy is not None:
        (d / "roe.json").write_text(json.dumps({"proxy": proxy}))
    return str(d)


def _cli(project, **env):
    return subprocess.run([sys.executable, str(EGRESS_PY), "env", "--project-dir", project],
                          capture_output=True, text=True, env=_env(**env))


# ── CLI ──

def test_cli_no_proxy_prints_nothing(tmp_path):
    r = _cli(_project(tmp_path))
    assert (r.returncode, r.stdout) == (0, "")


def test_cli_socks5h_exports_every_name(tmp_path):
    r = _cli(_project(tmp_path, "socks5h://127.0.0.1:8899"))
    assert r.returncode == 0
    for name in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                 "NO_PROXY", "no_proxy", "GRIMNIR_PROXY"):
        assert f"export {name}=" in r.stdout, name
    assert "export ALL_PROXY=socks5h://127.0.0.1:8899" in r.stdout
    assert "export NO_PROXY=localhost,127.0.0.1,::1" in r.stdout


def test_cli_invalid_proxy_exits_4(tmp_path):
    r = _cli(_project(tmp_path, "ftp://127.0.0.1:21"))
    assert r.returncode == 4 and r.stdout == ""
    assert "unusable" in r.stderr


def test_cli_env_overrides_roe_json(tmp_path):
    p = _project(tmp_path, "socks5h://127.0.0.1:8899")
    r = _cli(p, GRIMNIR_PROXY="http://127.0.0.1:3128")
    assert "export GRIMNIR_PROXY=http://127.0.0.1:3128" in r.stdout
    assert "8899" not in r.stdout
    # an unusable override is refused, not skipped in favour of the valid file
    assert _cli(p, GRIMNIR_PROXY="nonsense").returncode == 4


# ── egress-env.sh ──

def _sh(script, project, **env):
    return subprocess.run(["bash", "-c", f'source "{EGRESS_SH}"; {script}'], capture_output=True, text=True,
                          env=_env(**env), cwd=project)


def test_sh_init_exports_proxy(tmp_path):
    p = _project(tmp_path, "socks5h://127.0.0.1:8899")
    r = _sh('egress_init "$PWD" && echo "$ALL_PROXY|$GRIMNIR_PROXY"', p)
    assert r.stdout.strip() == "socks5h://127.0.0.1:8899|socks5h://127.0.0.1:8899"


def test_sh_init_without_proxy_is_silent_and_exports_nothing(tmp_path):
    p = _project(tmp_path)
    r = _sh('egress_init "$PWD" && echo "[${ALL_PROXY:-}][${GRIMNIR_PROXY:-}]"', p)
    assert (r.returncode, r.stdout.strip(), r.stderr) == (0, "[][]", "")


def test_sh_init_invalid_returns_4(tmp_path):
    p = _project(tmp_path, "socks5h://127.0.0.1")   # no port
    r = _sh('egress_init "$PWD"; echo rc=$?', p)
    assert "rc=4" in r.stdout and "refusing to run" in r.stderr


def test_sh_refuse_if_proxied(tmp_path):
    p = _project(tmp_path, "http://127.0.0.1:3128")
    refused = _sh('egress_init "$PWD"; egress_refuse_if_proxied nmap; echo rc=$?', p)
    assert "rc=4" in refused.stdout and "nmap: refusing to run" in refused.stderr
    # tmp_path itself has no roe.json: no proxy, no refusal
    open_ = _sh('egress_init "$PWD"; egress_refuse_if_proxied nmap; echo rc=$?', str(tmp_path))
    assert "rc=0" in open_.stdout


def test_sh_effective_proxy_program_wins_over_explicit(tmp_path):
    p = _project(tmp_path, "http://127.0.0.1:3128")
    r = _sh('egress_init "$PWD"; egress_effective_proxy http://127.0.0.1:8080', p)
    assert r.stdout == "http://127.0.0.1:3128" and "ignoring --proxy" in r.stderr
    # no program proxy: the explicit one is used as before
    r = _sh('egress_init "$PWD"; egress_effective_proxy http://127.0.0.1:8080', str(tmp_path))
    assert r.stdout == "http://127.0.0.1:8080"


# ── broker end to end ──

class _Target(BaseHTTPRequestHandler):
    hits = 0

    def do_POST(self):
        _Target.hits += 1
        msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        res = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "stub"}} \
            if msg.get("method") == "initialize" else {"tools": []}
        body = json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": res}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _Proxy(BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):
        _Proxy.seen.append(self.path)            # absolute-URI form: what a forward proxy receives
        data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        req = urllib.request.Request(self.path, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as up:
            body = up.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler, host):
    srv = HTTPServer((host, 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _closed_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _broker_enum(tmp_path, proxy_url, target_url, *extra):
    project = _project(tmp_path, proxy_url)
    return subprocess.run(["bash", str(BROKER), "enum", target_url, "--timeout", "5", *extra],
                          capture_output=True, text=True, timeout=120,
                          env=_env(GRIMNIR_MCP_PROJECT_DIR=project))


def test_broker_enum_goes_through_the_program_proxy(tmp_path):
    _Target.hits, _Proxy.seen = 0, []
    target, proxy = _serve(_Target, "127.0.0.2"), _serve(_Proxy, "127.0.0.1")
    try:
        url = f"http://127.0.0.2:{target.server_port}/mcp"
        # the agent-supplied --proxy is overridden by the program's
        r = _broker_enum(tmp_path, f"http://127.0.0.1:{proxy.server_port}", url, "--proxy", "http://127.0.0.1:9")
    finally:
        target.shutdown(); proxy.shutdown()
    assert _Proxy.seen, r.stdout[-400:] + r.stderr[-400:]
    assert all(p.startswith(f"http://127.0.0.2:{target.server_port}/") for p in _Proxy.seen)
    assert _Target.hits == len(_Proxy.seen)       # every hit the target saw arrived via the proxy


def test_broker_enum_with_dead_proxy_never_connects_direct(tmp_path):
    _Target.hits = 0
    target = _serve(_Target, "127.0.0.2")
    try:
        url = f"http://127.0.0.2:{target.server_port}/mcp"
        _broker_enum(tmp_path, f"http://127.0.0.1:{_closed_port()}", url)
    finally:
        target.shutdown()
    assert _Target.hits == 0


def test_broker_refuses_an_unusable_proxy_before_any_traffic(tmp_path):
    _Target.hits = 0
    target = _serve(_Target, "127.0.0.2")
    try:
        r = _broker_enum(tmp_path, "socks5h://127.0.0.1", f"http://127.0.0.2:{target.server_port}/mcp")
    finally:
        target.shutdown()
    assert r.returncode == 4 and _Target.hits == 0


def test_broker_selftest_still_runs_without_a_project():
    assert subprocess.run(["bash", str(BROKER), "--selftest"], capture_output=True, env=_env()).returncode == 0


# ── recon-pipeline.sh ──

RECON = REPO / "huginn" / "scripts" / "recon-pipeline.sh"


def test_recon_pipeline_proxies_what_it_can_and_skips_the_rest(tmp_path):
    """httpx and katana are handed the program's proxy; naabu, whatweb and openssl never run."""
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("httpx", "katana", "naabu", "whatweb"):
        t = fakebin / tool
        t.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\n')
        t.chmod(0o755)
    project = _project(tmp_path, "socks5h://127.0.0.1:%d" % _closed_port())
    r = subprocess.run(["bash", str(RECON), "http://acme.example", "--project-dir", project,
                        "--skip-passive", "--skip-js"],
                       capture_output=True, text=True, timeout=120, env=_env(PATH=f"{fakebin}:/usr/bin:/bin"))
    assert r.returncode == 0, r.stderr[-500:]
    calls = log.read_text()
    assert "httpx " in calls and "-proxy socks5://127.0.0.1:" in calls     # Go tools: socks5h mapped
    assert "katana " in calls and calls.count("-proxy socks5://") >= 2
    assert "naabu" not in calls and "whatweb" not in calls
    pre = json.loads((Path(project) / "recon" / "preflight.json").read_text())
    assert set(pre["skipped_proxied"]) == {"naabu", "whatweb", "openssl"}


def test_recon_pipeline_refuses_an_unusable_proxy(tmp_path):
    project = _project(tmp_path, "http://127.0.0.1")
    r = subprocess.run(["bash", str(RECON), "http://acme.example", "--project-dir", project],
                       capture_output=True, text=True, timeout=60, env=_env())
    assert r.returncode == 4


# ── the newly wired leaf scripts: each refuses an unusable proxy at the egress gate ──
# These take no project dir, so they read GRIMNIR_PROXY from the environment (@OUT@ is a placeholder
# for a per-test output path). The argv is the minimum that reaches the egress gate.

_CURL_SCRIPTS = [
    ("artemis/scripts/prompt-injection-spray.sh", ["http://acme.example"]),
    ("artemis/scripts/rag-poisoning-spray.sh", ["http://acme.example"]),
    ("artemis/scripts/rag-document-extract.sh", ["http://acme.example"]),
    ("artemis/scripts/system-prompt-extract.sh", ["http://acme.example"]),
    ("artemis/scripts/output-xss-test.sh", ["http://acme.example"]),
    ("artemis/scripts/guardrail-probe.sh", ["http://acme.example"]),
    ("artemis/scripts/agent-tool-enum.sh", ["http://acme.example"]),
    ("artemis/scripts/llm-recon.sh", ["http://acme.example"]),
    ("nimbus/scripts/firebase-probe.sh", ["demo-project"]),
    ("nimbus/scripts/storage-scan.sh", ["demo-bucket"]),
    ("specter/scripts/spec-analyzer.sh", ["http://acme.example/openapi.json"]),   # URL -> download path
    ("specter/scripts/triage-probe.sh", ["acme.example", "direct", "@OUT@", "/"]),
]


@pytest.mark.parametrize("script,argv", _CURL_SCRIPTS, ids=[s for s, _ in _CURL_SCRIPTS])
def test_target_touching_script_refuses_an_unusable_proxy(tmp_path, script, argv):
    argv = [str(tmp_path / "triage.out") if a == "@OUT@" else a for a in argv]
    r = subprocess.run(["bash", str(REPO / script), *argv], capture_output=True, text=True,
                       timeout=60, cwd=str(tmp_path),
                       env=_env(GRIMNIR_PROXY="socks5h://127.0.0.1"))   # no port -> unusable
    assert r.returncode == 4, (r.stdout[-300:], r.stderr[-300:])
    assert "refus" in r.stderr.lower()


# ── hunter scripts: raw-socket scans cannot ride a proxy, so a configured proxy makes them refuse ──

_HUNTER_SCRIPTS = [
    ("hunter/scripts/host-discovery.sh", ["acme.example"]),
    ("hunter/scripts/service-enum.sh", ["acme.example"]),
    ("hunter/scripts/vuln-scan.sh", ["acme.example"]),
    ("hunter/scripts/smb-enum.sh", ["acme.example"]),
    ("hunter/scripts/cred-spray.sh", ["acme.example", "ssh"]),
    ("hunter/scripts/full-audit.sh", ["acme.example"]),
]


@pytest.mark.parametrize("script,argv", _HUNTER_SCRIPTS, ids=[s for s, _ in _HUNTER_SCRIPTS])
def test_hunter_script_refuses_when_proxied_and_never_scans(tmp_path, script, argv):
    """A configured (usable) proxy makes a raw-socket scanner refuse up front; the scanner binaries
    must never be invoked, so nothing leaks from an unproxied address."""
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    log = tmp_path / "scan.log"
    for tool in ("nmap", "hydra", "netexec", "enum4linux", "smbclient"):
        t = fakebin / tool
        t.write_text(f'#!/bin/sh\necho "{tool} $*" >> "{log}"\n')
        t.chmod(0o755)
    r = subprocess.run(["bash", str(REPO / script), *argv], capture_output=True, text=True,
                       timeout=60, cwd=str(tmp_path),
                       env=_env(PATH=f"{fakebin}:/usr/bin:/bin", GRIMNIR_PROXY="http://127.0.0.1:3128"))
    assert r.returncode == 4, (r.stdout[-300:], r.stderr[-300:])
    assert "refusing to run" in r.stderr
    assert not log.exists(), "a scanner ran despite a configured proxy"


# ── a plain-curl spray actually rides the exported proxy (the mechanism the curl scripts rely on) ──
# The refuse tests prove the gate fires; this proves the other half: when the gate passes, a bare
# curl (no --proxy flag) routes through the exported ALL_PROXY, and a dead proxy leaves zero direct
# hits at the target. 127.0.0.2 stands in for a non-loopback target (NO_PROXY lists only 127.0.0.1).

SPRAY = REPO / "artemis" / "scripts" / "prompt-injection-spray.sh"


def _run_spray(tmp_path, proxy_url, target):
    wl = tmp_path / "wl.txt"
    wl.write_text("probe-one\n")
    return subprocess.run(["bash", str(SPRAY), target, str(wl), "", str(tmp_path / "spray-out")],
                          capture_output=True, text=True, timeout=120, env=_env(GRIMNIR_PROXY=proxy_url))


def test_spray_rides_the_exported_proxy(tmp_path):
    _Target.hits, _Proxy.seen = 0, []
    target, proxy = _serve(_Target, "127.0.0.2"), _serve(_Proxy, "127.0.0.1")
    try:
        url = f"http://127.0.0.2:{target.server_port}/chat"
        r = _run_spray(tmp_path, f"http://127.0.0.1:{proxy.server_port}", url)
    finally:
        target.shutdown(); proxy.shutdown()
    assert _Proxy.seen, r.stdout[-300:] + r.stderr[-300:]
    assert all(p.startswith(f"http://127.0.0.2:{target.server_port}/") for p in _Proxy.seen)
    assert _Target.hits == len(_Proxy.seen)       # every target hit arrived via the proxy


def test_spray_with_dead_proxy_never_connects_direct(tmp_path):
    _Target.hits = 0
    target = _serve(_Target, "127.0.0.2")
    try:
        url = f"http://127.0.0.2:{target.server_port}/chat"
        _run_spray(tmp_path, f"http://127.0.0.1:{_closed_port()}", url)
    finally:
        target.shutdown()
    assert _Target.hits == 0
