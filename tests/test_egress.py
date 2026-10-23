"""The per-program egress proxy: with one configured, every client either rides it or refuses.

The failure these tests guard is the silent one — a request that leaves direct because the proxy
was unreachable, unparsed, or simply not threaded through. So the load-bearing cases are the
fail-closed ones (a proxy pointed at a closed port must leave ZERO direct hits at the target) and
the routing ones (a request through a loopback stub proxy / stub SOCKS5 server must arrive with the
target having seen nothing direct). Everything is loopback; no external request is made.
"""
import argparse
import contextlib
import json
import os
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from conftest import _load

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import egress  # noqa: E402  imported under its real name: the tools under test share this instance


@pytest.fixture(autouse=True)
def _clear_egress_state(monkeypatch):
    """A remembered project dir must not leak between tests (each test sets its own, if any)."""
    monkeypatch.setattr(egress, "_PROJECT_DIR", None)


@pytest.fixture(scope="session")
def params_mod():
    return _load("grimnir_egress_params", "scripts/params.py")


@pytest.fixture(scope="session")
def authz_mod():
    return _load("grimnir_egress_authz", "scripts/confirm/authz-confirm.py")


def _serve(handler_cls):
    """A loopback HTTP server on an ephemeral port. Yields (base_url, hits, shutdown)."""
    hits = []

    class Handler(handler_cls):
        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    srv.hits = hits
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def shutdown():
        srv.shutdown()

    return f"http://127.0.0.1:{srv.server_address[1]}", hits, shutdown


class _Target(BaseHTTPRequestHandler):
    """The engagement's host: every request that reaches it is recorded."""

    def _send(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.hits.append(self.path)
        self._send(b"target-ok")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.hits.append(self.path)
        self._send(b'{"ok":true}')


class _Proxy(BaseHTTPRequestHandler):
    """A stub HTTP proxy: absolute-URI requests are forwarded to their target and recorded."""

    def do_GET(self):
        self.server.hits.append(self.path)
        # Forward with proxy handling disabled: this stub IS the egress.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(urllib.request.Request(self.path), timeout=5) as resp:
                data, code = resp.read(), resp.status
        except urllib.error.HTTPError as e:
            data, code = e.read(), e.code
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def target():
    url, hits, shutdown = _serve(_Target)
    yield url, hits
    shutdown()


@pytest.fixture
def http_proxy():
    url, seen, shutdown = _serve(_Proxy)
    yield url, seen
    shutdown()


class _Socks5Stub:
    """A minimal SOCKS5 CONNECT server (no auth), then a blind relay. Records what each connection
    asked for, so a test can tell a proxied request from a direct one."""

    def __init__(self):
        self.targets = []
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.url = f"socks5h://127.0.0.1:{self._srv.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self._srv.close()

    def _accept(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    @staticmethod
    def _read(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("short read")
            buf += chunk
        return buf

    def _session(self, conn):
        upstream = None
        try:
            _ver, n = self._read(conn, 2)
            self._read(conn, n)                          # offered methods
            conn.sendall(b"\x05\x00")                    # no auth
            _ver, _cmd, _rsv, atyp = self._read(conn, 4)
            if atyp == 1:                                # IPv4
                host = socket.inet_ntoa(self._read(conn, 4))
            elif atyp == 3:                              # domain (socks5h)
                host = self._read(conn, self._read(conn, 1)[0]).decode()
            else:
                return
            port = int.from_bytes(self._read(conn, 2), "big")
            self.targets.append((host, port))
            upstream = socket.create_connection((host, port), timeout=5)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            pumps = [threading.Thread(target=self._pump, args=(src, dst), daemon=True)
                     for src, dst in ((conn, upstream), (upstream, conn))]
            for t in pumps:
                t.start()
            for t in pumps:
                t.join(timeout=10)
        except (OSError, ConnectionError):
            pass
        finally:
            conn.close()
            if upstream:
                upstream.close()

    @staticmethod
    def _pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)


@pytest.fixture
def socks_proxy():
    stub = _Socks5Stub()
    yield stub
    stub.close()


def _closed_proxy() -> str:
    """A proxy URL on a loopback port nothing listens on: connection refused, not a hang."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def _port_of(url: str) -> int:
    return int(url.rsplit(":", 1)[1])


def _write_roe(pd, **fields):
    (pd / "roe.json").write_text(json.dumps(fields))


# ── roe.json's proxy field ─────────────────────────────────────────────────────
class TestRoeField:
    def test_default_is_empty(self, roe_mod, tmp_path):
        r = roe_mod.load(str(tmp_path))
        assert r["proxy"] == "" and not r["_errors"]

    def test_valid_proxy_loads(self, roe_mod, tmp_path):
        _write_roe(tmp_path, proxy="socks5h://127.0.0.1:8899")
        r = roe_mod.load(str(tmp_path))
        assert r["proxy"] == "socks5h://127.0.0.1:8899" and not r["_errors"]

    @pytest.mark.parametrize("bad", ["ftp://127.0.0.1:8899", "socks5h://127.0.0.1",
                                     "127.0.0.1:8899", 8899])
    def test_unusable_value_stays_configured_and_flagged(self, roe_mod, tmp_path, bad):
        _write_roe(tmp_path, proxy=bad)
        r = roe_mod.load(str(tmp_path))
        # configured-but-unusable, never read as "no proxy": callers refuse, they never go direct
        assert r["proxy"] and r["_errors"]


# ── resolving the proxy ────────────────────────────────────────────────────────
class TestProxyResolution:
    def test_nothing_configured_is_empty(self, tmp_path):
        assert egress.proxy(str(tmp_path)) == ""

    def test_env_overrides_roe(self, tmp_path, monkeypatch):
        _write_roe(tmp_path, proxy="socks5h://127.0.0.1:8899")
        monkeypatch.setenv("GRIMNIR_PROXY", "http://127.0.0.1:8888")
        assert egress.proxy(str(tmp_path)) == "http://127.0.0.1:8888"

    def test_empty_env_falls_through_to_roe(self, tmp_path, monkeypatch):
        _write_roe(tmp_path, proxy="socks5h://127.0.0.1:8899")
        monkeypatch.setenv("GRIMNIR_PROXY", "")
        assert egress.proxy(str(tmp_path)) == "socks5h://127.0.0.1:8899"

    def test_init_remembers_the_project_dir(self, tmp_path):
        _write_roe(tmp_path, proxy="socks5h://127.0.0.1:8899")
        egress.init(str(tmp_path))
        assert egress.proxy() == "socks5h://127.0.0.1:8899"

    def test_unusable_roe_value_raises(self, tmp_path):
        _write_roe(tmp_path, proxy="ftp://127.0.0.1:1")
        with pytest.raises(egress.EgressError):
            egress.proxy(str(tmp_path))

    def test_unusable_env_value_raises(self, monkeypatch):
        monkeypatch.setenv("GRIMNIR_PROXY", "not-a-proxy")
        with pytest.raises(egress.EgressError):
            egress.proxy()

    def test_whitespace_env_falls_through_to_roe(self, tmp_path, monkeypatch):
        """A whitespace-only env value is not "set": an accidental shell space cannot send a
        proxied program direct — the program's roe.json proxy still applies."""
        _write_roe(tmp_path, proxy="socks5h://127.0.0.1:8899")
        monkeypatch.setenv("GRIMNIR_PROXY", "   ")
        assert egress.proxy(str(tmp_path)) == "socks5h://127.0.0.1:8899"

    def test_whitespace_roe_value_raises(self, tmp_path):
        _write_roe(tmp_path, proxy="   ")
        with pytest.raises(egress.EgressError):
            egress.proxy(str(tmp_path))

    def test_surrounding_whitespace_is_trimmed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("GRIMNIR_PROXY", "  socks5h://127.0.0.1:8899  ")
        assert egress.proxy(str(tmp_path)) == "socks5h://127.0.0.1:8899"


# ── the pure mappings ──────────────────────────────────────────────────────────
class TestMappings:
    def test_curl_args(self):
        assert egress.curl_args("") == []
        assert egress.curl_args("socks5h://127.0.0.1:8899") == ["--proxy", "socks5h://127.0.0.1:8899"]

    @pytest.mark.parametrize("p,want", [
        ("", None),
        ("socks5h://127.0.0.1:8899", {"server": "socks5://127.0.0.1:8899"}),
        ("socks5://127.0.0.1:8899", {"server": "socks5://127.0.0.1:8899"}),
        ("http://127.0.0.1:8080", {"server": "http://127.0.0.1:8080"}),
    ])
    def test_playwright_proxy(self, p, want):
        assert egress.playwright_proxy(p) == want

    def test_opener_keeps_passed_handlers(self):
        class _Flag(urllib.request.HTTPRedirectHandler):
            pass

        op = egress.opener(_Flag)
        assert any(isinstance(h, _Flag) for h in op.handlers)

    def test_opener_refuses_an_unusable_proxy(self):
        with pytest.raises(egress.EgressError):
            egress.opener(proxy="ftp://127.0.0.1:1")

    def test_socks_connect_factory_rejects_a_non_socks_proxy(self):
        with pytest.raises(egress.EgressError):
            egress.socks_connect_factory("http://127.0.0.1:8080")

    def test_refuse_if_proxied_names_the_tool_and_exits_2(self, capsys):
        egress.refuse_if_proxied("some-tool.py", "")          # no proxy: nothing to refuse
        with pytest.raises(SystemExit) as e:
            egress.refuse_if_proxied("some-tool.py", "socks5h://127.0.0.1:8899")
        assert e.value.code == 2
        assert "some-tool.py" in capsys.readouterr().err


# ── routing (loopback only) ────────────────────────────────────────────────────
class TestRouting:
    def test_http_proxy_is_used_and_reaches_the_target(self, params_mod, target, http_proxy, monkeypatch):
        url, hits = target
        proxy_url, seen = http_proxy
        monkeypatch.setenv("GRIMNIR_PROXY", proxy_url)
        r = params_mod.fetch(f"{url}/thing?x=1", [], 5.0)
        assert r["status"] == 200 and r["body"] == "target-ok"
        assert hits == ["/thing?x=1"]
        assert seen == [f"{url}/thing?x=1"]     # the proxy, not the target, was the first hop

    def test_socks_proxy_is_used_and_reaches_the_target(self, params_mod, target, socks_proxy, monkeypatch):
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", socks_proxy.url)
        r = params_mod.fetch(f"{url}/s", [], 5.0)
        assert r["status"] == 200 and r["body"] == "target-ok"
        assert hits == ["/s"]
        assert socks_proxy.targets == [("127.0.0.1", _port_of(url))]

    def test_roe_proxy_applies_without_the_env(self, params_mod, target, socks_proxy, tmp_path):
        url, hits = target
        pd = tmp_path / "eng"
        pd.mkdir()
        _write_roe(pd, proxy=socks_proxy.url)
        egress.init(str(pd))                    # the CLI path: egress.init(project_dir)
        r = params_mod.fetch(f"{url}/roe", [], 5.0)
        assert r["status"] == 200 and hits == ["/roe"]
        assert socks_proxy.targets == [("127.0.0.1", _port_of(url))]


# ── fail closed ────────────────────────────────────────────────────────────────
class TestFailClosed:
    def test_params_fetch_leaves_no_direct_hit(self, params_mod, target, monkeypatch):
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", _closed_proxy())
        r = params_mod.fetch(f"{url}/leak", [], 5.0)
        assert r["status"] == 0 and r["error"]
        assert hits == []

    def test_curl_oracle_leaves_no_direct_hit(self, authz_mod, target, monkeypatch):
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", _closed_proxy())
        r = authz_mod.fetch("GET", f"{url}/leak", [], None)
        assert r["status"] == 0
        assert hits == []

    def test_lane_runner_refuses_an_unusable_proxy_before_firing(self, lane_runner_mod, tmp_path, capsys):
        _write_roe(tmp_path, proxy="ftp://127.0.0.1:1", max_rps_per_host=1000,
                   daily_request_budget=1000, auto_fire_allowed=True)
        (tmp_path / "scope.json").write_text(json.dumps({"in_scope": ["127.0.0.1"]}))
        (tmp_path / "test-lanes.jsonl").write_text(json.dumps({
            "id": "bola-x", "class": "authz", "action_class": "read-only", "method": "GET",
            "url": "http://127.0.0.1:1/users/{id}/card", "headers": ["Authorization: Bearer T"],
            "own_id": "1", "victim_id": "2", "nonexistent_id": "3"}) + "\n")
        rc = lane_runner_mod.cmd_run(argparse.Namespace(
            project_dir=str(tmp_path), lane="bola-x", agent=None, dry_run=False,
            operator_override=False))
        assert rc == lane_runner_mod.EXIT_ROE_REFUSED
        assert "refused-egress" in capsys.readouterr().out


# ── lane-runner hands the proxy to the oracle it spawns ────────────────────────
class TestLaneRunnerEnv:
    def test_child_receives_grimnir_proxy(self, lane_runner_mod):
        rc, out = lane_runner_mod._run(
            [sys.executable, "-c", "import os; print(os.environ.get('GRIMNIR_PROXY', 'unset'))"],
            timeout=30, proxy="socks5h://127.0.0.1:8899")
        assert rc == 0 and "socks5h://127.0.0.1:8899" in out

    def test_child_without_a_proxy_inherits_the_environment(self, lane_runner_mod):
        rc, out = lane_runner_mod._run(
            [sys.executable, "-c", "import os; print(os.environ.get('GRIMNIR_PROXY', 'unset'))"],
            timeout=30)
        assert rc == 0 and "unset" in out

    def test_a_fired_lane_rides_the_socks_proxy(self, lane_runner_mod, target, socks_proxy, tmp_path,
                                                monkeypatch):
        """End to end: roe.json's proxy -> lane-runner's env -> authz-confirm -> curl --proxy -> the
        stub SOCKS5 server -> the target. The stub records the CONNECTs it relayed."""
        url, hits = target
        monkeypatch.setenv("GRIMNIR_HOME", str(tmp_path / "home"))   # keep the test journal local
        _write_roe(tmp_path, proxy=socks_proxy.url, max_rps_per_host=1000, daily_request_budget=1000,
                   auto_fire_allowed=True)
        (tmp_path / "scope.json").write_text(json.dumps({"in_scope": ["127.0.0.1"]}))
        (tmp_path / "test-lanes.jsonl").write_text(json.dumps({
            "id": "bola-x", "class": "authz", "action_class": "read-only", "method": "GET",
            "url": f"{url}/users/{{id}}/card", "headers": ["Authorization: Bearer T"],
            "own_id": "1", "victim_id": "2", "nonexistent_id": "3"}) + "\n")
        rc = lane_runner_mod.cmd_run(argparse.Namespace(
            project_dir=str(tmp_path), lane="bola-x", agent=None, dry_run=False,
            operator_override=False))
        assert rc == 0
        port = _port_of(url)
        assert socks_proxy.targets and all(t == ("127.0.0.1", port) for t in socks_proxy.targets)
        assert hits and all(h.startswith("/users/") for h in hits)


# ── race-confirm: a raw-socket client ──────────────────────────────────────────
class TestRaceConfirm:
    def _run(self, tmp_path, url, proxy):
        return subprocess.run(
            ["python3", str(REPO / "scripts" / "confirm" / "race-confirm.py"),
             "--finding-id", "SPE-001", "--project-dir", str(tmp_path), "--method", "POST",
             "--url", f"{url}/coupon", "--body", '{"code":"X"}', "--count", "3",
             "--expected-max", "1"],
            cwd=str(REPO), capture_output=True, text=True, timeout=120,
            env={**os.environ, "GRIMNIR_PROXY": proxy})

    def test_socks_proxy_routes_the_burst(self, target, socks_proxy, tmp_path):
        url, hits = target
        p = self._run(tmp_path, url, socks_proxy.url)
        assert p.returncode == 0, p.stderr
        port = _port_of(url)
        assert len(socks_proxy.targets) == 3     # 3 arms, all through the proxy
        assert all(t == ("127.0.0.1", port) for t in socks_proxy.targets)
        assert hits.count("/coupon") == 3

    def test_non_socks_proxy_refuses(self, tmp_path):
        p = self._run(tmp_path, "http://127.0.0.1:1", "http://127.0.0.1:9")
        assert p.returncode == 2 and "refusing" in p.stderr.lower()


# ── graphql-probe.py: a urllib client that must ride the egress proxy ───────────
class TestGraphqlProbeEgress:
    """The introspection-off probe POSTs to the target; with a proxy configured every POST must ride
    it (routing) or the probe must refuse (fail closed) — never a direct request."""

    def test_rides_the_socks_proxy(self, graphql_probe_mod, target, socks_proxy, monkeypatch):
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", socks_proxy.url)
        r = graphql_probe_mod.http_post(f"{url}/graphql", [])("{ __typename }")
        assert r["status"] == 200
        assert hits == ["/graphql"]
        assert socks_proxy.targets == [("127.0.0.1", _port_of(url))]

    def test_fails_closed_leaves_no_direct_hit(self, graphql_probe_mod, target, monkeypatch):
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", _closed_proxy())
        r = graphql_probe_mod.http_post(f"{url}/graphql", [])("{ __typename }")
        assert r["status"] == 0 and r.get("err")
        assert hits == []

    def test_main_refuses_an_unusable_proxy(self, graphql_probe_mod, target, monkeypatch, capsys):
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", "not-a-proxy")
        rc = graphql_probe_mod.main([f"{url}/graphql", "--max-requests", "5"])
        assert rc == 4
        assert "refusing" in capsys.readouterr().err.lower()
        assert hits == []      # it refused before issuing the confirm probe


# ── waf fingerprint/arsenal: active probes are target traffic ───────────────────
class TestWafFingerprintEgress:
    def test_active_fetch_rides_the_socks_proxy(self, target, socks_proxy, monkeypatch):
        import importlib
        sys.path.insert(0, str(REPO / "specter" / "scripts"))
        fingerprint = importlib.import_module("waf.fingerprint")
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", socks_proxy.url)
        fingerprint._EGRESS = None                 # re-resolve the lazy egress module under this env
        fingerprint.detect(url, timeout=5.0, active=False)
        assert hits == ["/"]
        assert socks_proxy.targets == [("127.0.0.1", _port_of(url))]

    def test_fails_closed_leaves_no_direct_hit(self, target, monkeypatch):
        import importlib
        sys.path.insert(0, str(REPO / "specter" / "scripts"))
        fingerprint = importlib.import_module("waf.fingerprint")
        url, hits = target
        monkeypatch.setenv("GRIMNIR_PROXY", _closed_proxy())
        fingerprint._EGRESS = None
        res = fingerprint.detect(url, timeout=5.0, active=False)
        assert res["waf"] == "none" and "error" in res["fetch"]
        assert hits == []


# ── metadata-probe.sh: direct = host IMDS (never proxied); ssrf = target traffic ─
class TestMetadataProbeEgress:
    SCRIPT = REPO / "nimbus" / "scripts" / "metadata-probe.sh"

    def test_direct_mode_is_never_proxied(self, socks_proxy):
        """direct mode queries the host's OWN link-local IMDS; a proxy left in the environment must
        not capture it (`--noproxy '*'`). The stub proxy must record nothing."""
        env = {**os.environ, "GRIMNIR_PROXY": socks_proxy.url, "ALL_PROXY": socks_proxy.url,
               "all_proxy": socks_proxy.url, "HTTP_PROXY": socks_proxy.url,
               "http_proxy": socks_proxy.url, "HTTPS_PROXY": socks_proxy.url}
        subprocess.run(["bash", str(self.SCRIPT), "direct"], capture_output=True, text=True,
                       timeout=60, env=env)
        assert socks_proxy.targets == []

    def test_ssrf_mode_rides_the_proxy(self, socks_proxy):
        """ssrf mode sends its request to the target's SSRF sink — that IS target traffic, so it
        rides the program's egress proxy. The stub records the CONNECT it was asked to relay."""
        env = {**os.environ, "GRIMNIR_PROXY": socks_proxy.url}
        subprocess.run(["bash", str(self.SCRIPT), "ssrf", "http://sink.ssrf.test/fetch?url="],
                       capture_output=True, text=True, timeout=60, env=env)
        assert ("sink.ssrf.test", 80) in socks_proxy.targets

    def test_ssrf_mode_refuses_an_unusable_proxy(self):
        env = {**os.environ, "GRIMNIR_PROXY": "not-a-proxy"}
        p = subprocess.run(["bash", str(self.SCRIPT), "ssrf", "http://sink.ssrf.test/fetch?url="],
                           capture_output=True, text=True, timeout=60, env=env)
        assert p.returncode == 4


# ── the wired shell scripts source the egress contract before any target request ─
class TestShellScriptsAreWired:
    """A structural guard: each target-touching shell script must source egress-env.sh and call
    egress_init, so a future edit cannot quietly drop the fail-closed wiring. (The curl/Go tooling
    these drive is not installed in CI, so routing is proven via the Python clients above; this pins
    that the contract is at least invoked.)"""

    WIRED = [
        "specter/scripts/full-audit.sh", "specter/scripts/graphql-enum.sh",
        "specter/scripts/recon-pipeline.sh", "specter/scripts/rest-api-test.sh",
        "specter/scripts/triage-register-probe.sh", "specter/scripts/waf-detect.sh",
        "specter/scripts/api-fuzz.sh", "nimbus/scripts/cloud-recon.sh",
        "nimbus/scripts/iam-enum.sh", "nimbus/scripts/metadata-probe.sh",
    ]

    @pytest.mark.parametrize("rel", WIRED)
    def test_sources_egress_and_inits(self, rel):
        text = (REPO / rel).read_text()
        assert "egress-env.sh" in text, f"{rel} does not source the egress contract"
        assert "egress_init" in text, f"{rel} does not call egress_init"
