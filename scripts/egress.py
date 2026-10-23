#!/usr/bin/env python3
"""egress.py — one program, one proxy: where an engagement's target traffic leaves the host.

Some programs block our VPS egress, so the engagement routes ALL its target traffic through one
proxy, typically a local SOCKS tunnel (`socks5h://127.0.0.1:8899`) that exits where the program
expects. The proxy is roe.json's `"proxy"`, overridable per process tree with GRIMNIR_PROXY
(the calling harness hands it to every oracle it spawns, so a child never re-reads the file).

The contract is fail closed: when a proxy is configured, each client either routes through it or
refuses. Nothing falls back to a direct connection — a direct request is at best a wasted lane and
at worst an out-of-policy request from an address the program did not authorize.

    egress.init(dir)                 remember the engagement dir, like _pace.init, so a client
                                     with no dir of its own can still ask proxy()
    egress.proxy([dir])              the configured proxy: GRIMNIR_PROXY, else roe.json, else ""
    egress.curl_args(p)              ["--proxy", p] for a curl argv, [] when there is no proxy
    egress.opener(*handlers)         a urllib opener that rides the proxy, keeping the handlers in
    egress.socks_connect_factory(p)  a socket factory for a client that opens its own connections
    egress.playwright_proxy(p)       the dict playwright's chromium.launch(proxy=...) takes
    egress.refuse_if_proxied(tool, p)  for a client that cannot be proxied at all: exit 2

Shell tooling reads it through the CLI (`egress.py env --project-dir DIR`, sourced by
scripts/egress-env.sh): proxy configured -> `export` lines; none -> nothing; unusable -> exit 4.

A configured-but-unusable value raises EgressError from every one of these, `proxy()` included, so
it can never be silently read as "no proxy".
"""
from __future__ import annotations

import http.client
import os
import sys
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import roe as _roe  # noqa: E402 — the proxy grammar is validated with the rest of roe.json

_PROJECT_DIR = None


class EgressError(RuntimeError):
    """A proxy is configured and cannot be honored. The caller must fail, never connect directly."""


def init(project_dir) -> None:
    """Remember the engagement dir so proxy() can read its roe.json — the same idiom as
    _pace.init(project_dir). A the calling harness child does not need this: GRIMNIR_PROXY arrives in the
    environment and wins. A missing dir just means proxy() falls back to the environment."""
    global _PROJECT_DIR
    _PROJECT_DIR = project_dir or None


def _split(value: str) -> urllib.parse.SplitResult:
    err = _roe.proxy_error(value)
    if err:
        raise EgressError(f"proxy {value!r} is unusable ({err}); refusing to route target traffic")
    return urllib.parse.urlsplit(value)


def proxy(project_dir=None) -> str:
    """The engagement's egress proxy: $GRIMNIR_PROXY when set and non-empty, else roe.json's
    `proxy` for the given (or init-remembered) project dir, else "". An unusable configured value
    raises: it is configured-but-unusable, not absent."""
    value = (os.environ.get("GRIMNIR_PROXY") or "").strip()   # a whitespace-only env is "not set"
    if not value:
        pd = project_dir or _PROJECT_DIR
        if pd:
            value = str(_roe.load(pd).get("proxy") or "")
    if not value:
        return ""
    _split(value)               # unusable raises: never a silent fall-through to a direct connection
    return value.strip()        # a leading space parsed fine; the clients get the clean URL


def curl_args(p: str) -> list[str]:
    """The curl argv for the proxy: ["--proxy", p], or nothing when there is no proxy."""
    return ["--proxy", p] if p else []


def _pysocks(p: str):
    try:
        import socks  # PySocks
    except ImportError as e:
        raise EgressError(
            f"proxy {p!r} is SOCKS and PySocks is not installed; refusing to connect directly"
        ) from e
    return socks


def _credentials(parts: urllib.parse.SplitResult) -> tuple:
    user = urllib.parse.unquote(parts.username) if parts.username else None
    password = urllib.parse.unquote(parts.password) if parts.password else None
    return user, password


def _socks_connector(parts: urllib.parse.SplitResult, socks):
    """(address, timeout=None) -> socket: connect through the SOCKS5 proxy. socks5h resolves DNS at
    the proxy (rdns); plain socks5 resolves here and sends the address."""
    user, password = _credentials(parts)
    rdns = parts.scheme == "socks5h"

    def connect(address, timeout=None):
        s = socks.socksocket()
        s.set_proxy(socks.PROXY_TYPE_SOCKS5, parts.hostname, parts.port, rdns=rdns,
                    username=user, password=password)
        s.settimeout(timeout)
        s.connect(address)
        return s

    return connect


def socks_connect_factory(proxy: str):
    """A socket factory for a client that opens its own connections (a raw-socket burst, a
    hand-rolled client): the TCP stream rides the socks proxy instead of going direct. Raises
    EgressError for a non-SOCKS proxy or a missing PySocks, so the client refuses."""
    parts = _split(proxy)
    if parts.scheme not in ("socks5", "socks5h"):
        raise EgressError(f"proxy {proxy!r} is not a SOCKS proxy, so this raw-socket client "
                          f"cannot ride it")
    return _socks_connector(parts, _pysocks(proxy))


def opener(*handlers, proxy=None) -> urllib.request.OpenerDirector:
    """A urllib opener that routes through `proxy`, keeping every handler passed in (params.py
    passes its no-redirect handler). An http/https proxy uses urllib's ProxyHandler; a SOCKS proxy
    uses PySocks — sockshandler's SocksiPyHandler when installed, else a small HTTP/HTTPS handler
    pair on socks.socksocket. A missing PySocks while a SOCKS proxy is configured raises rather
    than building an opener that would go direct."""
    if not proxy:
        return urllib.request.build_opener(*handlers)
    parts = _split(proxy)
    if parts.scheme in ("http", "https"):
        proxies = {"http": proxy, "https": proxy}
        return urllib.request.build_opener(urllib.request.ProxyHandler(proxies), *handlers)
    socks = _pysocks(proxy)
    try:
        from sockshandler import SocksiPyHandler
    except ImportError:
        socks_handlers = _socks_handlers(parts, socks)
    else:
        user, password = _credentials(parts)
        socks_handlers = (SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, parts.hostname, parts.port,
                                          rdns=parts.scheme == "socks5h", username=user,
                                          password=password),)
    # An empty ProxyHandler suppresses the environment's http_proxy/https_proxy: the program's
    # proxy is the only way out.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), *socks_handlers, *handlers)


def _socks_handlers(parts: urllib.parse.SplitResult, socks) -> tuple:
    """The no-sockshandler path: an HTTP and an HTTPS handler whose connections ride the proxy.
    sockshandler ships with PySocks, so this is only for an install that dropped it."""
    connect = _socks_connector(parts, socks)

    class _Connection(http.client.HTTPConnection):
        def connect(self):
            self.sock = connect((self.host, self.port), self.timeout)

    class _TLSConnection(http.client.HTTPSConnection):
        def connect(self):
            self.sock = connect((self.host, self.port), self.timeout)
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

    class _HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_Connection, req)

    class _HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_TLSConnection, req, context=self._context)

    return (_HTTPHandler(), _HTTPSHandler())


def playwright_proxy(p: str):
    """The `proxy=` dict chromium.launch takes, or None. Chromium resolves DNS through a SOCKS5
    proxy itself, so socks5h maps to the plain socks5 server string."""
    if not p:
        return None
    parts = _split(p)
    if parts.scheme in ("socks5", "socks5h"):
        return {"server": f"socks5://{parts.netloc}"}
    return {"server": p}


def refuse_if_proxied(tool: str, p: str) -> None:
    """For a client that cannot route through a proxy at all: name it, say why, and exit 2 — so a
    configured proxy can never be bypassed by a direct connection."""
    if not p:
        return
    print(f"{tool}: refusing to run — the program's egress proxy is {p!r} and this client cannot "
          f"route through it; a direct connection would bypass the program's egress",
          file=sys.stderr)
    sys.exit(2)


# ── CLI: the shell tooling's reader ──────────────────────────────────────────────────────────────
# A shell script evals `egress.py env`. Scheme note: curl takes socks5h:// natively in ALL_PROXY and
# --proxy. The Go tools (httpx, katana, nuclei) read HTTP_PROXY/HTTPS_PROXY (Go's transport also
# accepts socks5:// and socks5h:// there and sends the hostname to the proxy) but ignore ALL_PROXY,
# which is why every name is exported. A tool with its own proxy flag is passed GRIMNIR_PROXY
# explicitly by the script that runs it.
EXIT_UNUSABLE = 4
_PROXY_VARS = ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY")


def env_lines(p: str) -> list[str]:
    """The shell `export` lines for proxy `p` ([] when there is none)."""
    import shlex
    if not p:
        return []
    q = shlex.quote(p)
    no_proxy = shlex.quote("localhost,127.0.0.1,::1")
    lines = []
    for name in _PROXY_VARS:
        lines += [f"export {name}={q}", f"export {name.lower()}={q}"]
    lines += [f"export NO_PROXY={no_proxy}", f"export no_proxy={no_proxy}", f"export GRIMNIR_PROXY={q}"]
    return lines


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="the program's egress proxy, for shell tooling")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("env", help="print export lines for the configured proxy (nothing if none)")
    e.add_argument("--project-dir", default="", help="engagement dir (roe.json); optional when "
                   "GRIMNIR_PROXY is set")
    args = ap.parse_args(argv)
    try:
        p = proxy(args.project_dir or None)
    except EgressError as err:
        print(f"egress: {err}", file=sys.stderr)
        return EXIT_UNUSABLE
    for line in env_lines(p):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
