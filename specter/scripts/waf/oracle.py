#!/usr/bin/env python3
"""
WAF test oracle — measure evasion against REAL ModSecurity/CRS, not a mock.

A mock WAF only blocks what you program it to block, so "bypassing" it is circular. This
stands up the OWASP Core Rule Set (rules we did not write) in front of a trivial backend
via podman, so a variant that gets through is genuine signal.

Topology (podman, rootless):
    client -> [CRS / ModSecurity :PORT] -> [whoami backend]
    a raw attack payload must be BLOCKED (403); a benign request must PASS (200);
    an arsenal variant that reaches the backend (non-403) is a bypass CANDIDATE.

Caveat kept loud: passing the WAF is NOT a finding. The oracle measures request-filter
evasion only; the payload still has to fire at a real origin to matter.

Subcommands:
    up [--port N] [--paranoia N]   start the oracle (idempotent)
    status [--port N]              is it reachable, does it block a raw payload
    measure --payload P ...        fire baseline + arsenal variants, report bypasses
    down                           tear everything down

Requires podman. Not part of the offline selftest (needs a container runtime + network).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from typing import Dict, List, Optional
from urllib import request as _request, parse as _parse
from urllib.error import HTTPError, URLError

try:
    from . import catalog, context as _context
except ImportError:  # pragma: no cover - script invocation
    import catalog, context as _context  # type: ignore

NET = "grimnir-waf"
BACKEND = "grimnir-waf-backend"
CRS = "grimnir-waf-crs"
BACKEND_IMAGE = "docker.io/traefik/whoami:latest"
CRS_IMAGE = "docker.io/owasp/modsecurity-crs:nginx"
DEFAULT_PORT = 18085
BLOCK_STATUSES = {403, 406, 501}


def _podman(*args: str, check: bool = False, quiet: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["podman", *args], capture_output=True, text=True,
                          timeout=120, check=check)


def _fire(url: str) -> int:
    req = _request.Request(url, headers={"User-Agent": "grimnir-waf-oracle/1.0"})
    try:
        with _request.urlopen(req, timeout=10) as r:
            return r.status
    except HTTPError as e:
        return e.code
    except (URLError, OSError, ValueError):
        return 0


def _url(port: int, param: str, value: str) -> str:
    return f"http://127.0.0.1:{port}/?{_parse.urlencode({param: value})}"


def _wait_ready(port: int, tries: int = 25) -> bool:
    for _ in range(tries):
        if _fire(f"http://127.0.0.1:{port}/") == 200:
            return True
        time.sleep(1)
    return False


def up(port: int = DEFAULT_PORT, paranoia: int = 1) -> Dict:
    if not _have_podman():
        return {"ok": False, "error": "podman not found"}
    _podman("network", "create", NET)  # idempotent; ignore 'already exists'
    _podman("rm", "-f", BACKEND)
    _podman("rm", "-f", CRS)
    b = _podman("run", "-d", "--name", BACKEND, "--network", NET, BACKEND_IMAGE)
    if b.returncode != 0:
        return {"ok": False, "error": f"backend start failed: {b.stderr.strip()}"}
    c = _podman(
        "run", "-d", "--name", CRS, "--network", NET,
        "-p", f"127.0.0.1:{port}:8080",
        "-e", f"BACKEND=http://{BACKEND}:80",
        "-e", "MODSEC_RULE_ENGINE=On",
        "-e", f"PARANOIA={paranoia}",
        "-e", "ANOMALY_INBOUND=5",
        "-e", "PORT=8080",
        CRS_IMAGE,
    )
    if c.returncode != 0:
        return {"ok": False, "error": f"crs start failed: {c.stderr.strip()}"}
    if not _wait_ready(port):
        logs = _podman("logs", CRS).stderr[-500:]
        return {"ok": False, "error": "not ready after start", "crs_logs": logs}
    return {"ok": True, "port": port, "paranoia": paranoia,
            "url": f"http://127.0.0.1:{port}/"}


def down() -> Dict:
    if not _have_podman():
        return {"ok": False, "error": "podman not found"}
    _podman("rm", "-f", CRS)
    _podman("rm", "-f", BACKEND)
    _podman("network", "rm", NET)
    return {"ok": True, "torn_down": [CRS, BACKEND, NET]}


def status(port: int = DEFAULT_PORT, param: str = "q") -> Dict:
    reachable = _fire(f"http://127.0.0.1:{port}/") == 200
    raw_block = _fire(_url(port, param, "<script>alert(1)</script>")) if reachable else None
    benign = _fire(_url(port, param, "hello world")) if reachable else None
    return {
        "reachable": reachable,
        "blocks_raw_xss": raw_block in BLOCK_STATUSES if reachable else None,
        "raw_xss_status": raw_block,
        "benign_status": benign,
    }


def measure(payload: str, contexts: Optional[List[str]], waf: Optional[str],
            port: int = DEFAULT_PORT, param: str = "q",
            max_variants: int = 20, max_tier: int = 5) -> Dict:
    if _fire(f"http://127.0.0.1:{port}/") != 200:
        return {"error": f"oracle not reachable on :{port} -- run `oracle.py up` first"}
    baseline_status = _fire(_url(port, param, payload))
    variants = catalog.encode_payload(payload, waf=waf, contexts=contexts,
                                      max_variants=max_variants, max_tier=max_tier,
                                      include_original=False)
    rows: List[Dict] = []
    bypassed = 0
    for v in variants:
        st = _fire(_url(port, param, v.payload))
        passed = st not in BLOCK_STATUSES and st != 0
        if passed:
            bypassed += 1
        rows.append({"technique": v.technique, "tier": v.tier, "status": st,
                     "passed_waf": passed, "payload": v.payload})
    return {
        "payload": payload,
        "waf_target": waf or "unknown",
        "contexts": contexts or ["*"],
        "baseline_status": baseline_status,
        "baseline_blocked": baseline_status in BLOCK_STATUSES,
        "variants_tested": len(rows),
        "variants_passed_waf": bypassed,
        "bypass_rate": round(bypassed / len(rows), 3) if rows else 0.0,
        "results": rows,
        "note": "passed_waf means the request cleared CRS; it is NOT proof the payload "
                "fires at the origin. Confirm the underlying class before reporting.",
    }


def _have_podman() -> bool:
    try:
        return subprocess.run(["podman", "--version"], capture_output=True,
                              timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="waf-oracle", description="Measure WAF evasion vs real ModSecurity/CRS")
    sub = p.add_subparsers(dest="cmd", required=True)
    pu = sub.add_parser("up"); pu.add_argument("--port", type=int, default=DEFAULT_PORT); pu.add_argument("--paranoia", type=int, default=1)
    # down tears down by fixed container names, but accept --port so the same flag can be
    # carried across every subcommand without an "unrecognized arguments" surprise.
    pd = sub.add_parser("down"); pd.add_argument("--port", type=int, default=DEFAULT_PORT)
    ps = sub.add_parser("status"); ps.add_argument("--port", type=int, default=DEFAULT_PORT); ps.add_argument("--param", default="q")
    pm = sub.add_parser("measure")
    pm.add_argument("--payload", required=True)
    pm.add_argument("--context", help="comma-separated reflection contexts")
    pm.add_argument("--waf", help="target WAF id for variant selection")
    pm.add_argument("--port", type=int, default=DEFAULT_PORT)
    pm.add_argument("--param", default="q")
    pm.add_argument("--max-variants", type=int, default=20)
    pm.add_argument("--max-tier", type=int, default=5)
    a = p.parse_args(argv)

    if a.cmd == "up":
        out = up(a.port, a.paranoia)
    elif a.cmd == "down":
        out = down()
    elif a.cmd == "status":
        out = status(a.port, a.param)
    else:
        ctxs = a.context.split(",") if a.context else None
        out = measure(a.payload, ctxs, a.waf, a.port, a.param, a.max_variants, a.max_tier)
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if out.get("ok", True) and "error" not in out else 1


if __name__ == "__main__":
    raise SystemExit(main())
