#!/usr/bin/env python3
"""
ssrf-confirm.py — the out-of-band collaborator oracle (Grimnir confirmation harness).

Turns a bound SSRF lane into a verdict by driving the full OOB loop as ONE call the lane runner can
invoke: preflight the listener -> mint a nonce + callback URL -> plant it into the target request
(the {oob} placeholder in the url or body) -> fire the request -> poll the listener -> write the
verdict. The oracle is a callback: the target fetched our collaborator, which nothing benign does.

It wraps oob-client.py (mint / poll / verdict against the listener) rather than re-implementing the
channel — one source of OOB truth. The only new step is FIRING the planted request, which used to be
a manual/agent action.

  ssrf-confirm.py --finding-id FINDING-009 --project-dir ~/workspace/prog \
     --method GET --url 'https://t/fetch?target={oob}' [-H 'Authorization: Bearer T'] \
     [--body '{"url":"{oob}"}'] [--poll-timeout 60] [--rung blind]

Verdict (written to evidence/<id>/verdict.json, the same artifact the gate + validate-finding read):
  confirmed     the listener received a callback for our nonce — the target made the request.
  inconclusive  NO callback within the timeout, OR the preflight failed (listener down/unreachable),
                OR mint failed. A no-callback is NOT recorded as `negative`: a down listener and a
                blind SSRF that only calls back on an unwatched channel produce identical silence, so
                a confident negative here would close a live lane (hunting Rule 27). The listener
                must be proven reachable before a silence means anything.

The planted URL always points at OUR listener (single-hop /h/<nonce> or a 2-hop that still returns to
our base), never at internal infra — so firing the probe is low-blast; climbing the response-channel
rung (blind -> partial -> full -> credential) toward internal targets is a separate, human step
(hunting Rule 32). Zero LLM; the decision is the callback.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module)
import egress as _egress  # noqa: E402  the program's egress proxy: the fired request rides it or refuses

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(os.path.dirname(HERE))
OOB_CLIENT = os.path.join(HERE, "oob-client.py")

# Placeholder the lane binds the minted callback URL into (url and/or body), analogous to authz's {id}.
OOB_PLACEHOLDER = "{oob}"


def plant_oob(url: str, body: str | None, oob_url: str) -> tuple[str, str | None]:
    """Substitute the minted callback URL for every {oob} in the url and body. Pure."""
    planted_url = url.replace(OOB_PLACEHOLDER, oob_url)
    planted_body = body.replace(OOB_PLACEHOLDER, oob_url) if body is not None else None
    return planted_url, planted_body


def has_placeholder(url: str, body: str | None) -> bool:
    return OOB_PLACEHOLDER in (url or "") or OOB_PLACEHOLDER in (body or "")


def parse_mint(stdout: str) -> tuple[str | None, str | None]:
    """(nonce, single_hop_url) from `oob-client.py mint` output, or (None, None). The single-hop
    /h/<nonce> URL is the plain probe; the 2-hop redirect URL is left for the operator's rung climb."""
    nonce = re.search(r"nonce:\s*(\S+)", stdout or "")
    url = re.search(r"http single-hop\s*:\s*(\S+)", stdout or "")
    return (nonce.group(1) if nonce else None,
            url.group(1) if url else None)


def _host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]


def _run(argv: list[str], timeout: int, env: dict | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, cwd=REPO_DIR, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, **(env or {})})
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (subprocess.SubprocessError, OSError) as e:
        return 1, str(e)


def _oob(args: list[str], project_dir: str, timeout: int) -> tuple[int, str]:
    return _run(["python3", OOB_CLIENT, *args], timeout, env={"PROJECT_DIR": project_dir})


def _fire(method: str, url: str, headers: list[str], body: str | None) -> int:
    """Fire the planted request; return the HTTP status (0 on transport error). The RESPONSE is not
    the oracle — the callback is — so we only note the status for evidence."""
    cmd = ["curl", "-sS", "-g", "-m", "20", "-o", os.devnull, "-w", "%{http_code}", "-X", method]
    cmd += _egress.curl_args(_egress.proxy())
    for h in headers:
        cmd += ["-H", h]
    if body is not None:
        cmd += ["--data-binary", body]
        if not any(h.lower().startswith("content-type:") for h in headers):
            cmd += ["-H", "Content-Type: application/json"]
    cmd += [url]
    _pace.before(url)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        code = int(re.sub(r"\D", "", out or "0") or 0)
        _pace.after(url, code)
        return code
    except Exception:
        return 0


def _write_verdict(project_dir: str, finding_id: str, verdict: str, why: str, extra: dict | None = None) -> None:
    """Write the minimal verdict.json for the paths oob-client.py's own verdict does not handle
    (preflight-down, mint-fail). Same schema key the runner reads: `verdict`."""
    rec = {"schema": 1, "finding_id": finding_id, "vuln_class": "ssrf",
           "verdict": verdict, "why": why, "channel_rung": "blind",
           "ts": datetime.now(timezone.utc).isoformat()}
    if extra:
        rec.update(extra)
    d = os.path.join(project_dir, "evidence", finding_id)
    os.makedirs(d, exist_ok=True)
    json.dump(rec, open(os.path.join(d, "verdict.json"), "w"), indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(prog="ssrf-confirm.py")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True, help="target URL; {oob} marks where the callback goes")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--body", default=None, help="request body; {oob} substitutes here too")
    ap.add_argument("--poll-timeout", type=int, default=60)
    ap.add_argument("--rung", default="blind", help="response-channel rung (Rule 32); default blind")
    a = ap.parse_args()
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env

    def emit(verdict, why):
        print(json.dumps({"finding_id": a.finding_id, "verdict": verdict, "why": why}, indent=2))

    if not has_placeholder(a.url, a.body):
        _write_verdict(a.project_dir, a.finding_id, "inconclusive",
                       f"lane has no {OOB_PLACEHOLDER} injection point — nothing to plant")
        emit("inconclusive", "no injection placeholder")
        return 0

    # 1. Preflight — a down/unreachable listener makes silence meaningless (Rule 27), so treat it as
    #    inconclusive and STOP before spending the probe.
    rc, out = _oob(["preflight"], a.project_dir, timeout=60)
    if rc != 0:
        _write_verdict(a.project_dir, a.finding_id, "inconclusive",
                       "OOB listener preflight failed (down/unreachable) — cannot conclude; "
                       "a silence here is not a negative (Rule 27)")
        emit("inconclusive", "listener preflight failed")
        return 0

    # 2. Mint a nonce + callback URL.
    rc, out = _oob(["mint", "--label", f"{a.finding_id} {_host_of(a.url)}"], a.project_dir, timeout=60)
    nonce, oob_url = parse_mint(out)
    if not nonce or not oob_url:
        _write_verdict(a.project_dir, a.finding_id, "inconclusive",
                       "could not mint an OOB nonce/callback URL (is GRIMNIR_OOB_BASE configured?)")
        emit("inconclusive", "mint failed")
        return 0

    # 3-4. Plant the callback URL and FIRE the request.
    planted_url, planted_body = plant_oob(a.url, a.body, oob_url)
    status = _fire(a.method.upper(), planted_url, a.headers, planted_body)

    # 5. Poll the listener for our nonce.
    _oob(["poll", nonce, str(a.poll_timeout)], a.project_dir, timeout=a.poll_timeout + 30)

    # 6. Verdict — delegate to oob-client (rich rung / port-bypass / channel record). It writes
    #    evidence/<id>/verdict.json: confirmed if the journal has a hit for the nonce, else
    #    inconclusive (never a bare negative).
    rc, vout = _oob(["verdict", nonce, a.finding_id, "ssrf", a.rung], a.project_dir, timeout=60)
    verdict = ""
    m = re.search(r'"verdict":\s*"(\w+)"', vout)
    if m:
        verdict = m.group(1)
    if not verdict:
        # oob-client verdict did not produce a readable record — record our own honest inconclusive.
        _write_verdict(a.project_dir, a.finding_id, "inconclusive",
                       f"fired (status {status}) but the verdict record was unreadable", {"fired_status": status})
        verdict = "inconclusive"
    emit(verdict, f"fired status {status}; nonce {nonce}; rung {a.rung}")
    return 0


if __name__ == "__main__":
    main()
