#!/usr/bin/env python3
"""roe.py — a program's rules of engagement, machine-readable, enforced on every live request.

One file per engagement, $PROJECT_DIR/roe.json, holds every limit the program imposes, so a batch
of unattended lanes can never outrun them:

  {
    "max_rps_per_host": 1,              # requests per second, per host, across all processes
    "max_concurrency_per_host": 1,      # informational: lanes fire sequentially today
    "daily_request_budget": 300,        # live requests per UTC day, the whole engagement
    "required_headers": {"User-Agent": "..."},   # merged over request-headers.json
    "auto_fire_allowed": true,          # the opt-in: unattended auto-fire runs ONLY when this is
                                        # explicitly true in a confirmed roe.json. Omitted/false/no
                                        # file = supervised only: nothing fires unattended.
    "automated_scanning_banned": false, # true = unattended lanes of <= 3 requests, 1 per run
    "ai_tools_banned": false,           # enforced only when the caller opts in to honoring it
    "quiet_hours_utc": null,            # "22-06" or [22, 6]: nothing fires in that window
    "proxy": "",                        # "" = direct; socks5h/socks5/http/https routes ALL target
                                        # traffic through it (scripts/egress.py, fail closed)
    "source": ["operator"],
    "policy_checked": "2026-01-31",     # date the operator last checked this file against the policy
    "parked_reason": "",                # required when auto_fire_allowed is false: why, and what
                                        # would flip it; "shelved: ..." marks a retired program
    "policy_sha256": "..."              # hash of the platform policy text at the last check;
                                        # `policy-check` bumps policy_checked while it matches
  }

A missing roe.json is NOT "unlimited": the conservative defaults below apply. The operator confirms
the file once per program (the same as the credentials step); `roe.py init` writes a template.

Unattended auto-fire is deny-by-default. The gate is: a roe.json exists on disk AND its
`auto_fire_allowed` is explicitly true. No file, the key omitted, a bad value, or false all leave a
program supervised-only — a human must run its lanes with --operator-override. So every program the
operator wants to auto-fire needs a confirmed roe.json with `auto_fire_allowed: true`; a program
that is deliberately not auto-firing either has `auto_fire_allowed: false` (with the reason in its
`source`/notes) or simply has no roe.json. An operator-override fire is never gated by this switch.

Enforcement has two halves:
  - check_lane()  before a lane fires (the calling harness): auto-fire switch, quiet hours, scanning ban,
                  and whether the day's budget can absorb the lane's estimated request cost.
  - pace()        before every request a confirm primitive sends (scripts/confirm/_pace.py): sleeps
                  to hold the per-host rate across processes and counts the request against the
                  budget. note_status() records 429/503 throttling for the batch back-off.

State lives in $PROJECT_DIR/.roe-state.json (operator data tier, never tracked).

Usage:
  roe.py show  --project-dir DIR [--json]
  roe.py init  --project-dir DIR [--force]
  roe.py usage --project-dir DIR [--json]
  roe.py audit / policy-check   (when scripts/roe_ops.py is present; see that file)
  roe.py selftest
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

ROE_FILE = "roe.json"
STATE_FILE = ".roe-state.json"
LEGACY_HEADERS_FILE = "request-headers.json"
PROPOSAL_FILE = "roe.proposed.json"

DEFAULTS = {
    "max_rps_per_host": 1.0,
    "max_concurrency_per_host": 1,
    "daily_request_budget": 300,
    "required_headers": {},
    "auto_fire_allowed": False,   # deny-by-default: opt in per program with an explicit true in roe.json
    "automated_scanning_banned": False,
    "ai_tools_banned": False,
    "quiet_hours_utc": None,
    "proxy": "",
    "source": ["defaults"],
}

# Schemes a proxy URL may use: the two SOCKS5 dialects (socks5h resolves DNS at the proxy) and
# the two HTTP ones. scripts/egress.py routes target traffic through the value; lane tooling
# refuses to run when it cannot.
PROXY_SCHEMES = ("socks5h", "socks5", "http", "https")

# Estimated live requests per check, by class (a budget check before firing; pace() counts the
# real number). Rounded up from what each confirm primitive in scripts/confirm/ sends.
CLASS_COST = {"authz": 4, "race": 20, "infoleak": 2, "ssrf": 1, "jwt": 6, "bopla": 6, "ssti": 6,
              "sqli": 12, "xss": 3, "authn": 4, "tier": 6}
DEFAULT_COST = 6
# When a lane-class registry sits beside this file it is the authority (it also resolves class
# aliases); the table above is the same numbers for builds without one.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import lane_classes as _lc
except ImportError:
    _lc = None
SCANNING_BAN_MAX_COST = 3
THROTTLE_STATUSES = (429, 503)


# ── Loading ──────────────────────────────────────────────────────────────────
def _read_json(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _legacy_headers(project_dir: str) -> dict:
    data = _read_json(os.path.join(project_dir, LEGACY_HEADERS_FILE))
    out: dict = {}
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(k, str) and k.strip() and v is not None:
                out[k.strip()] = str(v)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str) and ":" in item:
                k, v = item.split(":", 1)
                out[k.strip()] = v.strip()
    return out


def proxy_error(value: str) -> str:
    """"" when `value` is a usable proxy URL, else why it is not: a scheme we can route
    (PROXY_SCHEMES), a host, and a port. scripts/egress.py refuses on any non-empty error."""
    try:
        p = urlsplit(value)
        if p.scheme not in PROXY_SCHEMES:
            return f"scheme '{p.scheme}' is not one of {'/'.join(PROXY_SCHEMES)}"
        if not p.hostname:
            return "no host"
        if p.port is None:
            return "no port"
    except ValueError as e:
        return f"not a URL ({e})"
    return ""


def load(project_dir: str) -> dict:
    """Effective RoE: defaults, overlaid by roe.json. required_headers = request-headers.json
    overlaid by roe.json's (roe.json wins per header name). `_errors` lists rejected values; a bad
    value keeps the conservative default rather than loosening anything."""
    roe = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v)
           for k, v in DEFAULTS.items()}
    roe["_errors"] = []
    roe["_file"] = None
    data = _read_json(os.path.join(project_dir, ROE_FILE))
    if data is not None and not isinstance(data, dict):
        roe["_errors"].append("roe.json is not a JSON object; defaults apply")
        data = None
    if data is not None:
        roe["_file"] = os.path.join(project_dir, ROE_FILE)
        for key in ("max_rps_per_host", "daily_request_budget", "max_concurrency_per_host"):
            if key in data:
                v = data[key]
                if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
                    roe[key] = v
                else:
                    roe["_errors"].append(f"{key}={v!r} is not a positive number; default kept")
        for key in ("auto_fire_allowed", "automated_scanning_banned", "ai_tools_banned"):
            if key in data:
                if isinstance(data[key], bool):
                    roe[key] = data[key]
                else:
                    roe["_errors"].append(f"{key} must be true/false; default kept")
        if data.get("quiet_hours_utc") is not None:
            if _parse_quiet(data["quiet_hours_utc"]) is None:
                roe["_errors"].append(f"quiet_hours_utc={data['quiet_hours_utc']!r} unparseable; "
                                      "treating every hour as quiet until fixed")
                roe["quiet_hours_utc"] = [0, 24]
            else:
                roe["quiet_hours_utc"] = data["quiet_hours_utc"]
        if data.get("proxy") is not None:
            v = data["proxy"]
            # An unusable value stays configured, so callers refuse (egress.py raises) instead of
            # reading it as "no proxy" and connecting directly.
            roe["proxy"] = v if isinstance(v, str) else str(v)
            err = proxy_error(roe["proxy"]) if roe["proxy"] else ""
            if err:
                roe["_errors"].append(f"proxy={v!r} unusable ({err}); target traffic will refuse to run")
        if isinstance(data.get("source"), list):
            roe["source"] = data["source"]
        for key in ("policy_checked", "parked_reason"):   # bookkeeping, not enforced
            if isinstance(data.get(key), str) and data[key].strip():
                roe[key] = data[key].strip()
    headers = _legacy_headers(project_dir)
    rh = (data or {}).get("required_headers")
    if isinstance(rh, dict):
        headers.update({str(k).strip(): str(v) for k, v in rh.items() if str(k).strip() and v is not None})
    elif rh is not None:
        roe["_errors"].append("required_headers must be an object of name -> value")
    roe["required_headers"] = headers
    return roe


def required_header_lines(project_dir: str) -> list[str]:
    return [f"{k}: {v}" for k, v in load(project_dir)["required_headers"].items()]


# ── Quiet hours ──────────────────────────────────────────────────────────────
def _parse_quiet(spec) -> tuple[int, int] | None:
    """[start, end) in UTC hours. Accepts "22-06", "22:00-06:00", or [22, 6]."""
    try:
        if isinstance(spec, (list, tuple)) and len(spec) == 2:
            a, b = int(spec[0]), int(spec[1])
        elif isinstance(spec, str) and "-" in spec:
            a_s, b_s = spec.split("-", 1)
            a, b = int(a_s.split(":")[0]), int(b_s.split(":")[0])
        else:
            return None
    except (TypeError, ValueError):
        return None
    if not (0 <= a <= 24 and 0 <= b <= 24):
        return None
    return a, b


def in_quiet_hours(roe: dict, now: datetime | None = None) -> bool:
    q = _parse_quiet(roe.get("quiet_hours_utc")) if roe.get("quiet_hours_utc") is not None else None
    if not q:
        return False
    h = (now or datetime.now(timezone.utc)).hour
    a, b = q
    if a == b:
        return False
    return a <= h < b if a < b else (h >= a or h < b)


# ── State: pacing, budget, throttling ────────────────────────────────────────
def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class _State:
    """$PROJECT_DIR/.roe-state.json under an exclusive lock. The day rolls over on first touch."""

    def __init__(self, project_dir: str):
        self.path = os.path.join(project_dir, STATE_FILE)

    def __enter__(self):
        self.fh = open(self.path, "a+")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        self.fh.seek(0)
        try:
            self.data = json.loads(self.fh.read() or "{}")
        except json.JSONDecodeError:
            self.data = {}
        if self.data.get("date") != _today():
            self.data = {"date": _today(), "requests": 0, "throttled": 0, "throttle_streak": 0,
                         "hosts": self.data.get("hosts", {})}
        return self.data

    def __exit__(self, *exc):
        self.fh.seek(0)
        self.fh.truncate()
        self.fh.write(json.dumps(self.data))
        self.fh.flush()
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def usage(project_dir: str) -> dict:
    data = _read_json(os.path.join(project_dir, STATE_FILE)) or {}
    if data.get("date") != _today():
        data = {"date": _today(), "requests": 0, "throttled": 0, "throttle_streak": 0}
    data.pop("hosts", None)
    return data


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def pace(project_dir: str, url: str, roe: dict | None = None, _sleep=time.sleep) -> float:
    """Block until this host's rate allows one more request, then count it. Returns the seconds
    slept. Holding the lock while sleeping is deliberate: it serializes every process firing at
    this engagement, which is what max_concurrency_per_host=1 means."""
    roe = roe or load(project_dir)
    interval = 1.0 / float(roe["max_rps_per_host"])
    host = _host(url)
    slept = 0.0
    with _State(project_dir) as st:
        last = float(st.setdefault("hosts", {}).get(host, 0))
        wait = last + interval - time.time()
        if wait > 0:
            _sleep(wait)
            slept = wait
        st["hosts"][host] = time.time()
        st["requests"] = int(st.get("requests", 0)) + 1
    return slept


def note_status(project_dir: str, url: str, status: int) -> None:
    """Record a response status: 429/503 extends the throttle streak, anything else resets it."""
    with _State(project_dir) as st:
        if int(status or 0) in THROTTLE_STATUSES:
            st["throttled"] = int(st.get("throttled", 0)) + 1
            st["throttle_streak"] = int(st.get("throttle_streak", 0)) + 1
        elif status:
            st["throttle_streak"] = 0


# ── The pre-fire check ───────────────────────────────────────────────────────
def lane_cost(lane: dict) -> int:
    return _lc.lane_cost(lane) if _lc else CLASS_COST.get(lane.get("class"), DEFAULT_COST)


def global_block(project_dir: str, unattended: bool, roe: dict | None = None,
                 now: datetime | None = None) -> str | None:
    """A reason NO lane may fire right now (supervised-only, quiet hours, budget spent), else None."""
    roe = roe or load(project_dir)
    if unattended:
        if not roe.get("_file"):
            return ("roe: no roe.json — unattended auto-fire needs a confirmed roe.json with "
                    "auto_fire_allowed=true (this program is supervised-only until one exists)")
        if not roe["auto_fire_allowed"]:
            return "roe: auto_fire_allowed is not true (supervised-only program)"
    if in_quiet_hours(roe, now):
        return f"roe: inside quiet hours {roe['quiet_hours_utc']} UTC"
    used, budget = usage(project_dir).get("requests", 0), int(roe["daily_request_budget"])
    if used >= budget:
        return f"roe: daily budget spent ({used}/{budget})"
    return None


def check_lane(project_dir: str, lane: dict, unattended: bool, roe: dict | None = None,
               now: datetime | None = None) -> tuple[bool, str]:
    """(allowed, reason). Program rules bind a human too, so quiet hours and the daily budget apply
    to every fire; the auto-fire switch and the scanning ban only restrict unattended fires."""
    roe = roe or load(project_dir)
    block = global_block(project_dir, unattended, roe, now)
    if block:
        return False, block
    cost = lane_cost(lane)
    if unattended and roe["automated_scanning_banned"] and cost > SCANNING_BAN_MAX_COST:
        return False, (f"roe: automated scanning banned and this lane costs ~{cost} requests "
                       f"(> {SCANNING_BAN_MAX_COST})")
    used = usage(project_dir).get("requests", 0)
    budget = int(roe["daily_request_budget"])
    if used + cost > budget:
        return False, f"roe: daily budget {used}/{budget} cannot absorb ~{cost} more requests"
    return True, f"roe ok ({used}/{budget} requests today, lane ~{cost})"


# ── CLI ──────────────────────────────────────────────────────────────────────
def _abs_dir(p: str) -> str | None:
    return p if os.path.isabs(p) and os.path.isdir(p) else None


def cmd_show(a) -> int:
    pd = _abs_dir(a.project_dir)
    if not pd:
        print("roe: --project-dir must be an existing absolute path", file=sys.stderr)
        return 2
    roe = load(pd)
    if a.json:
        print(json.dumps(roe, indent=2))
        return 0
    print(f"RoE for {os.path.basename(pd)}: {roe['_file'] or 'NO roe.json (conservative defaults)'}")
    for k in DEFAULTS:
        v = roe[k]
        if k == "required_headers":
            v = ", ".join(v) or "-"   # names only: a header value can be an identifier
        print(f"  {k:<26} {v}")
    for e in roe["_errors"]:
        print(f"  ! {e}")
    return 1 if roe["_errors"] else 0


def cmd_init(a) -> int:
    pd = _abs_dir(a.project_dir)
    if not pd:
        print("roe: --project-dir must be an existing absolute path", file=sys.stderr)
        return 2
    path = os.path.join(pd, ROE_FILE)
    if os.path.exists(path) and not a.force:
        print(f"refusing to overwrite {path} (use --force)", file=sys.stderr)
        return 1
    body = {k: v for k, v in DEFAULTS.items()}
    body["required_headers"] = _legacy_headers(pd)
    body["source"] = ["operator"]
    # A policy-derived proposal (roe.proposed.json, written by an onboarding step) tightens the template; it never loosens a default.
    prop = _read_json(os.path.join(pd, PROPOSAL_FILE))
    if isinstance(prop, dict):
        rps = prop.get("max_rps_per_host")
        if isinstance(rps, (int, float)) and not isinstance(rps, bool) and 0 < rps < body["max_rps_per_host"]:
            body["max_rps_per_host"] = rps
        for key in ("automated_scanning_banned", "ai_tools_banned"):
            if prop.get(key) is True:
                body[key] = True
        if isinstance(prop.get("required_headers"), dict):
            body["required_headers"] = {**prop["required_headers"], **body["required_headers"]}
        psrc = prop.get("source")
        body["source"] = [psrc[0] if isinstance(psrc, list) and psrc else "policy:proposal", "operator"]
    body["_note"] = ("Fill from the program policy, then confirm. Defaults are conservative; "
                     "loosen only what the policy allows.")
    with open(path, "w") as fh:
        json.dump(body, fh, indent=2)
        fh.write("\n")
    tag = " + policy proposal" if str(body["source"][0]).startswith("policy:") else ""
    print(f"wrote {path} (conservative template{tag}; review against the program policy)")
    return 0


def cmd_usage(a) -> int:
    pd = _abs_dir(a.project_dir)
    if not pd:
        print("roe: --project-dir must be an existing absolute path", file=sys.stderr)
        return 2
    u, roe = usage(pd), load(pd)
    u["budget"] = roe["daily_request_budget"]
    print(json.dumps(u) if a.json else
          f"{u['date']}: {u['requests']}/{u['budget']} requests, {u['throttled']} throttled "
          f"(streak {u['throttle_streak']})")
    return 0



def cmd_selftest(_a) -> int:
    import tempfile
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        fails += 0 if cond else 1

    with tempfile.TemporaryDirectory() as d:
        r = load(d)
        check("missing roe.json is conservative, not unlimited",
              r["max_rps_per_host"] == 1.0 and r["daily_request_budget"] == 300)
        check("no roe.json refuses unattended auto-fire",
              not check_lane(d, {"class": "authz"}, True, r)[0])
        check("operator may still fire with no roe.json",
              check_lane(d, {"class": "authz"}, False, r)[0])
        with open(os.path.join(d, ROE_FILE), "w") as fh:
            json.dump({"max_rps_per_host": "fast", "auto_fire_allowed": False,
                       "daily_request_budget": 5, "proxy": "ftp://127.0.0.1:1"}, fh)
        r = load(d)
        check("bad value keeps the default", r["max_rps_per_host"] == 1.0 and r["_errors"])
        check("unusable proxy stays configured (callers fail closed)",
              r["proxy"] == "ftp://127.0.0.1:1" and any("proxy" in e for e in r["_errors"]))
        check("supervised program refuses unattended",
              not check_lane(d, {"class": "authz"}, True, r)[0])
        check("operator may fire a supervised program", check_lane(d, {"class": "authz"}, False, r)[0])
        slept = []
        pace(d, "https://a.example.com/x", r, _sleep=slept.append)
        pace(d, "https://a.example.com/y", r, _sleep=slept.append)
        check("second request to a host waits ~1s", slept and 0.5 < slept[0] <= 1.0)
        check("requests counted", usage(d)["requests"] == 2)
        check("budget refuses a lane it cannot absorb",
              not check_lane(d, {"class": "authz"}, False, r)[0])
        note_status(d, "https://a.example.com/x", 429)
        check("throttle streak counted", usage(d)["throttle_streak"] == 1)
        check("quiet hours wrap midnight",
              in_quiet_hours({"quiet_hours_utc": "22-06"}, datetime(2026, 1, 1, 3, tzinfo=timezone.utc)))
    print("selftest:", "OK" if not fails else f"{fails} FAILED")
    return 1 if fails else 0


# Optional operator tooling (audit, policy-check), kept in roe_ops.py. When present it is bound to
# this module and its functions are re-exported here, so `roe.audit(...)` keeps working.
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import roe_ops as _OPS
    import types
    _OPS.bind(sys.modules.get(__name__) or types.SimpleNamespace(**globals()))
    for _n in _OPS.EXPORTS:
        globals()[_n] = getattr(_OPS, _n)
except ImportError:
    _OPS = None


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Program rules of engagement (roe.json).")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("show", cmd_show), ("usage", cmd_usage)):
        s = sub.add_parser(name)
        s.add_argument("--project-dir", required=True)
        s.add_argument("--json", action="store_true")
        s.set_defaults(fn=fn)
    s = sub.add_parser("init", help="write a conservative roe.json template")
    s.add_argument("--project-dir", required=True)
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_init)
    if _OPS:
        _OPS.register(sub)
    s = sub.add_parser("selftest")
    s.set_defaults(fn=cmd_selftest)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
