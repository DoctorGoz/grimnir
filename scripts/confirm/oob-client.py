#!/usr/bin/env python3
"""
oob-client.py — mint OOB nonces + read back the verdict (Grimnir confirmation harness).

Pairs with oob-listener.py (HTTP), tls-oob-listener.py (https) and dns-rebind.py (DNS).
All three append to the same journal, so one nonce correlates across every channel.
Mechanism/policy split: emits a machine-readable verdict the gate (validate-finding.sh)
consumes -- the SAME contract a future autonomous validator uses.

  oob-client.py preflight [--external]          prove the listener is reachable BEFORE spending
  oob-client.py mint [--count N] [--label TEXT] fresh nonce(s) + callback URLs
  oob-client.py plants [nonce]                  what each nonce was planted in
  oob-client.py poll <nonce> [timeout_s] [--all]  wait for callbacks; print hits
  oob-client.py verdict <nonce> <finding_id> <vuln_class> [rung]
                                                write evidence/<id>/verdict.json

The rung is the response-channel rung (hunting Rule 32): blind|partial|full|credential|
execution. Omitted = blind, which caps the finding at medium in the evidence gate.

Env: GRIMNIR_OOB_BASE (public http base, e.g. http://203.0.113.10) -- REQUIRED to mint,
     GRIMNIR_OOB_DNS_DOMAIN (delegated zone for the DNS channel, optional),
     GRIMNIR_OOB_PORTS, GRIMNIR_OOB_LOG, GRIMNIR_OOB_PLANTS,
     PROJECT_DIR (where evidence/<id>/ is written).
"""
import argparse
import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _rung  # noqa: E402  (sibling module; see its docstring)

#: The listener's systemd unit already reads this file, but an interactive shell does not, so
#: the operator had to re-export the same values by hand every session -- and forgetting meant
#: `mint` refused (or, before that, minted an unreachable URL). Deriving the config from the one
#: place it already lives beats asking for it again.
CONFIG = os.path.expanduser(os.environ.get("GRIMNIR_OOB_CONFIG", "~/.grimnir/oob/config.env"))


def _from_config(key, default=""):
    """Env wins; fall back to the listener's own config.env; then the default."""
    v = os.environ.get(key)
    if v:
        return v
    try:
        with open(CONFIG) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, val = line.partition("=")
                if k.strip() == key:
                    return val.strip().strip('"').strip("'")
    except OSError:
        pass
    return default


LOG = os.path.expanduser(_from_config("GRIMNIR_OOB_LOG", "~/.grimnir/oob/hits.jsonl"))
PLANTS = os.path.expanduser(_from_config("GRIMNIR_OOB_PLANTS", "~/.grimnir/oob/plants.jsonl"))
BASE = _from_config("GRIMNIR_OOB_BASE", "")
DNS_DOMAIN = _from_config("GRIMNIR_OOB_DNS_DOMAIN", "").strip().strip(".")
PORTS = [p.strip() for p in _from_config("GRIMNIR_OOB_PORTS", "18080,18081").split(",") if p.strip()]

#: Values that are documentation, not a listener. Planting one of these produces no callback
#: and the lane then reads as a clean negative -- a confounded negative that closes a live
#: lane on a misconfiguration (hunting Rule 27). Refusing to mint is cheaper than the retest.
PLACEHOLDERS = ("", "http://PUBLIC-IP", "https://PUBLIC-IP", "http://<public-ip>",
                "http://your-ip", "http://example.com", "http://localhost")


def _resolved_base():
    b = BASE.rstrip("/")
    if b.lower() in [p.lower() for p in PLACEHOLDERS] or "public-ip" in b.lower():
        sys.stderr.write(
            "error: GRIMNIR_OOB_BASE is unset or still the placeholder (%r).\n"
            "       Minting anyway hands you a callback URL nothing can reach, and the silent\n"
            "       run that follows reads as 'no SSRF' rather than 'no listener'.\n"
            "       Set it in %s (the listener's own config, read automatically), or export\n"
            "       GRIMNIR_OOB_BASE=http://<your-public-ip>. Then run `preflight`.\n"
            % (BASE or None, CONFIG))
        sys.exit(2)
    return b


def hits_for(nonce):
    out = []
    if os.path.exists(LOG):
        for line in open(LOG, errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("nonce") == nonce:
                out.append(r)
    return out


def _plant(rec):
    try:
        os.makedirs(os.path.dirname(PLANTS), exist_ok=True)
        with open(PLANTS, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError as exc:
        sys.stderr.write(f"warning: could not record the plant ({exc}); keep the map by hand\n")


def label_for(nonce):
    if not os.path.exists(PLANTS):
        return ""
    hit = ""
    for line in open(PLANTS, errors="ignore"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("nonce") == nonce:
            hit = r.get("label", "")
    return hit


def cmd_mint(a):
    base = _resolved_base()
    p_allowed = PORTS[0]
    p_alt = PORTS[1] if len(PORTS) > 1 else PORTS[0]
    for i in range(max(1, a.count)):
        nonce = "gn" + secrets.token_hex(8)
        label = a.label or ""
        if a.count > 1 and label:
            label = f"{label} #{i + 1}"
        _plant({"schema": 1, "nonce": nonce, "label": label,
                "ts": datetime.now(timezone.utc).isoformat(),
                "base": base, "project": os.environ.get("PROJECT_DIR", "")})
        print(f"nonce: {nonce}" + (f"   label: {label}" if label else ""))
        print(f"  http single-hop  : {base}:{p_allowed}/h/{nonce}")
        print(f"  http 2-hop bypass: {base}:{p_allowed}/r/{nonce}?to={base}:{p_alt}/h/{nonce}")
        if DNS_DOMAIN:
            print(f"  dns-only channel : http://{nonce}.{DNS_DOMAIN}/")
    if a.count == 1:
        print(f"  hop1 on :{p_allowed} 302-redirects to hop2 on :{p_alt}; a hit on :{p_alt} proves")
        print(f"  redirect-follow AND that the port/host allowlist was bypassed.")
    if not DNS_DOMAIN:
        print("  (no GRIMNIR_OOB_DNS_DOMAIN set: no DNS channel, so a target that resolves but")
        print("   cannot connect out will look identical to no SSRF at all. See dns-rebind.py.)")
    print(f"poll: oob-client.py poll <nonce> 120")


def cmd_plants(a):
    if not os.path.exists(PLANTS):
        print(f"no plants recorded ({PLANTS})")
        return
    rows = []
    for line in open(PLANTS, errors="ignore"):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if a.nonce and r.get("nonce") != a.nonce:
            continue
        rows.append(r)
    for r in rows:
        n = r.get("nonce", "")
        fired = len(hits_for(n))
        print(f"  {n}  {'FIRED x%-3d' % fired if fired else 'quiet     '} "
              f"{r.get('ts', '')[:19]}  {r.get('label', '') or '-'}")
    if not rows:
        print("  (none matched)")


def _show(r):
    ch = r.get("channel", "http")
    trace = (r.get("headers") or {}).get("traceparent") or \
            (r.get("headers") or {}).get("x-request-id") or "-"
    print(f"  HIT [{ch}] :{r.get('port', '?')} {r.get('method', '?')} {r.get('path', '')} "
          f"from {r.get('src_ip', '?')} trace={trace}")


def cmd_poll(a):
    nonce, timeout = a.nonce, int(a.timeout)
    label = label_for(nonce)
    if label:
        print(f"  ({nonce} was planted in: {label})")
    deadline = time.time() + timeout
    seen = 0
    while time.time() < deadline:
        h = hits_for(nonce)
        if len(h) > seen:
            for r in h[seen:]:
                _show(r)
            seen = len(h)
            # Return as soon as the question is answered. Burning the full timeout after a
            # confirmed hit is pure wall-clock in a dispatched run; --all keeps waiting for
            # the second-order case, where more sinks may still fire.
            if not a.all:
                return hits_for(nonce)
        time.sleep(2)
    if not seen:
        print(f"  no callbacks for {nonce} within {timeout}s (blind-negative or not reached)")
        print(f"  before recording a negative, run `oob-client.py preflight` -- an unreachable")
        print(f"  listener produces exactly this output (hunting Rule 27).")
    return hits_for(nonce)


def cmd_verdict(a):
    """Write the evidence artifact validate-finding.sh --from-evidence reads.

    The rung records WHAT CAME BACK, not merely that the request fired (hunting Rule 32).
    A callback alone is the `blind` rung, which is the floor of the class, so the evidence
    gate caps a rung-less ssrf/imds finding at medium.
    """
    try:
        rung = _rung.normalize(a.rung)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        sys.exit(2)
    h = hits_for(a.nonce)
    ports = {r.get("port") for r in h}
    channels = {r.get("channel", "http") for r in h}
    dns_only = bool(h) and channels == {"dns"}
    rec = {
        "schema": 1,
        "finding_id": a.finding_id,
        "vuln_class": a.vuln_class,
        # Default to the floor on purpose: an unrecorded channel must not unlock a high
        # severity, and a callback by itself only ever proves the blind rung.
        "channel_rung": rung or "blind",
        "verdict": "confirmed" if h else "inconclusive",
        "port_bypass": len(ports) > 1,   # hits on >1 port via the redirect => filter/port bypass
        "channels": sorted(channels),
        "dns_only": dns_only,
        "planted_in": label_for(a.nonce),
        "nonce": a.nonce,
        "ts": datetime.now(timezone.utc).isoformat(),
        "evidence": h,
        "reproducer": f"cause the target to fetch {BASE}:{PORTS[0]}/h/{a.nonce} "
                      f"(see `oob-client.py mint`)",
    }
    if dns_only:
        rec["note"] = ("DNS resolution only, no connection: the name was looked up but nothing "
                       "reached the listener. That proves the fetch was ATTEMPTED and is worth "
                       "recording, but on its own it is the blind rung and it can also come "
                       "from a resolver cache or a link-preview safety check.")
        if rung and rung != "blind":
            sys.stderr.write(
                f"warning: rung '{rung}' recorded but every hit for {a.nonce} is DNS-only. If the\n"
                f"         response actually came back it did so through a channel this journal\n"
                f"         never saw -- make sure the finding shows that evidence.\n")
    pdir = os.environ.get("PROJECT_DIR")
    if pdir:
        d = os.path.join(pdir, "evidence", a.finding_id)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "verdict.json")
        json.dump(rec, open(path, "w"), indent=2)
        print(f"wrote {path}")
    summary = {k: rec[k] for k in ("finding_id", "vuln_class", "verdict", "channel_rung",
                                   "port_bypass", "channels", "nonce")}
    print(json.dumps(summary, indent=2))
    return rec


def cmd_preflight(a):
    """Prove the loop works before a lane spends anything on it.

    The failure this catches is the expensive one: a listener that is down, firewalled, or
    addressed by a placeholder yields silence, and silence is indistinguishable from a target
    with no SSRF. That negative then closes the lane (hunting Rule 27).
    """
    ok = True
    print(f"vantage      : {socket.gethostname()}   "
          f"(hunting Rule 30: a result seen from inside the target's network is not a result)")
    base = _resolved_base()
    print(f"base         : {base}")
    print(f"journal      : {LOG}")
    print(f"dns channel  : {DNS_DOMAIN or '(none -- resolve-but-no-egress will look like a negative)'}")

    host = base.split("://", 1)[-1].split("/")[0].split(":")[0]
    for p in PORTS:
        try:
            with socket.create_connection((host, int(p)), timeout=5):
                print(f"  port {p:<6}: open from this vantage")
        except OSError as exc:
            ok = False
            print(f"  port {p:<6}: UNREACHABLE ({exc}) -- the listener is down or firewalled")

    if ok:
        nonce = "gn" + secrets.token_hex(8)
        url = f"{base}:{PORTS[0]}/h/{nonce}"
        try:
            urllib.request.urlopen(url, timeout=8).read()
        except (urllib.error.URLError, OSError) as exc:
            ok = False
            print(f"  loop        : FAILED to fetch {url} ({exc})")
        else:
            time.sleep(1)
            if hits_for(nonce):
                print(f"  loop        : end to end OK (callback journaled as {nonce})")
            else:
                ok = False
                print(f"  loop        : the request succeeded but NOTHING was journaled to {LOG}.")
                print(f"                The listener is answering from a different journal path.")

    # A local loop proves the listener runs and journals. It does NOT prove the internet can
    # reach it, because the request never left the host -- and an inbound firewall rule is
    # exactly what turns a live lane into a silent negative. Bouncing off a third-party
    # server-side fetcher is the cheap external proof: the hit arrives from THEIR address.
    # Opt-in, because it discloses the listener URL to that third party.
    if ok and a.external:
        nonce = "gn" + secrets.token_hex(8)
        target = f"{base}:{PORTS[0]}/h/{nonce}"
        probe = "https://r.jina.ai/" + target
        print(f"  external    : asking a third-party fetcher to call {target}")
        try:
            req = urllib.request.Request(probe, headers={"User-Agent": "curl/8"})
            urllib.request.urlopen(req, timeout=25).read()
        except (urllib.error.URLError, OSError) as exc:
            print(f"                the fetcher itself failed ({exc}); inconclusive, not a negative")
        time.sleep(2)
        ext = [h for h in hits_for(nonce)
               if (h.get("src_ip") or "").split(".")[0] not in ("127", "10", "192", "172")]
        if ext:
            print(f"                REACHABLE from the internet (hit from {ext[0].get('src_ip')})")
        else:
            ok = False
            print(f"                NO external hit. The listener is up locally but the internet")
            print(f"                cannot reach it. Every probe will look like a clean negative.")
    elif ok:
        print("  external    : not checked (pass --external). The loop above proves the listener")
        print("                runs and journals, NOT that a target can reach it.")

    print("READY" if ok else "NOT READY -- fix the above before recording any OOB negative")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    m = sub.add_parser("mint", help="fresh nonce(s) + callback URLs")
    m.add_argument("--count", type=int, default=1,
                   help="mint N nonces at once. The second-order lane needs a DISTINCT nonce "
                        "per candidate field or a late callback cannot name its sink.")
    m.add_argument("--label", default="",
                   help="what this nonce is being planted in (field, endpoint, feature). "
                        "Recorded so `plants` and `verdict` can name the sink hours later.")

    pl = sub.add_parser("plants", help="what each nonce was planted in, and whether it fired")
    pl.add_argument("nonce", nargs="?", default="")

    po = sub.add_parser("poll", help="wait for callbacks")
    po.add_argument("nonce")
    po.add_argument("timeout", nargs="?", default=120)
    po.add_argument("--all", action="store_true",
                    help="keep waiting the full timeout after the first hit (second-order)")

    v = sub.add_parser("verdict", help="write evidence/<id>/verdict.json")
    v.add_argument("nonce")
    v.add_argument("finding_id")
    v.add_argument("vuln_class")
    # Validated by _rung.normalize rather than argparse `choices`: the shared helper gives
    # the one error message every primitive gives, and keeps `None` out of the help text.
    v.add_argument("rung", nargs="?", default=None, metavar="RUNG", help=_rung.HELP)

    pf = sub.add_parser("preflight", help="prove the listener is reachable before spending a lane")
    pf.add_argument("--external", action="store_true",
                    help="additionally prove INTERNET reachability by bouncing a callback off a "
                         "third-party server-side fetcher. Discloses the listener URL to it.")

    a = ap.parse_args()
    if a.cmd == "mint":
        cmd_mint(a)
    elif a.cmd == "plants":
        cmd_plants(a)
    elif a.cmd == "poll":
        cmd_poll(a)
    elif a.cmd == "verdict":
        cmd_verdict(a)
    elif a.cmd == "preflight":
        sys.exit(cmd_preflight(a))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
