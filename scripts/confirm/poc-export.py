#!/usr/bin/env python3
"""
poc-export.py — bundle a confirmed finding's evidence into a reproducible PoC (Grimnir harness).

Reads evidence/<id>/{verdict,authz,render}.json and writes evidence/<id>/poc/{poc.md, repro.sh} —
a self-contained package for the report/submission, and the substrate a future exploit-chainer
consumes (ROADMAP-confirmation-harness.md §8).

  poc-export.py --finding-id FINDING-003 --project-dir ~/workspace/prog
"""
import argparse
import json
import os
from datetime import datetime, timezone


def load(p):
    try:
        return json.load(open(p))
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    a = ap.parse_args()

    ev = os.path.join(a.project_dir, "evidence", a.finding_id)
    if not os.path.isdir(ev):
        print(f"no evidence dir: {ev}")
        return
    out = os.path.join(ev, "poc")
    os.makedirs(out, exist_ok=True)

    parts = []
    repro = ["#!/usr/bin/env bash", "set -euo pipefail", f"# Reproducer for {a.finding_id}", ""]
    # Any *.json carrying a "verdict" key counts, not just the three original primitive
    # names. A finding confirmed by a newer primitive (the TLS OOB listener, say) used to
    # export an empty bundle that still printed "wrote ..." -- the export looked like it
    # succeeded and the operator got a worthless package. Discover by shape, not by name.
    seen = set()
    candidates = []
    for name in ("verdict.json", "authz.json", "render.json"):
        p = os.path.join(ev, name)
        if os.path.isfile(p):
            candidates.append(p)
            seen.add(os.path.abspath(p))
    for entry in sorted(os.listdir(ev)):
        p = os.path.join(ev, entry)
        if not entry.endswith(".json") or os.path.abspath(p) in seen or not os.path.isfile(p):
            continue
        probe = load(p)
        if isinstance(probe, dict) and "verdict" in probe:
            candidates.append(p)

    for path in candidates:
        rec = load(path)
        if not rec:
            continue
        parts.append(f"## {rec.get('vuln_class', '?')} — verdict: **{rec.get('verdict', '?')}**")
        if rec.get("why"):
            parts.append(rec["why"])
        if rec.get("reproducer"):
            parts.append(f"Reproducer: {rec['reproducer']}")
            repro.append(f"# {rec['reproducer']}")
        if rec.get("port_bypass"):
            parts.append("Port/host-allowlist BYPASS proven (callbacks on >1 port via redirect).")
        if rec.get("differential"):
            parts.append("\n4-way differential:")
            for k, v in rec["differential"].items():
                parts.append(f"- `{k}`: HTTP {v['status']}  len={v['len']}  sha={v['sha']}")
        if rec.get("screenshot"):
            parts.append(f"\nScreenshot: `{rec['screenshot']}`")
        if rec.get("peer_ips"):
            parts.append(f"\nCallbacks from: {', '.join(rec['peer_ips'])}"
                         + (f"  (SNI: {', '.join(rec['sni_names'])})" if rec.get("sni_names") else "")
                         + f"  [{rec.get('connections', '?')} connections]")
        # Primitives do not share an evidence-row shape: the HTTP listener emits
        # port/src_ip/path, the TLS listener emits peer/sni/event. Render whichever is
        # present rather than printing a row of None.
        for h in (rec.get("evidence") or [])[:5]:
            if not isinstance(h, dict):
                parts.append(f"- {h}")
            elif h.get("src_ip") or h.get("port"):
                parts.append(f"- OOB hit :{h.get('port')} from {h.get('src_ip')} {h.get('path', '')}".rstrip())
            elif h.get("peer"):
                bits = [h.get("event", "?"), f"from {h['peer']}"]
                if h.get("sni"):
                    bits.append(f"SNI {h['sni']}")
                if h.get("ts"):
                    bits.append(f"at {h['ts']}")
                parts.append("- " + "  ".join(bits))
            else:
                parts.append(f"- {json.dumps(h)[:160]}")
        parts.append("")

    # A bundle with no machine-readable verdict is a DEGRADED bundle, not a finished one.
    # It still gets built -- the operator usually has real artifacts on disk even when no
    # primitive was run -- but it must index those artifacts and say plainly what is
    # missing, and the exit code must let a caller tell the two cases apart.
    degraded = len(parts) == 0
    if degraded:
        listed = []
        for entry in sorted(os.listdir(ev)):
            p = os.path.join(ev, entry)
            if os.path.isfile(p):
                listed.append((entry, os.path.getsize(p)))
        declared = []
        for agent in ("specter", "artemis", "hunter", "nimbus", "nomad", "huginn"):
            fp = os.path.join(a.project_dir, agent, "findings", f"{a.finding_id}.json")
            fj = load(fp)
            if fj:
                for e in (fj.get("evidence") or []):
                    declared.append(e.get("path") or e.get("description") or str(e))
                break

        parts = ["> **DEGRADED BUNDLE.** No confirm primitive has been run for this finding, so "
                 "there is no machine-readable verdict to export. Everything below is raw "
                 "material that happened to be on disk, indexed for convenience. Do not treat "
                 "this as confirmation.", "",
                 "Run one of: `oob-client.py verdict`, `authz-confirm.py`, `render-confirm.py`, "
                 "or `tls-oob-listener.py verdict`.", ""]
        if listed:
            parts += ["## Files present in the evidence directory", ""]
            parts += [f"- `{n}` ({s} bytes)" for n, s in listed] + [""]
        if declared:
            parts += ["## Evidence declared by the finding record", ""]
            parts += [f"- {d}" for d in declared] + [""]
        if not listed and not declared:
            parts += ["_The evidence directory is empty and the finding declares no evidence._", ""]

    md = (f"# PoC bundle — {a.finding_id}\n\n"
          f"Generated {datetime.now(timezone.utc).isoformat()}\n\n" + "\n".join(parts))
    open(os.path.join(out, "poc.md"), "w").write(md)
    open(os.path.join(out, "repro.sh"), "w").write("\n".join(repro) + "\n")
    if degraded:
        print(f"WARNING: no verdict record found for {a.finding_id}; wrote a DEGRADED bundle")
        print(f"wrote {out}/poc.md + repro.sh")
        return 1
    print(f"wrote {out}/poc.md + repro.sh  ({len(candidates)} verdict record(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
