#!/usr/bin/env python3
"""
mcp-poison-scan.py — scored MCP tool-poisoning analyzer + rug-pull monitor (MCP03).

Deepens mcp-enum.sh's boolean poisoning flags into a weighted risk score, decodes
invisible characters to their codepoints, detects cross-server tool shadowing, and
diffs two enumerations to catch rug pulls (a tool definition mutating after approval).

Consumes the mcp-assets.json emitted by mcp-enum.sh.

  # score one or more servers (multiple => also cross-server shadowing check)
  mcp-poison-scan.py scan <mcp-assets.json> [<other-assets.json> ...] \
      [--project-dir DIR] [--out DIR]

  # rug-pull: diff a fresh enum against an earlier baseline
  mcp-poison-scan.py diff --baseline <old-assets.json> --current <new-assets.json> \
      [--project-dir DIR] [--out DIR]

Reality note (see references/owasp-mcp-top10.md): on a first-party target, a poisoned
description is usually vendor-by-design and NOT submittable. It only pays when an
attacker can INTRODUCE or ALTER a description another party's agent consumes, or when
a rug pull changes a tool after the user approved it. The score prioritizes review; the
operator still has to show the consumption path.
"""
import argparse
import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone

# family -> (weight, compiled regex). Weights are additive, capped at 100.
FAMILIES = [
    ("instruction-override", 30, re.compile(r'ignore (the |all )?(previous|prior|above|earlier)|disregard (the )?(system|prior|previous)|supers ?ede', re.I)),
    ("concealment",          30, re.compile(r'do not (tell|mention|inform|reveal|disclose|notify|summarize)|without (telling|informing) the user|(?<!do not )silently', re.I)),
    ("exfil-directive",      35, re.compile(r'exfiltrat|send (it|them|this|the results?|a copy) to|forward (it|this|the) to|POST .* to https?://', re.I)),
    ("tool-shadowing",       25, re.compile(r'before (using|calling|invoking) (any )?other tool|whenever the user|instead first|when another tool', re.I)),
    ("secret-solicitation",  25, re.compile(r'(provide|read|include|pass) (the )?(user\'?s )?(api[_-]?key|password|secret|token|credential|session)|\.aws/credentials|id_rsa|\.env', re.I)),
    ("role-injection",       20, re.compile(r'^\s*(system|assistant)\s*:|<\s*system\s*>|developer mode', re.I | re.M)),
    ("hidden-tag",           20, re.compile(r'<\s*/?\s*(important|secret|system|instruction|instructions|hidden)\s*>|\[\[\s*hidden', re.I)),
    ("imperative",            8, re.compile(r'\byou (must|should|shall|need to|have to)\b', re.I)),
]
INVISIBLE = re.compile(r'[​-‏‪-‮⁠-⁤﻿]|[\U000E0000-\U000E007F]')


def blob(t):
    parts = [t.get("name", "") or "", t.get("description", "") or ""]
    schema = t.get("input_schema") or t.get("inputSchema") or {}
    # include property descriptions (poisoning hides in schema too)
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    for _, spec in (props or {}).items():
        if isinstance(spec, dict) and spec.get("description"):
            parts.append(spec["description"])
    try:
        parts.append(json.dumps(schema))
    except Exception:
        pass
    return "\n".join(parts)


def invisible_report(text):
    out = []
    for i, ch in enumerate(text):
        if INVISIBLE.match(ch):
            try:
                nm = unicodedata.name(ch)
            except ValueError:
                nm = "?"
            out.append({"offset": i, "codepoint": f"U+{ord(ch):04X}", "name": nm})
    return out


def score_tool(t):
    text = blob(t)
    hits, score = [], 0
    for label, weight, rx in FAMILIES:
        if rx.search(text):
            hits.append({"family": label, "weight": weight})
            score += weight
    inv = invisible_report(text)
    if inv:
        hits.append({"family": "invisible-unicode", "weight": 40, "detail": inv})
        score += 40
    score = min(100, score)
    band = "critical" if score >= 60 else "high" if score >= 35 else "medium" if score >= 15 else "clean"
    return {"tool": t.get("name", "?"), "score": score, "band": band, "hits": hits}


def load_tools(path):
    data = json.load(open(path))
    return data.get("tools", []) or [], data.get("server_info", {}) or {}, data.get("target", path)


def shadow_check(servers):
    """Cross-server tool shadowing: does one server's text name another server's tool?"""
    findings = []
    names = {}
    for s in servers:
        for t in s["tools"]:
            names.setdefault(t.get("name", ""), []).append(s["target"])
    for s in servers:
        others = [t.get("name", "") for other in servers if other is not s for t in other["tools"]]
        others = [n for n in others if n and len(n) >= 4]
        for t in s["tools"]:
            text = blob(t)
            for on in set(others) - {t.get("name", "")}:  # a same-named tool is a duplicate, not a reference
                if re.search(r'\b' + re.escape(on) + r'\b', text):
                    findings.append({"server": s["target"], "tool": t.get("name"),
                                     "references_foreign_tool": on})
    dupes = {n: v for n, v in names.items() if len(set(v)) > 1}
    return findings, dupes


def cmd_scan(a):
    servers = []
    for p in a.assets:
        tools, info, target = load_tools(p)
        servers.append({"path": p, "tools": tools, "info": info, "target": target})
    scored = []
    for s in servers:
        for t in s["tools"]:
            r = score_tool(t)
            r["server"] = s["target"]
            scored.append(r)
    scored.sort(key=lambda x: -x["score"])
    shadow, dupes = shadow_check(servers) if len(servers) > 1 else ([], {})

    out = ensure_out(a)
    rec = {"schema": 1, "ts": datetime.now(timezone.utc).isoformat(),
           "servers": [s["target"] for s in servers], "scored": scored,
           "cross_server_shadowing": shadow, "duplicate_tool_names": dupes}
    json.dump(rec, open(os.path.join(out, "poison-scan.json"), "w"), indent=2)

    flagged = [s for s in scored if s["band"] != "clean"]
    L = ["# MCP Tool-Poisoning Scan (MCP03)", "",
         f"**Servers:** {', '.join(rec['servers'])}  ",
         f"**Date:** {rec['ts']}  ",
         f"**Tools scanned:** {len(scored)} | **flagged:** {len(flagged)}", ""]
    if flagged:
        L += ["## Flagged tools (by risk score)", "",
              "| Tool | Server | Score | Band | Families |", "|------|--------|-------|------|----------|"]
        for s in flagged:
            fams = ", ".join(h["family"] for h in s["hits"])
            L.append(f"| {s['tool']} | {s['server']} | {s['score']} | {s['band']} | {fams} |")
        L.append("")
        for s in flagged:
            inv = [h for h in s["hits"] if h["family"] == "invisible-unicode"]
            if inv:
                L.append(f"- **{s['tool']}** invisible chars: " +
                         ", ".join(f"{d['codepoint']}@{d['offset']}" for d in inv[0].get("detail", [])[:20]))
        L.append("")
    else:
        L += ["_No poisoning families matched (clean, or vendor-by-design)._", ""]
    if shadow:
        L += ["## Cross-server tool shadowing", "",
              "_One server's description references another server's tool by name — a shadowing vector._", ""]
        for f in shadow:
            L.append(f"- `{f['server']}` tool **{f['tool']}** references foreign tool `{f['references_foreign_tool']}`")
        L.append("")
    if dupes:
        L += ["## Duplicate tool names across servers", ""]
        for n, v in dupes.items():
            L.append(f"- `{n}` on {', '.join(sorted(set(v)))}")
        L.append("")
    L += ["## Submittability", "",
          "A flagged description pays ONLY if an attacker can introduce/alter it and another",
          "party's agent consumes it (see rules/never-submit.md). Self-only poisoning is Info/Low.",
          "For a rug pull, re-run with `diff --baseline <old> --current <new>`."]
    open(os.path.join(out, "poison-report.md"), "w").write("\n".join(L) + "\n")
    print(f"scanned {len(scored)} tools; flagged {len(flagged)}; shadowing {len(shadow)}")
    for s in flagged[:10]:
        print(f"  [{s['band']}] {s['tool']} ({s['score']}) {[h['family'] for h in s['hits']]}")
    print(f"report: {os.path.join(out, 'poison-report.md')}")


def cmd_diff(a):
    old_tools, _, old_t = load_tools(a.baseline)
    new_tools, _, new_t = load_tools(a.current)
    oldm = {t.get("name"): t for t in old_tools}
    newm = {t.get("name"): t for t in new_tools}

    def sig(t):
        schema = t.get("input_schema") or t.get("inputSchema") or {}
        return (t.get("description", "") or "", json.dumps(schema, sort_keys=True))

    added = [n for n in newm if n not in oldm]
    removed = [n for n in oldm if n not in newm]
    mutated = []
    for n in set(oldm) & set(newm):
        od, os_ = sig(oldm[n])
        nd, ns_ = sig(newm[n])
        if od != nd or os_ != ns_:
            mutated.append({"tool": n, "desc_changed": od != nd, "schema_changed": os_ != ns_,
                            "old_desc": od[:200], "new_desc": nd[:200]})

    out = ensure_out(a)
    rec = {"schema": 1, "ts": datetime.now(timezone.utc).isoformat(),
           "baseline": old_t, "current": new_t,
           "added_tools": added, "removed_tools": removed, "mutated_tools": mutated}
    json.dump(rec, open(os.path.join(out, "rugpull-diff.json"), "w"), indent=2)

    rug = bool(mutated or added)
    L = ["# MCP Rug-Pull Diff (MCP03)", "",
         f"**Baseline:** {old_t}  ", f"**Current:** {new_t}  ",
         f"**Date:** {rec['ts']}  ",
         f"**Verdict:** {'RUG-PULL / DEFINITION CHANGE DETECTED' if rug else 'stable (no change)'}", ""]
    if mutated:
        L += ["## Mutated tool definitions (rug pull)", ""]
        for m in mutated:
            what = ", ".join([w for w, b in (("description", m["desc_changed"]), ("schema", m["schema_changed"])) if b])
            L.append(f"- **{m['tool']}** — {what} changed")
            if m["desc_changed"]:
                L.append(f"  - old: `{m['old_desc']}`")
                L.append(f"  - new: `{m['new_desc']}`")
        L.append("")
    if added:
        L += ["## Tools added since baseline", ""] + [f"- `{n}`" for n in added] + [""]
    if removed:
        L += ["## Tools removed since baseline", ""] + [f"- `{n}`" for n in removed] + [""]
    if rug:
        L += ["_A definition changing after the user approved the tool is a rug pull. If the change",
              "grants new capability or hides intent, and re-consent is not required, that is the finding._"]
    open(os.path.join(out, "rugpull-report.md"), "w").write("\n".join(L) + "\n")
    print(f"diff: +{len(added)} added, -{len(removed)} removed, ~{len(mutated)} mutated -> "
          f"{'RUG-PULL' if rug else 'stable'}")
    print(f"report: {os.path.join(out, 'rugpull-report.md')}")


def ensure_out(a):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if a.out:
        out = a.out
    elif a.project_dir:
        out = os.path.join(a.project_dir, "artemis", "recon", f"mcp-poison-{ts}")
    else:
        out = f"reports/mcp-poison-{ts}"
    os.makedirs(out, exist_ok=True)
    return out


def main():
    ap = argparse.ArgumentParser(description="MCP tool-poisoning analyzer + rug-pull monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("scan", help="score one or more servers' tool descriptions")
    ps.add_argument("assets", nargs="+", help="mcp-assets.json file(s)")
    ps.add_argument("--project-dir", default="")
    ps.add_argument("--out", default="")
    pd = sub.add_parser("diff", help="rug-pull diff between two enumerations")
    pd.add_argument("--baseline", required=True)
    pd.add_argument("--current", required=True)
    pd.add_argument("--project-dir", default="")
    pd.add_argument("--out", default="")
    a = ap.parse_args()
    if a.cmd == "scan":
        cmd_scan(a)
    elif a.cmd == "diff":
        cmd_diff(a)


if __name__ == "__main__":
    main()
