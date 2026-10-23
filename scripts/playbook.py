#!/usr/bin/env python3
"""
playbook.py — Grimnir attack-playbook matcher.

Playbooks (rules/playbooks/*.yaml) are declarative, reachability-aware attack chains.
This tool answers, at /engage time: given what HUGINN found (asset-map.json + intel.jsonl),
what the operator declared at intake (scope.md + classification.md), and what the operator
can reach (reachability.json), which playbooks are worth dispatching, to whom, and how will
each step be proven? Reading the intake docs means `match` returns a ranked plan pre-Phase-0,
before any asset-map exists.

Subcommands:
  list                              List all bundled playbooks.
  show <id>                         Print one playbook in full.
  validate [<file>|--all]           Validate playbook(s) against schemas/playbook.schema.json.
  match --project-dir DIR [--json]  Rank playbooks against an engagement, REACHABLE-first.
  selftest                          Validate every bundled playbook + run a synthetic match.

Design note: Grimnir never executes. A playbook names specialists to delegate to; it does not
fire tooling. Adapted from Kittysploit's playbook engine, re-cast for a delegating orchestrator.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("playbook.py needs PyYAML: pip install pyyaml\n")
    sys.exit(3)

REPO = Path(__file__).resolve().parent.parent
PLAYBOOK_DIR = REPO / "rules" / "playbooks"
SCHEMA_PATH = REPO / "schemas" / "playbook.schema.json"

# Values that mean "gate not held" when reachability.json records a string.
_NEGATIVE = {"", "no", "none", "unset", "n/a", "false"}


# ── loading ──────────────────────────────────────────────────────────────────

def load_playbooks() -> list[dict]:
    books = []
    for path in sorted(PLAYBOOK_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            sys.stderr.write(f"[skip] {path.name}: YAML error: {exc}\n")
            continue
        if not isinstance(data, dict) or "id" not in data:
            continue
        data["_file"] = path.name
        books.append(data)
    return books


def get_playbook(pb_id: str) -> dict | None:
    for pb in load_playbooks():
        if pb.get("id") == pb_id:
            return pb
    return None


# ── target signal extraction ───────────────────────────────────────────────────

# Tokens too generic to keyword-match safely (they fire on incidental English:
# "cloud" hosting, a user "role"). Each still matches via its specific siblings in
# the same playbook (ssrf/imds/access_key/…), so dropping them loses no real signal.
_SIGNAL_STOPLIST = {"cloud", "role"}


def _signal_vocab() -> set[str]:
    """Union of every playbook's `signals_any` tokens (lowercased), minus the stoplist.
    The keyword scan is driven by what the playbooks actually ask for, so a new playbook
    extends the recognised vocabulary for free."""
    vocab: set[str] = set()
    for pb in load_playbooks():
        prereq = pb.get("prerequisites", {}) or {}
        for s in prereq.get("signals_any", []) or []:
            t = str(s).lower().strip()
            if t and t not in _SIGNAL_STOPLIST:
                vocab.add(t)
    return vocab


def _scan_signals(blob: str, vocab: set[str]) -> set[str]:
    """Keyword-scan a lowercased text blob for signal tokens. Compound tokens (with
    '_' or '-') match as substrings; short atomic tokens match on whole words so 'sso'
    does not fire inside 'grosso'. This makes the matcher tolerant of ANY asset-map shape
    HUGINN emits — flat lists or nested-by-product-family — instead of only the one
    structured shape read below."""
    if not blob:
        return set()
    words = set(re.findall(r"[a-z0-9]+", blob))
    found: set[str] = set()
    for t in vocab:
        if ("_" in t or "-" in t):
            if t in blob:
                found.add(t)
        elif t in words:
            found.add(t)
    return found


def collect_target(project_dir: Path) -> dict:
    """Extract signal tokens, tech names, and gate labels from an engagement dir."""
    signals: set[str] = set()
    techs: set[str] = set()

    am = project_dir / "asset-map.json"
    if am.is_file():
        try:
            data = json.loads(am.read_text())
            for tech in data.get("technologies", []):
                if isinstance(tech, dict):
                    if tech.get("name"):
                        techs.add(str(tech["name"]).lower())
                    if tech.get("category"):
                        signals.add(str(tech["category"]).lower())
            for ind in data.get("ai_indicators", []):
                if isinstance(ind, dict) and ind.get("indicator"):
                    signals.add(str(ind["indicator"]).lower())
            waf = data.get("waf")
            if isinstance(waf, dict) and waf.get("name"):
                signals.add("waf")
                techs.add(str(waf["name"]).lower())
            for am_entry in data.get("auth_mechanisms", []):
                if isinstance(am_entry, dict) and am_entry.get("type"):
                    signals.add(str(am_entry["type"]).lower())
            for ep in data.get("endpoints", []):
                if isinstance(ep, dict):
                    for tag in ep.get("tags", []) or []:
                        signals.add(str(tag).lower())
        except (json.JSONDecodeError, OSError) as exc:
            sys.stderr.write(f"[warn] could not read asset-map.json: {exc}\n")

    intel = project_dir / "intel.jsonl"
    if intel.is_file():
        try:
            for line in intel.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("discovery_type"):
                    signals.add(str(entry["discovery_type"]).lower())
                for tag in entry.get("tags", []) or []:
                    signals.add(str(tag).lower())
        except OSError as exc:
            sys.stderr.write(f"[warn] could not read intel.jsonl: {exc}\n")

    # Schema-tolerant fallback (defense in depth over the structured extraction above):
    # keyword-scan the raw asset-map + intel text for signal tokens, so a nested or
    # otherwise non-standard asset-map still yields signals rather than a silent zero-match.
    #
    # Also scan scope.md + classification.md when present. At a fresh /engage (pre-Phase-0)
    # there is no asset-map yet, but the operator already knows from intake that the target
    # is e.g. graphql/oauth/rest — that knowledge lives in scope.md / classification.md.
    # Reading them here lets `match` return a ranked plan on day one instead of a silent
    # zero-match that only fills in after HUGINN runs.
    try:
        parts = []
        if am.is_file():
            parts.append(am.read_text().lower())
        if intel.is_file():
            parts.append(intel.read_text().lower())
        for prose in ("scope.md", "classification.md"):
            pf = project_dir / prose
            if pf.is_file():
                parts.append(pf.read_text().lower())
        signals |= _scan_signals("\n".join(parts), _signal_vocab())
    except OSError as exc:
        sys.stderr.write(f"[warn] signal keyword-scan skipped: {exc}\n")

    gates_held = None
    reach = project_dir / "reachability.json"
    if reach.is_file():
        try:
            gates_held = json.loads(reach.read_text()).get("gates_held")
        except (json.JSONDecodeError, OSError) as exc:
            sys.stderr.write(f"[warn] could not read reachability.json: {exc}\n")

    return {"signals": signals, "techs": techs, "gates_held": gates_held}


# ── matching ───────────────────────────────────────────────────────────────────

def _tech_match(prereq: str, techs: set[str]) -> bool:
    p = prereq.lower()
    return any(p in t or t in p for t in techs)


def match_prereqs(pb: dict, target: dict) -> list[str]:
    """Return the list of matched tokens; empty if the playbook does not apply."""
    matched: list[str] = []
    prereq = pb.get("prerequisites", {}) or {}
    for s in prereq.get("signals_any", []) or []:
        if s.lower() in target["signals"]:
            matched.append(s)
    for t in prereq.get("tech_any", []) or []:
        if _tech_match(t, target["techs"]):
            matched.append(t)
    return matched


def _gate_status(gate: str, gates_held) -> str:
    """held | not_held | unknown for one gate against reachability.gates_held."""
    if not isinstance(gates_held, dict) or gate not in gates_held:
        return "unknown"
    val = gates_held[gate]
    if isinstance(val, bool):
        return "held" if val else "not_held"
    s = str(val).strip().lower()
    if s in _NEGATIVE or s.startswith("no "):
        return "not_held"
    return "held"


def reachability_verdict(pb: dict, gates_held) -> tuple[str, int]:
    """Return (verdict_string, rank) where rank sorts REACHABLE(0) < UNKNOWN(1) < BLOCKED(2)."""
    gates = (pb.get("reachability", {}) or {}).get("gates", []) or []
    if gates_held is None:
        return ("UNKNOWN(no reachability.json)", 1)
    blocked = [g for g in gates if _gate_status(g, gates_held) == "not_held"]
    if blocked:
        return (f"BLOCKED({','.join(blocked)})", 2)
    unknown = [g for g in gates if _gate_status(g, gates_held) == "unknown"]
    if unknown:
        return (f"UNKNOWN({','.join(unknown)})", 1)
    return ("REACHABLE", 0)


def match(project_dir: Path) -> list[dict]:
    target = collect_target(project_dir)
    results = []
    for pb in load_playbooks():
        matched = match_prereqs(pb, target)
        if not matched:
            continue
        verdict, rank = reachability_verdict(pb, target["gates_held"])
        results.append({
            "id": pb["id"],
            "name": pb.get("name", ""),
            "domain": pb.get("domain", ""),
            "lead_agent": pb.get("lead_agent", ""),
            "severity_ceiling": pb.get("severity_ceiling", ""),
            "verdict": verdict,
            "rank": rank,
            "score": len(matched),
            "matched_on": matched,
        })
    results.sort(key=lambda r: (r["rank"], -r["score"], r["id"]))
    return results


# ── commands ───────────────────────────────────────────────────────────────────

def cmd_list(_args) -> int:
    books = load_playbooks()
    if not books:
        print("no playbooks found in rules/playbooks/")
        return 0
    width = max(len(b["id"]) for b in books)
    for pb in sorted(books, key=lambda b: b["id"]):
        print(f"  {pb['id']:<{width}}  [{pb.get('domain',''):>7}/{pb.get('lead_agent','')}]  {pb.get('name','')}")
    print(f"\n{len(books)} playbook(s).")
    return 0


def cmd_show(args) -> int:
    pb = get_playbook(args.id)
    if not pb:
        sys.stderr.write(f"no playbook with id '{args.id}'\n")
        return 1
    pb.pop("_file", None)
    print(yaml.safe_dump(pb, sort_keys=False, default_flow_style=False, width=100).rstrip())
    return 0


PLACEHOLDER_RE = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")

# Mirrors finding.sh's prefix table. Used only to render a plausible id in the plan
# when the operator has not created the finding yet.
AGENT_PREFIX = {"huginn": "HUG", "specter": "SPE", "artemis": "ART",
                "hunter": "HUN", "nimbus": "NIM", "nomad": "NOM"}


def _confirm_command(step: dict, project_dir: Path, finding_id: str) -> list[str]:
    """The runnable form of a chain step's `confirm:` hook.

    `confirm: authz-confirm.py` names the primitive but not how to call it, which
    left the operator to reconstruct the invocation from the primitive's own
    --help every time. --finding-id/--project-dir are always the same two values,
    so plan supplies them; `confirm_args` carries the step-specific rest.
    """
    prim = step.get("confirm")
    if not prim:
        return []
    path = prim if prim.startswith("scripts/") else f"scripts/confirm/{prim}"
    # oob-client is a subcommand CLI, not a flag CLI -- it takes the nonce flow.
    if "oob-client" in prim or "oob-listener" in prim:
        cls = step.get("evidence_class", "ssrf")
        # `confirm_args` on an oob step names the subcommand to run between planting and the
        # verdict, e.g. `poll {NONCE} 900 --all` for a lane whose sinks fire hours apart.
        poll = (step.get("confirm_args") or "").strip()
        lines = [
            "python3 scripts/confirm/oob-client.py mint",
            "#   plant the minted URL in the target, then:",
        ]
        # Wait before reading the verdict. Without a poll line an agent following the plan
        # verbatim ran `verdict` the instant it planted, recorded `inconclusive`, and closed
        # the lane on nothing but its own impatience.
        lines.append("python3 scripts/confirm/oob-client.py "
                     + (poll if poll else "poll {NONCE} 120"))
        # For the classes the rung gate covers, emit the rung argument. Without it the
        # artifact records `blind`, and validate-finding.sh then refuses the very severity
        # this playbook's ceiling advertises -- a plan that cannot satisfy its own gate.
        if cls in ("ssrf", "imds"):
            lines.append(
                "#   {RUNG} = what CAME BACK, not that the request fired (hunting Rule 32):")
            lines.append(
                "#   blind|partial|full|credential|execution -- omitted means blind, which caps at medium")
            lines.append(
                f"PROJECT_DIR={project_dir} python3 scripts/confirm/oob-client.py "
                f"verdict {{NONCE}} {finding_id} {cls} {{RUNG}}")
        else:
            lines.append(
                f"PROJECT_DIR={project_dir} python3 scripts/confirm/oob-client.py "
                f"verdict {{NONCE}} {finding_id} {cls}")
        return lines
    args = (step.get("confirm_args") or "").strip()
    base = f"python3 {path} --finding-id {finding_id} --project-dir {project_dir}"
    return [f"{base} \\\n    {args}" if args else base]


def cmd_plan(args) -> int:
    pb = get_playbook(args.id)
    if not pb:
        sys.stderr.write(f"no playbook with id '{args.id}'\n")
        return 1
    project_dir = Path(args.project_dir)
    if not project_dir.is_absolute():
        sys.stderr.write("--project-dir must be an absolute path\n")
        return 2
    agent = pb.get("lead_agent", "specter")
    fid = args.finding_id or f"{AGENT_PREFIX.get(agent, 'SPE')}-NNN"

    print(f"# {pb['id']} -- {pb.get('name','')}")
    print(f"# lead: {agent}   domain: {pb.get('domain','')}   ceiling: {pb.get('severity_ceiling','?')}")
    gates = (pb.get("reachability") or {}).get("gates") or []
    if gates:
        print(f"# gates: {', '.join(gates)}  <- confirm you hold these before spending here")
    print()

    # A plan that spends on OOB callbacks starts by proving the callbacks can arrive. Silence
    # from an unreachable listener is indistinguishable from a target with no vulnerability,
    # and that negative closes the lane (hunting Rule 27).
    if any("oob-" in (st.get("confirm") or "") for st in pb.get("chain", [])):
        print("## 0. prove the OOB channel before spending anything on it")
        print("python3 scripts/confirm/oob-client.py preflight")
        print()

    placeholders: set[str] = set()
    for n, step in enumerate(pb.get("chain", []), 1):
        opt = "  (optional)" if step.get("optional") else ""
        print(f"## {n}. {step['id']}  [{step['capability']}] -> {step['agent']}{opt}")
        print(f"#  {step['action']}")
        cmds = _confirm_command(step, project_dir, fid)
        if cmds:
            for c in cmds:
                print(c)
                placeholders |= set(PLACEHOLDER_RE.findall(c))
        else:
            print(f"#  no confirm primitive for this step -- validate manually, then record why "
                  f"in the finding's --note")
        print()

    cls = next((s.get("evidence_class") for s in pb.get("chain", []) if s.get("evidence_class")), None)
    print("## record + promote")
    print(f"bash scripts/finding.sh --project-dir {project_dir} --agent {agent} \\")
    print(f"    --severity {pb.get('severity_ceiling','medium')} --title '<what you proved>' \\")
    rung_flag = " --channel-rung {RUNG}" if cls in ("ssrf", "imds") else ""
    print(f"    --description '<...>' --impact '<...>'"
          + (f" --class {cls}" if cls else "") + rung_flag)
    print(f"bash scripts/validate-finding.sh --project-dir {project_dir} --agent {agent} \\")
    print(f"    --id {fid} --from-evidence")
    print()

    if placeholders:
        print("# fill before running: " + ", ".join(sorted(placeholders)))
    ns = pb.get("never_submit") or []
    if ns:
        print("# do NOT file if:")
        for line in ns:
            print(f"#   - {line}")
    return 0


def _validate_one(schema, path: Path) -> list[str]:
    import jsonschema
    try:
        data = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        return [f"YAML error: {exc}"]
    validator = jsonschema.Draft202012Validator(schema)
    errs = []
    for e in sorted(validator.iter_errors(data), key=lambda e: e.path):
        loc = "/".join(str(p) for p in e.path) or "(root)"
        errs.append(f"{loc}: {e.message}")
    return errs


def cmd_validate(args) -> int:
    import importlib.util
    if importlib.util.find_spec("jsonschema") is None:
        sys.stderr.write("validate needs jsonschema: pip install jsonschema\n")
        return 3
    schema = json.loads(SCHEMA_PATH.read_text())
    if args.file and not args.all:
        targets = [Path(args.file)]
    else:
        targets = sorted(PLAYBOOK_DIR.glob("*.yaml"))
    rc = 0
    for path in targets:
        errs = _validate_one(schema, path)
        if errs:
            rc = 1
            print(f"FAIL {path.name}")
            for e in errs:
                print(f"     - {e}")
        else:
            print(f"ok   {path.name}")
    return rc


def lane_coverage(project_dir: Path) -> dict:
    """Per playbook: how many lanes instantiate it (test-lanes.jsonl) and what the fired ones
    returned (activity.jsonl lane-fire events). The executable side of each playbook, so a
    REACHABLE verdict can be read against what was actually fired."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import lane_classes as lc
    except Exception:  # noqa: BLE001
        return {}
    cov: dict = {}

    def row(pb):
        return cov.setdefault(pb, {"lanes": 0, "fired": 0, "negative": 0, "inconclusive": 0,
                                   "candidate": 0, "confirmed": 0})

    def jsonl(path: Path):
        try:
            for line in path.read_text().splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    yield rec
        except OSError:
            return

    for lane in jsonl(project_dir / "test-lanes.jsonl"):
        pb, _ = lc.playbook_step(lane)
        if pb:
            row(pb)["lanes"] += 1
    for ev in jsonl(project_dir / "activity.jsonl"):
        if ev.get("kind") != "lane-fire":
            continue
        pb = ev.get("playbook") or lc.CLASS_STEP.get(ev.get("lane_class") or "", (None,))[0]
        if not pb:
            continue
        r = row(pb)
        r["fired"] += 1
        if ev.get("verdict") in r:
            r[ev["verdict"]] += 1
    return cov


def _executable_playbooks() -> set:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import lane_classes as lc
        return {pb for pb, _ in lc.CLASS_STEP.values()}
    except Exception:  # noqa: BLE001
        return set()


def _lane_note(cov: dict | None, executable: bool) -> str:
    if not executable:
        return "manual (no lane class)"
    if not cov or not cov["lanes"] and not cov["fired"]:
        return "0 lanes"
    abbr = {"confirmed": "conf", "candidate": "cand", "negative": "neg", "inconclusive": "inc"}
    parts = [f"{cov[k]} {a}" for k, a in abbr.items() if cov[k]]
    return f"{cov['lanes']} lanes, {cov['fired']} fired" + (f" ({', '.join(parts)})" if parts else "")


def cmd_match(args) -> int:
    project_dir = Path(args.project_dir)
    if not project_dir.is_absolute():
        sys.stderr.write("--project-dir must be an absolute path\n")
        return 2
    if not project_dir.is_dir():
        sys.stderr.write(f"no such directory: {project_dir}\n")
        return 2
    results = match(project_dir)
    cov, executable = lane_coverage(project_dir), _executable_playbooks()
    for r in results:
        r["executable"] = r["id"] in executable
        r["lanes"] = cov.get(r["id"])
    if args.json:
        print(json.dumps(results, indent=2))
        return 0
    if not results:
        print("no playbooks matched this engagement's asset-map / intel signals.")
        print("(run HUGINN Phase 0 first so asset-map.json and intel.jsonl exist.)")
        return 0
    print(f"Matched playbooks for {project_dir.name} (REACHABLE first):\n")
    vw = max(len(r["verdict"]) for r in results)
    iw = max(len(r["id"]) for r in results)
    for r in results:
        print(f"  {r['verdict']:<{vw}}  {r['id']:<{iw}}  ->{r['lead_agent']:>8}  "
              f"[{r['severity_ceiling'] or '?'}]  {_lane_note(r['lanes'], r['executable'])}  "
              f"matched: {', '.join(r['matched_on'])}")
    unmatched = sorted(set(cov) - {r["id"] for r in results})
    if unmatched:
        print(f"\nLanes exist for playbooks the signals did not match: "
              + ", ".join(f"{pb} ({_lane_note(cov[pb], True)})" for pb in unmatched))
    print("\nLead the test plan with REACHABLE lanes + the program focus areas;")
    print("surface BLOCKED lanes to the operator before dispatch (hunting Rules 1, 20-23).")
    return 0


def cmd_selftest(_args) -> int:
    import tempfile
    rc = 0
    print("== validating bundled playbooks ==")
    if cmd_validate(argparse.Namespace(file=None, all=True)) != 0:
        rc = 1
    print("\n== synthetic match ==")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "asset-map.json").write_text(json.dumps({
            "target": "example.com", "generated_at": "2026-01-01T00:00:00Z", "generated_by": "huginn",
            "technologies": [{"name": "Apollo GraphQL", "category": "framework"},
                             {"name": "AWS", "category": "cdn"}],
            "auth_mechanisms": [{"type": "jwt"}],
        }))
        (tdp / "intel.jsonl").write_text(
            json.dumps({"id": "INTEL-000001", "timestamp": "2026-01-01T00:00:00Z",
                        "source_agent": "huginn", "discovery_type": "endpoint",
                        "data": {}, "confidence": "high", "tags": ["graphql", "ssrf"]}) + "\n")
        # The scenario holds a JWT (auth_mechanisms) => first-credential held, but only one
        # identity => second-account NOT held. This separates the two gates: token-analysis
        # lanes reach, cross-tenant lanes stay BLOCKED.
        (tdp / "reachability.json").write_text(json.dumps({
            "gates_held": {"second-account": False, "first-credential": True}}))
        results = match(tdp)
        ids = [r["id"] for r in results]
        print(f"matched ids: {ids}")
        # graphql-authz-abuse must match and be BLOCKED (no 2nd account);
        # ssrf-cloud-metadata must match and be REACHABLE (no gates).
        ok = True
        by_id = {r["id"]: r for r in results}
        if "graphql-authz-abuse" not in by_id or not by_id["graphql-authz-abuse"]["verdict"].startswith("BLOCKED"):
            print("  FAIL: graphql-authz-abuse should match and be BLOCKED(second-account)"); ok = False
        if "ssrf-cloud-metadata" not in by_id or by_id["ssrf-cloud-metadata"]["verdict"] != "REACHABLE":
            print("  FAIL: ssrf-cloud-metadata should match and be REACHABLE"); ok = False
        if "auth-token-privilege" not in by_id or by_id["auth-token-privilege"]["verdict"] != "REACHABLE":
            print("  FAIL: auth-token-privilege should match (jwt auth_mechanism) and be REACHABLE"); ok = False
        if results and results[0]["rank"] > (results[-1]["rank"]):
            print("  FAIL: results not sorted REACHABLE-first"); ok = False
        (tdp / "test-lanes.jsonl").write_text(
            json.dumps({"id": "l1", "class": "infoleak", "url": "https://example.com/.env"}) + "\n")
        (tdp / "activity.jsonl").write_text(json.dumps(
            {"kind": "lane-fire", "verdict": "negative", "lane_class": "infoleak"}) + "\n")
        cov = lane_coverage(tdp).get("exposed-file-infoleak", {})
        if (cov.get("lanes"), cov.get("fired"), cov.get("negative")) != (1, 1, 1):
            print(f"  FAIL: lane coverage should join lanes + fires to the playbook (got {cov})"); ok = False
        if ok:
            print("  ok: prereq matching + reachability annotation + ordering + lane coverage")
        else:
            rc = 1
    print("\nSELFTEST", "PASS" if rc == 0 else "FAIL")
    return rc


def main() -> int:
    p = argparse.ArgumentParser(prog="playbook.py", description="Grimnir attack-playbook matcher")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list").set_defaults(func=cmd_list)
    sp = sub.add_parser("show"); sp.add_argument("id"); sp.set_defaults(func=cmd_show)
    sp = sub.add_parser("validate")
    sp.add_argument("file", nargs="?"); sp.add_argument("--all", action="store_true")
    sp.set_defaults(func=cmd_validate)
    sp = sub.add_parser("plan", help="emit a playbook's chain as runnable commands")
    sp.add_argument("id")
    sp.add_argument("--project-dir", required=True)
    sp.add_argument("--finding-id", help="use a real finding id instead of AGT-NNN")
    sp.set_defaults(func=cmd_plan)
    sp = sub.add_parser("match")
    sp.add_argument("--project-dir", required=True); sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_match)
    sub.add_parser("selftest").set_defaults(func=cmd_selftest)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
