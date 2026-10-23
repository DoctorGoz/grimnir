#!/usr/bin/env python3
"""activity.py — the unified activity ledger: one append-only event stream per engagement.

Every tool that does work on an engagement records it here, so "what was tested on this
program, by whom, with what result" is one file instead of several hand-kept handoff docs.

  $PROJECT_DIR/activity.jsonl              per-engagement stream (authoritative)
  $GRIMNIR_HOME/activity/activity.jsonl    host-global rollup (same records + "program");
                                           $GRIMNIR_ACTIVITY_ROLLUP overrides the path

Both live in the non-repo data tiers: records name hosts and programs. Values that look like
tokens or keys are redacted before anything is written, so a careless --summary cannot leak a
credential into the ledger.

Record:
  {"id": "ACT-000873", "ts": "...Z", "actor": "executor", "kind": "lane-fire",
   "verdict": "negative", "summary": "...", "target": "https://...", "lane_class": "authz",
   "playbook": "bola-cross-tenant", "refs": ["finding:SPE-004"], "session": "run:..."}

Writers call emit() (Python) or `activity.py append` (shell; event-emitter.sh wraps it as
_activity_event). Emitting is best-effort: emit() never raises, so a ledger problem can never
fail the tool doing the real work. The CLI validates loudly instead, for direct use.

Usage:
  activity.py append --project-dir DIR --kind K --actor A --summary TEXT
                     [--verdict V] [--target T] [--lane-class C] [--playbook P]
                     [--ref TYPE:ID ...] [--session S] [--json]
  activity.py show   --project-dir DIR [--kind K] [--actor A] [-n N] [--json]
  activity.py yield  (--project-dir DIR | --all) [--json]
  activity.py backfill --project-dir DIR [--dry-run]   seed from .lane-runs.jsonl + decisions.jsonl
  activity.py selftest
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

LEDGER_FILE = "activity.jsonl"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import lane_classes as _lc
except Exception:  # noqa: BLE001 — the view degrades to "?" rather than failing
    _lc = None

ACTORS = ("operator", "orchestrator", "specter", "artemis", "hunter", "nimbus", "nomad",
          "huginn", "executor", "tier2", "curator")
# Aliases the existing tools already use for an actor; normalized on write.
ACTOR_ALIASES = {"grimnir": "orchestrator", "report-compiler": "orchestrator"}
KINDS = ("probe", "lane-fire", "finding", "validate", "negative", "decision", "blocked", "cred",
         "recon", "note", "handoff", "void")
VERDICTS = ("confirmed", "candidate", "negative", "inconclusive", "blocked", "n/a")
OPTIONAL = ("target", "lane_class", "playbook", "session")
MAX_SUMMARY = 500

# ── Redaction ────────────────────────────────────────────────────────────────
# Token-shaped values, not field names: the summary is free text, so a credential can turn up
# anywhere. Each pattern keeps enough context to say WHAT was there.
_REDACTIONS = [
    # JWT / JWS (three base64url segments, header starts eyJ).
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), "<jwt>"),
    # Authorization header values: keep the scheme word.
    (re.compile(r"(?i)\b(bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 <redacted>"),
    # key=value / key: value for secret-named keys (query strings, cookies, JSON-ish text).
    # Short keys (sig, sid, auth) only as whole words, so "authz: negative" survives.
    (re.compile(r"(?i)\b([\w-]*(?:token|secret|passw(?:or)?d|api[_-]?key|session|sessid|"
                r"authorization|cookie|signature)[\w-]*|sig|sid|auth|key)"
                r"(\"?\s*[:=]\s*\"?)([^\s\"&;,}]{6,})"),
     r"\1\2<redacted>"),
    # Well-known prefixed keys (cloud, VCS, chat, payment).
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<aws-key>"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"), "<gh-token>"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), "<slack-token>"),
    (re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "<api-key>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "<api-key>"),
    # Long opaque strings: 32+ hex, or 40+ base64-ish with mixed case AND a digit. Ids and
    # paths are shorter or single-case, so they survive.
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<hex>"),
    (re.compile(r"(?<![\w/.-])(?=[A-Za-z0-9+/_-]*[a-z])(?=[A-Za-z0-9+/_-]*[A-Z])"
                r"(?=[A-Za-z0-9+/_-]*\d)[A-Za-z0-9+/_-]{40,}={0,2}"), "<opaque>"),
]


def redact(value):
    """Redact token-shaped substrings in a string, or recursively in a list/dict."""
    if isinstance(value, str):
        for rx, repl in _REDACTIONS:
            value = rx.sub(repl, value)
        return value
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    return value


# ── Paths ────────────────────────────────────────────────────────────────────
def grimnir_home() -> str:
    return os.environ.get("GRIMNIR_HOME") or os.path.expanduser("~/.grimnir")


def ledger_path(project_dir: str) -> str:
    return os.path.join(project_dir, LEDGER_FILE)


def rollup_path() -> str:
    """$GRIMNIR_ACTIVITY_ROLLUP overrides, so test suites never write the operator's rollup."""
    return (os.environ.get("GRIMNIR_ACTIVITY_ROLLUP")
            or os.path.join(grimnir_home(), "activity", LEDGER_FILE))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Record building ──────────────────────────────────────────────────────────
class ActivityError(ValueError):
    pass


def normalize_actor(actor: str) -> str:
    a = (actor or "").strip().lower()
    return ACTOR_ALIASES.get(a, a)


def build_record(kind: str, actor: str, summary: str, verdict: str | None = None,
                 refs: list[str] | None = None, lenient: bool = False, **opt) -> dict:
    """Validate and normalize one record (without id/ts). Raises ActivityError on bad input.
    lenient=True (the emitter paths) files an unknown actor as orchestrator and keeps the raw
    name in actor_raw, rather than losing the event."""
    actor_raw = None
    actor = normalize_actor(actor)
    if actor not in ACTORS:
        if not lenient:
            raise ActivityError(f"actor '{actor}' not in {'|'.join(ACTORS)}")
        actor_raw, actor = actor or "?", "orchestrator"
    if kind not in KINDS:
        raise ActivityError(f"kind '{kind}' not in {'|'.join(KINDS)}")
    verdict = (verdict or "n/a").strip().lower()
    if verdict not in VERDICTS:
        raise ActivityError(f"verdict '{verdict}' not in {'|'.join(VERDICTS)}")
    summary = (summary or "").strip()
    if not summary:
        raise ActivityError("summary is required")
    if len(summary) > MAX_SUMMARY:
        summary = summary[:MAX_SUMMARY - 3] + "..."
    rec = {"actor": actor, "kind": kind, "verdict": verdict, "summary": summary}
    if actor_raw:
        rec["actor_raw"] = actor_raw
    for k in OPTIONAL:
        v = opt.get(k)
        if v:
            rec[k] = str(v)
    if not rec.get("session"):
        sess = os.environ.get("GRIMNIR_SESSION", "").strip()
        if sess:
            rec["session"] = sess
    refs = [r.strip() for r in (refs or []) if r and r.strip()]
    for r in refs:
        if ":" not in r:
            raise ActivityError(f"ref '{r}' must be TYPE:ID (e.g. finding:SPE-004)")
    if refs:
        rec["refs"] = refs
    return redact(rec)


def _next_id(fh) -> str:
    """Next ACT id from the last record in an open, locked ledger. Reads only the tail."""
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    if size == 0:
        return "ACT-000001"
    fh.seek(max(0, size - 8192))
    tail = fh.read().decode("utf-8", "replace").strip().splitlines()
    for line in reversed(tail):
        m = re.search(r'"id"\s*:\s*"ACT-(\d+)"', line)
        if m:
            return f"ACT-{int(m.group(1)) + 1:06d}"
    # Tail held no parseable id (corrupt or foreign lines): fall back to a full line count.
    fh.seek(0)
    return f"ACT-{sum(1 for _ in fh) + 1:06d}"


def append(project_dir: str, kind: str, actor: str, summary: str, ts: str | None = None,
           **kw) -> dict:
    """Validate, redact, assign an id under an exclusive lock, and append. Raises on failure.
    `ts` is for backfill only: live writers always take the current time."""
    if not os.path.isabs(project_dir):
        raise ActivityError("--project-dir must be an absolute path")
    if not os.path.isdir(project_dir):
        raise ActivityError(f"no such directory: {project_dir}")
    body = build_record(kind, actor, summary, **kw)
    path = ledger_path(project_dir)
    with open(path, "a+b") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            rec = {"id": _next_id(fh), "ts": ts or _now(), **body}
            fh.seek(0, os.SEEK_END)
            fh.write((json.dumps(rec) + "\n").encode())
            fh.flush()
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
    # Host-global rollup: best-effort; the per-engagement stream is the record of truth.
    try:
        rp = rollup_path()
        os.makedirs(os.path.dirname(rp), exist_ok=True)
        with open(rp, "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps({**rec, "program": os.path.basename(project_dir.rstrip("/"))}) + "\n")
    except OSError:
        pass
    return rec


def emit(project_dir: str, kind: str, actor: str, summary: str, **kw) -> dict | None:
    """append() for in-process writers: lenient about the actor, never raises, returns None on
    any failure."""
    try:
        return append(project_dir, kind, actor, summary, lenient=True, **kw)
    except Exception:  # noqa: BLE001 — the ledger must never break the caller
        return None


def read(path: str) -> list[dict]:
    rows = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    rows.append(rec)
    except OSError:
        pass
    return rows


# ── Views ────────────────────────────────────────────────────────────────────
YIELD_COLS = ("fired", "negative", "inconclusive", "candidate", "confirmed")


def voided_fires(rows: list[dict]) -> set:
    """(program, ACT id) of every lane-fire a `void` event cancelled. ACT ids are per engagement,
    so on a rollup the program is part of the key; in a single ledger it is None."""
    return {(r.get("program"), ref.split(":", 1)[1]) for r in rows if r.get("kind") == "void"
            for ref in r.get("refs") or [] if ref.startswith("act:")}


def lane_yield(rows: list[dict]) -> dict:
    """Lane-fire outcomes grouped by lane class and by playbook (plus program on a rollup).
    A fire a `void` event cancelled is counted in `voided`, not in its verdict."""
    out = {"by_class": defaultdict(lambda: dict.fromkeys(YIELD_COLS, 0)),
           "by_playbook": defaultdict(lambda: dict.fromkeys(YIELD_COLS, 0)),
           "by_program": defaultdict(lambda: dict.fromkeys(YIELD_COLS, 0)),
           "blocked": 0, "voided": 0}
    voided = voided_fires(rows)
    for r in rows:
        if r.get("kind") == "blocked":
            out["blocked"] += 1
            continue
        if r.get("kind") != "lane-fire":
            continue
        if (r.get("program"), r.get("id")) in voided:
            out["voided"] += 1
            continue
        v = r.get("verdict")
        cls = r.get("lane_class") or "?"
        # Events written before lanes carried a playbook resolve through the class table.
        pb = r.get("playbook") or (_lc.CLASS_STEP.get(cls, ("?",))[0] if _lc else "?")
        keys = [("by_class", cls), ("by_playbook", pb)]
        if r.get("program"):
            keys.append(("by_program", r["program"]))
        for group, key in keys:
            row = out[group][key]
            row["fired"] += 1
            if v in row:
                row[v] += 1
    return {k: (dict(v) if isinstance(v, defaultdict) else v) for k, v in out.items()}


def _print_table(title: str, table: dict) -> None:
    if not table:
        return
    print(f"\n{title}")
    print(f"  {'':<28}" + "".join(f"{c:>13}" for c in YIELD_COLS))
    for key, row in sorted(table.items(), key=lambda kv: -kv[1]["fired"]):
        print(f"  {key:<28}" + "".join(f"{row[c]:>13}" for c in YIELD_COLS))


# ── Backfill ─────────────────────────────────────────────────────────────────
# Lane-runner verdict -> activity verdict (same table as the calling harness.verdict_disposition).
_LANE_VERDICT = {"confirmed": "confirmed", "bola-likely": "candidate", "leak-likely": "candidate",
                 "negative": "negative"}


def _iso_z(ts: str | None) -> str | None:
    """Normalize a recorded timestamp to the ledger's ...Z form; None if unparseable."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def backfill_events(project_dir: str) -> list[dict]:
    """Events the ledger is missing, from the records that predate it. Idempotent: anything whose
    ref (lane:ID for a fire, decision:ID) is already in the ledger is skipped."""
    seen = {ref for r in read(ledger_path(project_dir)) for ref in (r.get("refs") or [])}
    lanes = {}
    for rec in read(os.path.join(project_dir, "test-lanes.jsonl")):
        if rec.get("id"):
            lanes[rec["id"]] = rec
    out = []
    for run in read(os.path.join(project_dir, ".lane-runs.jsonl")):
        lid = run.get("lane")
        if not lid or run.get("void") or f"lane:{lid}" in seen:
            continue
        seen.add(f"lane:{lid}")
        lane = lanes.get(lid, {})
        verdict = _LANE_VERDICT.get(str(run.get("verdict") or "").lower(), "inconclusive")
        fid = run.get("finding_id")
        cls = lane.get("class") or ("authz" if lane else None)
        out.append({"kind": "lane-fire", "actor": "executor", "verdict": verdict, "ts": _iso_z(run.get("ts")),
                    "summary": f"{cls or 'lane'} lane fired: {verdict} (backfilled from .lane-runs.jsonl)",
                    "refs": [f"lane:{lid}"] + ([f"finding:{fid}"] if fid else []),
                    "target": lane.get("url"), "lane_class": cls, "playbook": lane.get("playbook")})
    for d in read(os.path.join(project_dir, "decisions.jsonl")):
        did = d.get("id")
        if not did or f"decision:{did}" in seen:
            continue
        seen.add(f"decision:{did}")
        subject = f"{d['subject']}: " if d.get("subject") else ""
        refs = [f"decision:{did}"] + ([f"finding:{d['related_finding']}"] if d.get("related_finding") else [])
        out.append({"kind": "decision", "actor": d.get("actor") or "orchestrator", "verdict": "n/a",
                    "ts": _iso_z(d.get("timestamp")),
                    "summary": f"{d.get('decision_type', '?')}: {subject}{d.get('reason', '')}",
                    "refs": refs, "playbook": d.get("playbook_id")})
    out.sort(key=lambda e: e["ts"] or "")
    return out


def cmd_backfill(a) -> int:
    if not os.path.isabs(a.project_dir) or not os.path.isdir(a.project_dir):
        print("activity: --project-dir must be an existing absolute path", file=sys.stderr)
        return 2
    events = backfill_events(a.project_dir)
    written = 0
    for e in events:
        if a.dry_run:
            print(f"  would add {e['kind']:<9} {e['verdict']:<12} {e['summary'][:90]}")
            continue
        kind, actor, summary = e.pop("kind"), e.pop("actor"), e.pop("summary")
        try:
            append(a.project_dir, kind, actor, summary, lenient=True, **e)
            written += 1
        except (ActivityError, OSError) as err:
            print(f"activity: skipped one event: {err}", file=sys.stderr)
    verb = "would add" if a.dry_run else "added"
    print(f"{verb} {len(events) if a.dry_run else written} event(s) to {ledger_path(a.project_dir)}")
    return 0


# ── CLI ──────────────────────────────────────────────────────────────────────
def cmd_append(a) -> int:
    try:
        rec = append(a.project_dir, a.kind, a.actor, a.summary, verdict=a.verdict, refs=a.ref,
                     target=a.target, lane_class=a.lane_class, playbook=a.playbook,
                     session=a.session, lenient=a.lenient)
    except (ActivityError, OSError) as e:
        print(f"activity: {e}", file=sys.stderr)
        return 2
    print(json.dumps(rec) if a.json else f"{rec['id']} {rec['kind']} {rec['verdict']}")
    return 0


def cmd_show(a) -> int:
    rows = read(ledger_path(a.project_dir))
    if a.kind:
        rows = [r for r in rows if r.get("kind") == a.kind]
    if a.actor:
        rows = [r for r in rows if r.get("actor") == normalize_actor(a.actor)]
    rows = rows[-a.n:] if a.n else rows
    if a.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print(f"no activity recorded at {ledger_path(a.project_dir)}")
        return 0
    for r in rows:
        tgt = f"  {r['target']}" if r.get("target") else ""
        print(f"{r.get('id', '?'):<11} {r.get('ts', ''):<21} {r.get('actor', ''):<12} "
              f"{r.get('kind', ''):<9} {r.get('verdict', ''):<12} {r.get('summary', '')}{tgt}")
    return 0


def cmd_yield(a) -> int:
    rows = read(rollup_path() if a.all else ledger_path(a.project_dir))
    y = lane_yield(rows)
    if a.json:
        print(json.dumps(y, indent=2))
        return 0
    total = sum(r["fired"] for r in y["by_class"].values())
    if not total:
        print("no lane fires recorded yet.")
        return 0
    print(f"{total} lane fires, {y['blocked']} blocked, {y['voided']} voided")
    _print_table("by lane class", y["by_class"])
    _print_table("by playbook", y["by_playbook"])
    if a.all:
        _print_table("by program", y["by_program"])
    return 0


def cmd_selftest(_a) -> int:
    import tempfile
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        fails += 0 if cond else 1

    with tempfile.TemporaryDirectory() as d:
        os.environ["GRIMNIR_HOME"] = os.path.join(d, "home")
        os.environ.pop("GRIMNIR_ACTIVITY_ROLLUP", None)
        pd = os.path.join(d, "acme")
        os.mkdir(pd)
        r1 = append(pd, "lane-fire", "executor", "4-way: cross 403", verdict="negative",
                    lane_class="authz", playbook="bola-cross-tenant")
        r2 = append(pd, "note", "grimnir", "Authorization: Bearer abcdefghijklmnop1234")
        check("ids are sequential", (r1["id"], r2["id"]) == ("ACT-000001", "ACT-000002"))
        check("actor alias normalized", r2["actor"] == "orchestrator")
        check("bearer value redacted", "abcdefghijklmnop1234" not in r2["summary"])
        check("rollup carries program", read(rollup_path())[-1].get("program") == "acme")
        check("bad kind rejected", emit(pd, "nonsense", "executor", "x") is None)
        y = lane_yield(read(ledger_path(pd)))
        check("yield counts the negative", y["by_class"]["authz"]["negative"] == 1)
    print("selftest:", "OK" if not fails else f"{fails} FAILED")
    return 1 if fails else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Unified per-engagement activity ledger.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("append", help="record one event")
    s.add_argument("--project-dir", required=True)
    s.add_argument("--kind", required=True, choices=KINDS)
    s.add_argument("--actor", required=True)
    s.add_argument("--summary", required=True)
    s.add_argument("--verdict", default="n/a")
    s.add_argument("--target")
    s.add_argument("--lane-class")
    s.add_argument("--playbook")
    s.add_argument("--ref", action="append", default=[], help="TYPE:ID, repeatable")
    s.add_argument("--session")
    s.add_argument("--lenient", action="store_true",
                   help="file an unknown actor as orchestrator (actor_raw keeps it) instead of failing")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_append)

    s = sub.add_parser("show", help="list recorded events")
    s.add_argument("--project-dir", required=True)
    s.add_argument("--kind")
    s.add_argument("--actor")
    s.add_argument("-n", type=int, default=0, help="last N only")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("yield", help="lane-fire outcomes by class and playbook")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--project-dir")
    g.add_argument("--all", action="store_true", help="host-global rollup, across programs")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_yield)

    s = sub.add_parser("backfill", help="seed the ledger from pre-ledger records (idempotent)")
    s.add_argument("--project-dir", required=True)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_backfill)

    s = sub.add_parser("selftest")
    s.set_defaults(fn=cmd_selftest)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
