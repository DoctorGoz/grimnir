"""Canonical finding-state model — the ONE place the whole system agrees on a
finding's evidence strength and whether it may ship. Import this instead of
re-deriving `status` / `validation` by hand, so the deliver gate, the report
compiler, the coverage tool and the exporters can never drift apart.

Two orthogonal dimensions live on a finding:
  - status            triage: suspected | under_investigation | confirmed (analyst's call)
  - validation_state  evidence strength: theoretical -> validated -> confirmed -> refuted

SHIP readiness keys ONLY on validation_state == 'confirmed' (a reproducible PoC AND an
independent check: negative control for authz, render proof for UI, out-of-band for
SSRF), never on the analyst's `status` field. 'validated' means reproduced once, not
yet independently confirmed, and MUST NOT ship. A finding carrying a terminal
`disposition` (already submitted / duplicate / not-applicable / withdrawn) is done and
never re-surfaces to ship. This mirrors the invariant stated in validate-finding.sh and
rules/never-submit.md — encoded here as data, not as operator memory.
"""
from __future__ import annotations

import datetime
import glob
import json
import os

VALIDATION_STATES = ("theoretical", "validated", "confirmed", "refuted")
# The only evidence state that may be delivered or submitted.
SHIP_READY_STATES = frozenset({"confirmed"})
# A finding with any of these dispositions is terminal — never re-surface it to ship.
TERMINAL_DISPOSITIONS = frozenset(
    {"submitted", "duplicate", "not-applicable", "na", "wont-fix", "withdrawn", "resolved"}
)
# 'held' is the ONE non-terminal disposition: a confirmed finding deliberately parked
# (deprioritized / downgraded / gated on an unlock / program frozen), NOT dead. It is
# excluded from ship-readiness so no gate auto-delivers it, but unlike a terminal
# disposition a held finding re-surfaces as a review reminder rather than vanishing.
HELD_DISPOSITIONS = frozenset({"held"})


def validation_state(finding: dict) -> str:
    """Evidence-strength state, tolerant of the two shapes seen on disk: a flat
    `validation_state` or a nested `validation.state`. Defaults to theoretical."""
    if not isinstance(finding, dict):
        return "theoretical"
    vs = finding.get("validation_state")
    if not vs:
        vs = (finding.get("validation") or {}).get("state")
    return vs or "theoretical"


def disposition(finding: dict) -> str:
    """Terminal handling marker, if any (lowercased). Empty when the finding is still
    live. Read from a flat `disposition` or a nested `submission.status`."""
    if not isinstance(finding, dict):
        return ""
    d = finding.get("disposition") or (finding.get("submission") or {}).get("status") or ""
    return str(d).strip().lower()


def is_held(finding: dict) -> bool:
    """True when a finding carries the non-terminal `held` marker: confirmed but
    deliberately parked (not being filed right now). Held findings are excluded from
    ship-readiness, but unlike a terminal disposition they still re-surface for review."""
    return disposition(finding) in HELD_DISPOSITIONS


def is_ship_ready(finding: dict) -> bool:
    """The single SHIP predicate for the whole system: independently confirmed AND not
    already dispositioned AND not parked. A `validated` or `theoretical` finding is never
    ship-ready; neither is one stamped terminal (submitted/duplicate/…) or `held`."""
    return (
        validation_state(finding) in SHIP_READY_STATES
        and disposition(finding) not in TERMINAL_DISPOSITIONS
        and not is_held(finding)
    )


def validation_block(finding: dict) -> dict:
    """The structured proof a ship-ready claim rests on — what a submit task must carry
    so 'confirmed' is always traceable to its evidence, never a bare word."""
    v = finding.get("validation") if isinstance(finding, dict) else None
    if isinstance(v, dict) and v:
        return {
            "state": v.get("state") or validation_state(finding),
            "method": v.get("method") or finding.get("validation_method"),
            "checked_at": v.get("checked_at") or v.get("validated_at"),
        }
    return {
        "state": validation_state(finding),
        "method": finding.get("validation_method") if isinstance(finding, dict) else None,
        "checked_at": finding.get("validated_at") if isinstance(finding, dict) else None,
    }


def load_findings(project_dir: str) -> list[dict]:
    """Every finding record for an engagement, from both the merged top-level findings/
    and each agent's <agent>/findings/. Each dict gains a `_path`. Malformed JSON and
    id-less records are skipped, not fatal."""
    paths = glob.glob(os.path.join(project_dir, "findings", "*.json")) + glob.glob(
        os.path.join(project_dir, "*", "findings", "*.json")
    )
    out: list[dict] = []
    for fp in sorted(paths):
        try:
            with open(fp) as fh:
                d = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(d, dict) and d.get("id"):
            d["_path"] = fp
            out.append(d)
    return out


def ship_ready_findings(project_dir: str) -> list[dict]:
    """Findings for an engagement that may be delivered/submitted, in path order."""
    return [f for f in load_findings(project_dir) if is_ship_ready(f)]


def held_findings(project_dir: str) -> list[dict]:
    """Confirmed findings parked with the non-terminal `held` marker — deferred, not dead.
    Excluded from ship_ready_findings; a monitor surfaces these as review reminders."""
    return [
        f for f in load_findings(project_dir)
        if validation_state(f) in SHIP_READY_STATES and is_held(f)
    ]


def find_finding(project_dir: str, finding_id: str) -> dict | None:
    """Locate one finding by id under an engagement (merged findings/ or an agent dir).
    Returns the record with its `_path`, or None. First match in path order when an id
    appears in both the merged and an agent copy — use the path directly to disambiguate."""
    for f in load_findings(project_dir):
        if f.get("id") == finding_id:
            return f
    return None


# ── Claim split: file at the floor ─────────────────────────────────────────────
# A finding may record its claims separately (claims[]: one `base`, any `escalation`, each
# with severity_if_true and a verdict of untested | survived | refuted). The FLOOR is the
# highest severity whose claims, and every claim below it, survived. A refuted escalation
# is skipped; an untested claim stops the climb; a base claim that has not survived gives
# no floor. A finding with no claims[] keeps the old meaning: its own severity once
# confirmed. File at the floor; add escalations later as comments (hunting Rule 35).
SEV_ORDER = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}


def _claim_rank(c: dict) -> int:
    return _SEV_RANK.get(str(c.get("severity_if_true", "")).lower(), -1)


def base_claim(finding: dict) -> dict | None:
    return next((c for c in finding.get("claims") or [] if c.get("kind") == "base"), None)


def floor_severity(finding: dict) -> str | None:
    """Highest severity whose claims all survived, or None."""
    claims = finding.get("claims")
    if not claims:
        sev = str(finding.get("severity", "")).lower()
        return sev if validation_state(finding) == "confirmed" and sev in _SEV_RANK else None
    base = base_claim(finding)
    if base is None or base.get("verdict") != "survived":
        return None
    floor = None
    # Base sorts first among equals so a same-severity escalation cannot mask it.
    for c in sorted(claims, key=lambda c: (_claim_rank(c), c.get("kind") != "base")):
        v = c.get("verdict", "untested")
        if v == "refuted" and c.get("kind") != "base":
            continue
        if v != "survived":
            break
        floor = str(c["severity_if_true"]).lower()
    return floor


def set_disposition(
    path: str,
    disposition: str,
    *,
    reason: str | None = None,
    ref: str | None = None,
    decided_by: str = "operator",
    source: str | None = None,
    now: str | None = None,
) -> dict:
    """Stamp a TERMINAL disposition onto a finding JSON, atomically, and return the updated
    record. This is the ONE writer for the field `is_ship_ready` treats as terminal: the
    submit/outcome step calls it so a filed / duplicate / not-applicable finding can never
    re-surface as a fresh "confirmed finding ready" deliver task. Also writes the one
    non-terminal marker, `held` (park a confirmed finding: off the ship set, still re-
    surfaced for review). Raises ValueError on an unknown disposition — only a marker in
    TERMINAL_DISPOSITIONS | HELD_DISPOSITIONS suppresses shipping; anything else would be a
    silent no-op the caller thinks worked."""
    disp = str(disposition).strip().lower()
    _allowed = TERMINAL_DISPOSITIONS | HELD_DISPOSITIONS
    if disp not in _allowed:
        raise ValueError(
            f"unknown disposition {disposition!r}; must be one of {sorted(_allowed)}"
        )
    ts = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path) as fh:
        d = json.load(fh)
    d["disposition"] = disp
    detail: dict = {"decided_by": decided_by, "decided_at": ts}
    if reason:
        detail["reason"] = reason
    if ref:
        detail["ref"] = ref
    if source:
        detail["source"] = source
    d["disposition_detail"] = detail
    d["updated_at"] = ts
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as fh:
        json.dump(d, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)
    return d


def _main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="canonical finding-state tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sd = sub.add_parser("set-disposition", help="stamp a terminal disposition on a finding")
    sd.add_argument("--project-dir")
    sd.add_argument("--id")
    sd.add_argument("--path", help="finding JSON path; overrides --project-dir/--id lookup")
    sd.add_argument("--disposition", required=True,
                    help=f"one of {sorted(TERMINAL_DISPOSITIONS | HELD_DISPOSITIONS)} "
                         f"('held' is non-terminal: parks a finding, re-surfaces for review)")
    sd.add_argument("--reason")
    sd.add_argument("--ref", help="external report id / dupe parent, e.g. 'H1 #NNNNNNN'")
    sd.add_argument("--decided-by", default="operator")
    sd.add_argument("--source")

    sr = sub.add_parser("ship-ready", help="list ship-ready findings for an engagement")
    sr.add_argument("--project-dir", required=True)

    sh = sub.add_parser("show", help="print a finding's claims and its floor severity")
    sh.add_argument("--project-dir", required=True)
    sh.add_argument("--id", required=True)

    fl = sub.add_parser("floor", help="print only the floor severity of a finding file (empty when none)")
    fl.add_argument("--file", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "set-disposition":
        path = args.path
        if not path:
            if not (args.project_dir and args.id):
                ap.error("set-disposition needs --path OR (--project-dir AND --id)")
            rec = find_finding(args.project_dir, args.id)
            if not rec:
                ap.error(f"finding {args.id} not found under {args.project_dir}")
            path = rec["_path"]
        try:
            d = set_disposition(path, args.disposition, reason=args.reason, ref=args.ref,
                                decided_by=args.decided_by, source=args.source)
        except (ValueError, OSError, json.JSONDecodeError) as e:
            ap.error(str(e))
        print(f"{d.get('id')}: disposition={d['disposition']} ship_ready={is_ship_ready(d)} -> {path}")
        return 0

    if args.cmd == "show":
        f = find_finding(args.project_dir, args.id)
        if not f:
            ap.error(f"finding {args.id} not found under {args.project_dir}")
        print(f"{f['id']}  filed severity: {f.get('severity')}  state: {validation_state(f)}")
        if not f.get("claims"):
            print("  (no claims[] recorded: floor is the finding's own severity once confirmed)")
        for c in f.get("claims") or []:
            print(f"  {c.get('id', '?'):<4} {c.get('kind', '?'):<10} {c.get('severity_if_true', '?'):<8} "
                  f"{c.get('verdict', 'untested'):<9} {c.get('text', '')}")
        print(f"floor: {floor_severity(f) or 'NONE (base claim not survived)'}")
        return 0

    if args.cmd == "floor":
        with open(args.file) as fh:
            print(floor_severity(json.load(fh)) or "")
        return 0

    if args.cmd == "ship-ready":
        for f in ship_ready_findings(args.project_dir):
            print(f"{f.get('id')}\t{f.get('severity', '?')}\t{f['_path']}")
        return 0
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_main())
