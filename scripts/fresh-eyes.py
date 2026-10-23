#!/usr/bin/env python3
"""
fresh-eyes.py -- an independent, context-free second look at a finding before it is filed.

The author of a finding is the worst person to refute it: they carry every assumption that
made it look true. This builds a packet holding ONLY what a stranger would be handed -- the
finding JSON, its repro script, and the evidence files its claims cite -- and launches a
lean headless reviewer in that directory to re-run the repro in a clean session and try to
refute each claim. No engagement notes, no intel, no other findings: if the finding does not
stand on the packet alone, that is the result.

Output: $PROJECT_DIR/reviews/<ID>-fresh-eyes.md (per-claim verdict + a floor severity),
written by the reviewer. The packet is $PROJECT_DIR/reviews/<ID>-packet/.

It never blocks filing: the reviewer runs in the background under a timeout (the timebox),
and this script returns immediately. Hunting Rule 35: once the floor survives this review
and the operator repro, file at the floor.

The launcher is `claude -p` (deliberately a bare headless call, so no repo context is loaded). Override with GRIMNIR_REVIEWER_CMD, e.g. a different headless model CLI;
the prompt is fed on stdin and the command runs with the packet as cwd.

Usage:
  scripts/fresh-eyes.py --project-dir DIR --id AGT-NNN [--dry-run] [--timebox-min 45]
"""
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finding_state import find_finding  # noqa: E402

DEFAULT_CMD = "claude -p"

PROMPT = """You are an independent security reviewer with no prior context. Your working
directory is a review packet containing exactly: one finding JSON ({fid}.json), a repro script
under repro/, and the evidence files its claims cite. Nothing else exists for you; do not look
elsewhere on this machine for engagement notes, other findings, or intel.

The finding lists claims (claims[]), each with a severity_if_true. Verdicts in the file have been
reset to untested on purpose: form your own.

Do this, within about {timebox} minutes:
1. Read {fid}.json and the repro script. Run the repro in a clean session (fresh shell, no cached
   state). Fill in only placeholders the script itself asks for. Send no traffic beyond what the
   script sends, and nothing at any host the script does not name.
2. For EVERY claim, try to refute it: look for a benign explanation, a missing control, a
   baseline that makes the behaviour intended, evidence that does not actually show what the
   claim says, or a claim whose text goes beyond its evidence.
3. Write {out} with:
   - a table: claim id | kind | verdict (survived | refuted | untested) | one-line reason
   - FLOOR: the highest severity whose claims, and every lower claim, you judge survived
     (or NONE if the base claim did not survive)
   - anything the repro needs to be runnable by a stranger that it does not say
Be adversarial and specific. An unclear result is "untested", never "survived".
"""


def build_packet(project_dir: Path, fid: str, finding_path: Path):
    """Copy the allowed files into reviews/<fid>-packet/. Returns (packet, copied, missing)."""
    packet = project_dir / "reviews" / f"{fid}-packet"
    if packet.exists():
        shutil.rmtree(packet)
    packet.mkdir(parents=True)
    f = json.loads(finding_path.read_text())
    # The reviewer must reach its own verdict, so the author's verdicts and floor are withheld.
    f.pop("floor_severity", None)
    for c in f.get("claims") or []:
        c["verdict"] = "untested"
    (packet / f"{fid}.json").write_text(json.dumps(f, indent=2) + "\n")
    copied, missing = [f"{fid}.json"], []

    def take(rel: str):
        src = (project_dir / rel).resolve()
        # Evidence paths come from a finding file; refuse anything that escapes the project.
        if project_dir.resolve() not in src.parents or not src.is_file():
            missing.append(rel)
            return
        dst = packet / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel)

    take(f"repro/{fid}.sh")
    for c in f.get("claims") or []:
        for rel in c.get("evidence") or []:
            take(rel)
    return packet, copied, missing


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--id", required=True)
    ap.add_argument("--dry-run", action="store_true", help="build the packet, print the command, launch nothing")
    ap.add_argument("--timebox-min", type=int, default=45)
    a = ap.parse_args(argv)

    project_dir = Path(a.project_dir)
    if not project_dir.is_absolute():
        sys.exit("error: --project-dir must be an absolute path")
    rec = find_finding(str(project_dir), a.id)
    if not rec:
        sys.exit(f"error: no finding {a.id} under {project_dir}")
    fpath = Path(rec["_path"])
    packet, copied, missing = build_packet(project_dir, a.id, fpath)

    out = project_dir / "reviews" / f"{a.id}-fresh-eyes.md"
    prompt_path = project_dir / "reviews" / f"{a.id}-fresh-eyes-prompt.md"
    prompt_path.write_text(PROMPT.format(fid=a.id, timebox=a.timebox_min, out=out))
    cmd = ["timeout", str(a.timebox_min * 60)] + shlex.split(os.environ.get("GRIMNIR_REVIEWER_CMD", DEFAULT_CMD))

    print(f"packet: {packet}")
    for rel in copied:
        print(f"  + {rel}")
    for rel in missing:
        print(f"  ! missing or outside project, not packed: {rel}", file=sys.stderr)
    if "repro/%s.sh" % a.id in missing:
        print(f"  ! no repro script: scaffold one with finding.sh --repro, or the reviewer has nothing to run", file=sys.stderr)
    print(f"command: cd {packet} && {' '.join(shlex.quote(c) for c in cmd)} < {prompt_path}")
    if a.dry_run:
        print("(dry-run: nothing launched)")
        return 0

    log = project_dir / "reviews" / f"{a.id}-fresh-eyes.log"
    with open(prompt_path) as pin, open(log, "w") as lout:
        proc = subprocess.Popen(cmd, cwd=packet, stdin=pin, stdout=lout, stderr=subprocess.STDOUT,
                                start_new_session=True)
    print(f"launched pid {proc.pid} (timebox {a.timebox_min} min); verdict will land in {out}")
    print("filing is not blocked on this review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
