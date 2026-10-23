#!/usr/bin/env python3
"""
export-findings.py — export Grimnir findings to interop formats.

Grimnir's finding.schema.json is already rich; the gap Kittysploit highlighted is
INTEROP — getting findings into the tools a pentest/red-team deliverable feeds
(GitHub code scanning, DefectDojo, vuln managers). This reads the per-agent finding
JSON that already conforms to schemas/finding.schema.json and emits:

  sarif   SARIF 2.1.0 (default) — the widest-ingested format.
  json    A single merged findings.json bundle (Grimnir-native, deduped by nothing;
          just concatenated + sorted) for quick machine consumption.

By default only findings that clear the report validation gate are exported
(validation.state in {confirmed, validated}); --include-theoretical adds the rest,
--all also includes refuted. This mirrors the /report HARD gate so an exported
artifact never over-claims.

Usage:
  export-findings.py --project-dir DIR [--format sarif|json] [--out FILE]
                     [--include-theoretical] [--all]
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

SEVERITY_TO_SARIF = {  # SARIF result.level
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
AGENTS = ["huginn", "specter", "artemis", "hunter", "nimbus", "nomad"]


def load_findings(project_dir: Path) -> list[dict]:
    findings = []
    for agent in AGENTS:
        # Match on the DIRECTORY, not a filename prefix. Ids are AGT-NNN now
        # (SPE-024.json) and older engagements used FINDING-001.json,
        # specter-FINDING-003-oauth.json and others -- a prefix glob silently
        # exports nothing, which looks exactly like "no findings to export".
        for fp in sorted(glob.glob(str(project_dir / agent / "findings" / "*.json"))):
            try:
                data = json.loads(Path(fp).read_text())
            except (json.JSONDecodeError, OSError) as exc:
                sys.stderr.write(f"[warn] skipping {fp}: {exc}\n")
                continue
            data.setdefault("agent", agent)
            data["_path"] = fp
            findings.append(data)
    return findings


def gate_state(f: dict) -> str:
    return ((f.get("validation") or {}).get("state") or "theoretical").lower()


def select(findings: list[dict], include_theoretical: bool, include_all: bool) -> list[dict]:
    out = []
    for f in findings:
        st = gate_state(f)
        if include_all:
            out.append(f)
        elif include_theoretical:
            if st != "refuted":
                out.append(f)
        else:
            if st in ("confirmed", "validated"):
                out.append(f)
    out.sort(key=lambda f: (SEVERITY_RANK.get(str(f.get("severity", "info")).lower(), 9),
                            f.get("agent", ""), f.get("id", "")))
    return out


def _cwe_tags(f: dict) -> list[str]:
    fw = f.get("frameworks") or {}
    return [c for c in (fw.get("cwe") or []) if c]


def _impact_summary(f: dict) -> str:
    """Impact text, tolerant of both shapes on disk.

    The schema says `impact` is an object with a `summary`, and that is what
    finding.sh writes -- but hand-written and legacy findings carry a bare
    string. Assuming the object shape crashed the whole export on the first
    such record, so a single malformed finding lost every other one with it.
    """
    impact = f.get("impact")
    if isinstance(impact, dict):
        return str(impact.get("summary") or "")
    if isinstance(impact, str):
        return impact
    return ""


def to_sarif(findings: list[dict], target: str) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        fid = f.get("id", "FINDING-000")
        agent = f.get("agent", "grimnir")
        rule_id = f"grimnir/{agent}/{fid}"
        sev = str(f.get("severity", "info")).lower()
        impact_summary = _impact_summary(f)
        tags = ["security", agent, sev]
        tags += _cwe_tags(f)
        for k in ("owasp_api", "owasp_llm", "owasp_agentic", "owasp_wstg"):
            tags += [t for t in ((f.get("frameworks") or {}).get(k) or []) if t]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("title", fid),
                "shortDescription": {"text": (f.get("title") or fid)[:200]},
                "fullDescription": {"text": f.get("description", "") or f.get("title", "")},
                "defaultConfiguration": {"level": SEVERITY_TO_SARIF.get(sev, "note")},
                "properties": {
                    "tags": sorted(set(tags)),
                    "security-severity": f"{float(f.get('cvss_score') or 0.0):.1f}",
                    "validation-state": gate_state(f),
                },
            }
        locations = []
        for tgt in (f.get("affected_targets") or [target]):
            locations.append({
                "physicalLocation": {"artifactLocation": {"uri": str(tgt)}},
            })
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(sev, "note"),
            "message": {"text": impact_summary or f.get("description", "") or f.get("title", "")},
            "locations": locations or [{"physicalLocation": {"artifactLocation": {"uri": target}}}],
            "properties": {
                "id": fid, "agent": agent, "severity": sev,
                "cvss_score": f.get("cvss_score"),
                "validation_state": gate_state(f),
                "status": f.get("status"),
                "chain_id": f.get("chain_id"),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Grimnir",
                "informationUri": "https://github.com/DoctorGoz/grimnir",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": target, "finding_count": len(results)},
        }],
    }


def main() -> int:
    p = argparse.ArgumentParser(prog="export-findings.py")
    p.add_argument("--project-dir", required=True)
    p.add_argument("--format", choices=["sarif", "json"], default="sarif")
    p.add_argument("--out")
    p.add_argument("--include-theoretical", action="store_true",
                   help="also export theoretical findings (default: confirmed/validated only)")
    p.add_argument("--all", action="store_true",
                   help="export every finding including refuted (audit use)")
    args = p.parse_args()

    project_dir = Path(args.project_dir)
    if not project_dir.is_absolute():
        sys.stderr.write("--project-dir must be an absolute path\n"); return 2
    if not project_dir.is_dir():
        sys.stderr.write(f"no such directory: {project_dir}\n"); return 2

    target = project_dir.name
    am = project_dir / "asset-map.json"
    if am.is_file():
        try:
            target = json.loads(am.read_text()).get("target", target)
        except (json.JSONDecodeError, OSError):
            pass

    allf = load_findings(project_dir)
    selected = select(allf, args.include_theoretical, args.all)

    if args.format == "sarif":
        payload = to_sarif(selected, target)
    else:
        for f in selected:
            f.pop("_path", None)
        payload = {"target": target, "generated_by": "grimnir",
                   "finding_count": len(selected), "findings": selected}

    text = json.dumps(payload, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n")
        sys.stderr.write(f"wrote {len(selected)} finding(s) ({args.format}) -> {args.out}\n")
    else:
        print(text)

    excluded = len(allf) - len(selected)
    if excluded and not args.all:
        sys.stderr.write(f"[gate] excluded {excluded} finding(s) below the export gate "
                         f"(use --include-theoretical or --all to include).\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
