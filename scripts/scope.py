#!/usr/bin/env python3
"""scope.py — one in-scope decision for every tool that touches a target.

Recon, the corpus builder, lane synthesis, and the calling harness all ask the same question: is this URL
in scope for this engagement? Before this module each answered it differently or not at all
(`recon-pipeline.sh --scope-file` parsed the flag and never used it; lane synthesis and the calling harness had
no scope check). A lane on an excluded host must be dropped at synthesis AND refused at fire time,
so both layers call `load(project_dir).check(url)` and get the same answer.

SOURCES (merged; all optional)
    scope.json                       operator override: {"in_scope": [...], "out_of_scope": [...]}.
                                     Use it to correct a bad parse; its entries always apply.
    h1-structured-scopes*.json,      HackerOne structured scopes (GraphQL edges, REST data[], or a
    h1-scope*.json                   bare list). eligible_for_submission=false -> out of scope.
    *in-scope*.txt, *out-of-scope*.txt   plain host lists, one per line ('#' comments).
    scope.md                         the intake file. Always contributes exclusions. Contributes
                                     in-scope entries ONLY when no machine source (structured JSON
                                     or plain list) supplied any, because the machine copy is the
                                     authoritative one and prose summaries over-generalize
                                     ("all `*.acme.com`" on an explicit-host-list program).
    The JSON and list files are read from the engagement root and its recon/ directory.

MATCHING
    `*.acme.com` matches any subdomain of acme.com, NOT the apex (list `acme.com` separately).
    A `*` inside a name matches exactly one label (`api-gw.*.acme.com`). CIDRs and IPs match
    addresses. A pattern may carry a path prefix (`https://acme.com/api`).
    The most specific matching pattern wins: exact host > longer wildcard suffix, and a path
    prefix is more specific than its bare host. On a tie, OUT OF SCOPE wins. So an exact in-scope
    host survives a broad `*.acme.com` exclusion, and an exact exclusion beats a broad wildcard.
    A host no in-scope pattern matches is out of scope (third-party hosts found in JS, etc.).

FAIL CLOSED
    No parseable in-scope pattern -> code `no-scope`, never `in`. Callers decide what that means:
    the calling harness parks auto-fire but lets an operator override through; it never lets an `oos`
    verdict through, override or not.

Usage:
    scope.py show   --project-dir DIR [--json]
    scope.py check  --project-dir DIR URL [URL ...] [--json]   # exit 0 all in, 3 any out, 4 no scope
    scope.py filter --project-dir DIR [--passthrough-unscoped] < urls-or-hosts.txt
"""
from __future__ import annotations

import argparse
import fnmatch
import glob
import importlib.util
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_coverage():
    """coverage.py owns the scope.md heading/row heuristics; reuse them so the coverage gate and the
    fire gate never disagree about which section of scope.md is an exclusion list."""
    spec = importlib.util.spec_from_file_location("grimnir_coverage_for_scope",
                                                  os.path.join(_HERE, "coverage.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cov = _load_coverage()

# An innermost section heading that names notes rather than assets. In-scope tokens are never taken
# from these sections (an auth note naming a third-party IdP host must not put it in scope).
# Exclusions are still read from anywhere: over-excluding is safe, over-including is not.
_NON_ASSET_SECTION_RE = re.compile(
    r"cred|auth|token|proxy|rate|histor|\bnotes?\b|finding|lesson|strateg|recon|intel|evidence"
    r"|status|\blog\b|rule|\broe\b|engagement|constraint|contact|disclosure|reward",
    re.IGNORECASE,
)
_SCOPE_WORD_RE = re.compile(r"scope|asset|target", re.IGNORECASE)

_HOST_LABEL_RE = re.compile(r"^(?:\*|[a-z0-9*](?:[a-z0-9*_-]*[a-z0-9*])?)$")
_CIDR_RE = re.compile(r"^[0-9a-f:.]+/\d{1,3}$", re.IGNORECASE)

# H1 asset types that never name a network target.
_NON_NETWORK_ASSET_TYPES = frozenset({
    "GOOGLE_PLAY_APP_ID", "APPLE_STORE_APP_ID", "OTHER_APK", "OTHER_IPA", "TESTFLIGHT",
    "WINDOWS_APP_STORE_APP_ID", "SOURCE_CODE", "DOWNLOADABLE_EXECUTABLES", "HARDWARE",
    "SMART_CONTRACT", "AI_MODEL", "OTHER",
})


@dataclass(frozen=True)
class Pattern:
    raw: str
    source: str
    host: str = ""                    # lowercased host glob ("" for a network pattern)
    net: object = None                # ipaddress network, for CIDR / IP patterns
    path: str = ""                    # path prefix, "" = any path

    def match(self, host: str, path: str) -> int:
        """Specificity of a match (higher = more specific), or 0 for no match."""
        if self.path and not (path or "/").startswith(self.path):
            return 0
        bonus = (500 + len(self.path)) if self.path else 0
        if self.net is not None:
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                return 0
            if addr not in self.net:
                return 0
            return 1000 + self.net.prefixlen + bonus
        if "*" not in self.host:
            return (1000 + len(self.host) + bonus) if host == self.host else 0
        if self.host.startswith("*.") and "*" not in self.host[2:]:
            suffix = self.host[2:]
            return (len(suffix) + bonus) if host.endswith("." + suffix) else 0
        want, got = self.host.split("."), host.split(".")
        if len(want) != len(got):
            return 0
        if all(fnmatch.fnmatchcase(g, w) for w, g in zip(want, got)):
            return len(self.host.replace("*", "")) + bonus
        return 0


@dataclass(frozen=True)
class Verdict:
    in_scope: bool
    code: str          # in | oos | no-scope | bad-url
    reason: str
    host: str = ""

    def as_dict(self) -> dict:
        return {"in_scope": self.in_scope, "code": self.code, "reason": self.reason, "host": self.host}


def parse_pattern(token: str, source: str, allow_path: bool = True,
                  allow_loopback: bool = False) -> Pattern | None:
    """A scope token -> Pattern, or None when it is not a network target (an app id, an email,
    prose, a filename, a too-broad wildcard). Loopback is rejected unless `allow_loopback`: in
    scope.md it is a proxy or listener note, never a bounty asset; scope.json may opt in (lab
    targets, local test stubs). Private ranges stay allowed (internal-network engagements)."""
    t = re.sub(r"^\*\*(.+)\*\*$", r"\1", (token or "").strip())   # **bold** wrapper, not a `*.` glob
    t = t.strip("`").strip().rstrip(",;.").lower()
    if not t or " " in t or "@" in t or t in ("*", "*.*"):
        return None
    t = re.sub(r"^(?:https?|wss?|\*)://", "", t)
    if _CIDR_RE.match(t) or re.match(r"^[0-9.]+$", t) or (":" in t and re.match(r"^[0-9a-f:]+$", t)):
        return _net_pattern(t, token, source, allow_loopback)
    host, _, path = t.partition("/")
    path = ("/" + path) if path else ""
    path = re.sub(r"\*+$", "", path)
    if path in ("", "/"):
        path = ""
    elif not allow_path:
        return None
    host = re.sub(r":(?:\d+|\*)$", "", host).rstrip(".")
    if re.match(r"^[0-9.]+$", host) and not path:
        return _net_pattern(host, token, source, allow_loopback)
    if host == "localhost" or _cov._is_doc_filename(host):
        return None
    labels = host.split(".")
    if len(labels) < 2 or not all(_HOST_LABEL_RE.match(l) for l in labels):
        return None
    # The registrable tail must be concrete: `*.com`, `acme.*`, `*.*` are not a scope.
    fixed = [l for l in labels if "*" not in l]
    if "*" in labels[-1] or len(fixed) < 2 or (labels[0] == "*" and len(labels) < 3):
        return None
    if not re.match(r"^[a-z]{2,}$|^xn--", labels[-1]):
        return None
    return Pattern(raw=token.strip(), source=source, host=host, path=path)


def _net_pattern(t: str, token: str, source: str, allow_loopback: bool) -> Pattern | None:
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None
    if net.is_loopback and not allow_loopback:
        return None
    return Pattern(raw=token.strip(), source=source, net=net)


def split_url(url: str) -> tuple[str, str]:
    """(host, path) of a URL or bare host[/path]; host '' when unparseable."""
    u = (url or "").strip()
    if not u:
        return "", ""
    if "://" not in u:
        u = "http://" + u.lstrip("/")
    try:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return "", ""
    return host, parts.path or "/"


# ── source readers ────────────────────────────────────────────────────────────
def _structured_entries(doc) -> list[dict]:
    """Normalize the three HackerOne structured-scope shapes into a list of attribute dicts."""
    if isinstance(doc, dict):
        team = (doc.get("data") or {}).get("team") if isinstance(doc.get("data"), dict) else None
        if isinstance(team, dict):
            edges = (team.get("structured_scopes") or {}).get("edges") or []
            return [e.get("node") or {} for e in edges if isinstance(e, dict)]
        if isinstance(doc.get("data"), list):
            doc = doc["data"]
        elif isinstance(doc.get("structured_scopes"), list):
            doc = doc["structured_scopes"]
        else:
            return []
    if not isinstance(doc, list):
        return []
    out = []
    for item in doc:
        if isinstance(item, dict):
            out.append(item.get("attributes") if isinstance(item.get("attributes"), dict) else item)
    return out


def read_structured(path: str) -> tuple[list[Pattern], list[Pattern]]:
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return [], []
    inc, exc = [], []
    src = os.path.basename(path)
    for e in _structured_entries(doc):
        if str(e.get("asset_type") or "").upper() in _NON_NETWORK_ASSET_TYPES:
            continue
        eligible = e.get("eligible_for_submission")
        for tok in re.split(r"[,\s]+", str(e.get("asset_identifier") or "")):
            p = parse_pattern(tok, src)
            if p:
                (exc if eligible is False else inc).append(p)
    return inc, exc


def read_list(path: str) -> list[Pattern]:
    out = []
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    p = parse_pattern(line.split()[0], os.path.basename(path))
                    if p:
                        out.append(p)
    except OSError:
        pass
    return out


# A structured-scope pull writes the asset type as a tag leading the asset position: `- [URL]
# api.acme.example`, or the first cell of a table row. Optional backtick/bold wrapper included.
_ASSET_TAG_RE = re.compile(
    r"^((?:[-*+]\s+|\|)\s*)[`*]{0,2}\[\s*([A-Z][A-Z0-9_]*)\s*\][`*]{0,2}\s*"
)


def _strip_asset_tag(s: str) -> tuple[str, str]:
    """(the line with a leading asset-type tag removed, the TYPE), or (s, "") when there is none.
    The bullet/row marker is kept, so the remainder reads as an untagged line of the same shape."""
    m = _ASSET_TAG_RE.match(s)
    return (m.group(1) + s[m.end():], m.group(2)) if m else (s, "")


def _line_tokens(stripped: str, for_exclusion: bool) -> list[str]:
    """Candidate asset tokens on one scope.md line: backticked tokens; else a bare bullet's lead
    token or a bare table row's first two cells. An exclusion line takes backticks from any line
    shape (prose paragraphs under an out-of-scope heading list hosts that way). An in-scope table
    row is read from its first two cells only: the notes column routinely names other hosts.

    A leading `[TYPE]` asset tag is stripped before anything reads the token — left in place it is
    the bullet's lead token, which `parse_pattern` rejects on every line and the whole scope.md
    fails closed to no-scope. A non-network TYPE yields no tokens at all: the app id behind it
    would otherwise parse as a host (and a backticked id as a bogus exclusion)."""
    is_row = stripped.startswith("|")
    if is_row and re.match(r"^\|[\s:|-]+\|?$", stripped):
        return []
    body, tag = _strip_asset_tag(stripped)
    if tag in _NON_NETWORK_ASSET_TYPES:
        return []
    scan = body
    if is_row and not for_exclusion:
        scan = "|".join(body.strip("|").split("|")[:2])
    toks = [m.group(1) for m in _cov._BACKTICK_RE.finditer(scan)]
    if toks:
        return toks
    if re.match(r"^[-*+]\s+", body):
        lead = re.sub(r"^[-*+]\s+", "", body)
        lead = re.sub(r"^\*\*(.+?)\*\*", r"\1", lead)
        lead = re.split(r"[\s,;(—–]", lead, maxsplit=1)[0]
        return [lead] if lead else []
    if is_row:
        cells = [c.strip() for c in body.strip("|").split("|")]
        return [re.sub(r"^\*\*(.+?)\*\*$", r"\1", c).strip() for c in cells[:2] if c and " " not in c]
    return []


def read_scope_md(path: str) -> tuple[list[Pattern], list[Pattern]]:
    try:
        with open(path, errors="replace") as fh:
            text = fh.read()
    except OSError:
        return [], []
    inc, exc = [], []
    src = os.path.basename(path)
    section, oos_level = "", None
    for line in text.splitlines():
        hm = re.match(r"^(#+)\s*(.*)$", line)
        if hm:
            level, title = len(hm.group(1)), hm.group(2)
            if oos_level is not None and level <= oos_level:
                oos_level = None
            if _cov._OOS_HEADING_RE.search(title):
                oos_level = level
            section = title if level >= 2 else ""
            continue
        stripped = line.strip()
        if not stripped:
            continue
        row_oos = bool(_cov._OOS_ROW_RE.search(stripped)) and not _cov._OOS_NEGATED_RE.search(stripped)
        if oos_level is not None or row_oos:
            exc.extend(p for p in (parse_pattern(t, src) for t in _line_tokens(stripped, True)) if p)
            continue
        if not (stripped.startswith("|") or re.match(r"^[-*+]\s+", stripped)):
            continue
        if section and _NON_ASSET_SECTION_RE.search(section) and not _SCOPE_WORD_RE.search(section):
            continue
        # In-scope tokens: no bare host/path ("github.com/acme/cli" is a repo, not a web root).
        for t in _line_tokens(stripped, False):
            p = parse_pattern(t, src, allow_path=t.strip().lower().startswith("http"))
            if p:
                inc.append(p)
    return inc, exc


# ── the scope object ──────────────────────────────────────────────────────────
@dataclass
class Scope:
    project_dir: str
    in_patterns: list[Pattern] = field(default_factory=list)
    out_patterns: list[Pattern] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)   # scope.md exclusions read as references

    @property
    def ok(self) -> bool:
        return bool(self.in_patterns)

    def check(self, url: str) -> Verdict:
        host, path = split_url(url)
        if not host:
            return Verdict(False, "bad-url", f"no host in {url!r}")
        if not self.ok:
            return Verdict(False, "no-scope", "no parseable in-scope pattern for this engagement", host)
        best_in = max(((p.match(host, path), p) for p in self.in_patterns), key=lambda x: x[0])
        best_out = max(((p.match(host, path), p) for p in self.out_patterns), key=lambda x: x[0],
                       default=(0, None))
        if not best_in[0]:
            return Verdict(False, "oos", f"{host} matches no in-scope pattern", host)
        if best_out[0] and best_out[0] >= best_in[0]:
            p = best_out[1]
            return Verdict(False, "oos", f"{host} excluded by {p.raw} ({p.source})", host)
        p = best_in[1]
        return Verdict(True, "in", f"{host} in scope via {p.raw} ({p.source})", host)

    def summary(self) -> dict:
        return {"ok": self.ok, "sources": self.sources, "ignored_self_references": self.conflicts,
                "in_scope": sorted({p.raw for p in self.in_patterns}),
                "out_of_scope": sorted({p.raw for p in self.out_patterns})}


def _project_files(project_dir: str, patterns: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for base in (project_dir, os.path.join(project_dir, "recon")):
        for pat in patterns:
            found.extend(sorted(glob.glob(os.path.join(base, pat))))
    return sorted(set(found))


def load(project_dir: str, scope_md: str | None = None) -> Scope:
    """Build the engagement's Scope from every source on disk. Never raises."""
    s = Scope(project_dir=project_dir)
    machine_in: list[Pattern] = []

    for path in _project_files(project_dir, ("h1-structured-scopes*.json", "h1-scope*.json")):
        inc, exc = read_structured(path)
        if inc or exc:
            s.sources.append(path)
        machine_in += inc
        s.out_patterns += exc
    for path in _project_files(project_dir, ("*in-scope*.txt", "*inscope*.txt")):
        if re.search(r"mobile|app", os.path.basename(path), re.IGNORECASE):
            continue
        pats = read_list(path)
        if pats:
            s.sources.append(path)
        machine_in += pats
    for path in _project_files(project_dir, ("*out-of-scope*.txt", "*outofscope*.txt")):
        pats = read_list(path)
        if pats:
            s.sources.append(path)
        s.out_patterns += pats

    md = scope_md or os.path.join(project_dir, "scope.md")
    md_in, md_out = read_scope_md(md)
    if md_in or md_out:
        s.sources.append(md)
    # A pattern scope.md lists as in scope AND names under an out-of-scope heading is prose referring
    # back to the asset ("`*.acme.com` is a wildcard, but the exclusions below still govern"), not an
    # exclusion of the whole wildcard. Taken literally it would wipe out every unlisted subdomain.
    listed = {(p.host, p.path, p.net) for p in md_in}
    s.conflicts = sorted({p.raw for p in md_out if (p.host, p.path, p.net) in listed})
    s.out_patterns += [p for p in md_out if (p.host, p.path, p.net) not in listed]
    s.in_patterns += machine_in if machine_in else md_in

    override = os.path.join(project_dir, "scope.json")
    try:
        with open(override) as fh:
            doc = json.load(fh)
        s.in_patterns += [p for p in (parse_pattern(t, "scope.json", allow_loopback=True)
                                      for t in doc.get("in_scope") or []) if p]
        s.out_patterns += [p for p in (parse_pattern(t, "scope.json", allow_loopback=True)
                                       for t in doc.get("out_of_scope") or []) if p]
        s.sources.append(override)
    except (OSError, ValueError, AttributeError):
        pass
    return s


# ── CLI ───────────────────────────────────────────────────────────────────────
def _cmd_show(a) -> int:
    s = load(a.project_dir, a.scope_md)
    if a.json:
        print(json.dumps(s.summary(), indent=2))
        return 0 if s.ok else 4
    print(f"sources: {', '.join(s.sources) or '(none)'}")
    print(f"in scope ({len(s.in_patterns)}):")
    for raw in s.summary()["in_scope"]:
        print(f"  + {raw}")
    print(f"out of scope ({len(s.out_patterns)}):")
    for raw in s.summary()["out_of_scope"]:
        print(f"  - {raw}")
    if not s.ok:
        print("NO PARSEABLE IN-SCOPE PATTERN: every check returns no-scope (fail closed).")
    return 0 if s.ok else 4


def _cmd_check(a) -> int:
    s = load(a.project_dir, a.scope_md)
    verdicts = [(u, s.check(u)) for u in a.urls]
    if a.json:
        print(json.dumps([dict(v.as_dict(), url=u) for u, v in verdicts], indent=2))
    else:
        for u, v in verdicts:
            print(f"{'IN ' if v.in_scope else v.code.upper():<8} {u}  — {v.reason}")
    if not s.ok:
        return 4
    return 0 if all(v.in_scope for _, v in verdicts) else 3


def _cmd_filter(a) -> int:
    s = load(a.project_dir, a.scope_md)
    if not s.ok:
        if a.passthrough_unscoped:
            sys.stdout.write(sys.stdin.read())
            print("scope.py filter: no parseable scope — passing input through unfiltered",
                  file=sys.stderr)
            return 0
        print("scope.py filter: no parseable scope — emitting nothing (fail closed)", file=sys.stderr)
        return 4
    kept = dropped = 0
    for line in sys.stdin:
        item = line.strip()
        if not item:
            continue
        if s.check(item).in_scope:
            sys.stdout.write(item + "\n")
            kept += 1
        else:
            dropped += 1
    print(f"scope.py filter: kept {kept}, dropped {dropped} out of scope", file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="scope.py", description="Engagement scope gate")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("show", "check", "filter"):
        sp = sub.add_parser(name)
        sp.add_argument("--project-dir", required=True)
        sp.add_argument("--scope-md", help="scope.md path (default: PROJECT_DIR/scope.md)")
        if name in ("show", "check"):
            sp.add_argument("--json", action="store_true")
        if name == "check":
            sp.add_argument("urls", nargs="+")
        if name == "filter":
            sp.add_argument("--passthrough-unscoped", action="store_true",
                            help="with no parseable scope, pass input through instead of failing closed")
    a = p.parse_args()
    return {"show": _cmd_show, "check": _cmd_check, "filter": _cmd_filter}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
