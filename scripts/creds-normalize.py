#!/usr/bin/env python3
"""creds-normalize.py — turn human-authored freeform credential files into the structured
`credentials.jsonl` vault that lane synthesis / downstream tooling consume.

The operator drops creds for a program as `creds.txt` / `*creds.txt` (email/password lines,
`key: value` blocks, a pasted token). lane synthesis only reads `credentials.jsonl`, so those creds
were invisible to auto-BOLA synthesis. This normalizer parses
the freeform files DETERMINISTICALLY and emits `credentials.jsonl` records — token, object_id,
resource_ids (so owned-resource BOLA binds), and an identity/marker — matching the exact field vocab
lane synthesis's tenant_facts reads.

Two tiers, deterministic-first (Grimnir invariant A — zero-LLM by default):
  1. DETERMINISTIC parse of the common shapes (JSON/JSONL, key:value blocks, user:pass lines).
     This is what the autonomous pipeline uses — it never ships creds anywhere.
  2. LLM FALLBACK (--llm, opt-in) for a shape the parser does not recognize. Keeps everything in
     Claude (claude-sonnet-4-6) for now; the command is a single seam to swap for another model or a
     LOCAL model later. NOTE: --llm ships the cred file to a CLOUD model. All Grimnir creds are
     TEST accounts (free, no real PII), which lowers the risk, but it is real — see the roadmap
     item to revisit secret handling once a local model is available. --llm never runs unattended.

Usage:
  creds-normalize.py --project-dir DIR              # deterministic parse -> credentials.jsonl
  creds-normalize.py --project-dir DIR --llm        # + LLM fallback for files the parser can't read
  creds-normalize.py --project-dir DIR --json       # summary object; write nothing
  creds-normalize.py --project-dir DIR --dry-run    # print records with secret VALUES redacted
  creds-normalize.py --project-dir DIR --force      # merge into an existing credentials.jsonl
  creds-normalize.py selftest
"""
from __future__ import annotations

import argparse
import glob as _glob
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
LLM_UNAVAILABLE = "LLM fallback not available in this build"


def _load_ai_log():
    """The logged-LLM seam, imported only on the --llm path. None when this build does not ship it;
    the deterministic parser needs nothing from it."""
    try:
        import ai_log  # sibling module; path inserted above so importlib loads work too
        return ai_log
    except ImportError:
        return None


# Field vocab — KEEP IN STEP with lane synthesis / downstream tooling. Recognized keys normalize to a
# canonical name so downstream readers find them regardless of how the operator spelled them.
_TOKEN_KEYS = ("access_token", "token", "id_token", "bearer", "jwt", "session", "cookie")
_OBJECT_ID_KEYS = ("object_id", "user_id", "account_id", "user_uuid", "org_id", "tenant_id", "id")
_IDENTITY_MAP = {  # source key (normalized) -> canonical key
    "email": "email", "e_mail": "email",
    "username": "username", "user": "username", "login": "username", "handle": "username",
    "account": "account", "label": "account",
    "name": "name", "display_name": "name", "full_name": "name",
}
# Freeform files to scan (NOT credentials.jsonl — that is the output). Root + one level down.
_FREEFORM_GLOBS = ("*creds.txt", "creds*.txt", "*creds.json", "creds*.json", "creds.txt")
_HEADER_RE = re.compile(r"^\s*(\[.*\]|#.*|-{3,}.*|={3,}.*|\*{3,}.*)\s*$")
_KV_RE = re.compile(r"^\s*([A-Za-z][\w .-]*?)\s*[:=]\s*(.+?)\s*$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# email<sep>secret on one line: sep is ':', whitespace, or ' / '
_USERPASS_RE = re.compile(r"^\s*([^@\s]+@[^@\s:/]+\.[^@\s:/]+)\s*(?::|/|\s)\s*(\S.*?)\s*$")

DEFAULT_MODEL = "claude-sonnet-4-6"


# ── field mapping ───────────────────────────────────────────────────────────────
def _norm_key(k: str) -> str:
    return k.strip().lower().replace("-", "_").replace(" ", "_")


def _assign(rec: dict, key: str, val: str) -> None:
    """Place one key/value into a record under its canonical field. Order matters: account-id keys
    (user_id, org_id...) are object_ids, NOT resource ids, even though they end in _id."""
    val = val.strip().strip('"').strip("'")
    if not val:
        return
    k = _norm_key(key)
    if k in _TOKEN_KEYS:
        rec["access_token"] = val
    elif k in _OBJECT_ID_KEYS:
        rec["object_id"] = val
    elif k in ("password", "pass", "passwd", "pwd"):
        rec["password"] = val
    elif k in ("private_key", "client_secret", "api_key", "apikey", "secret", "secret_key"):
        rec[k] = val
    elif k.endswith("_id") or k.endswith("_uuid"):
        # An owned-resource id (device_id, device_id, order_id...) -> resource_ids[noun]. Singular
        # so lane synthesis's `resource_ids.get(noun) or .get(noun.rstrip('s'))` matches a plural route.
        noun = k[:-3] if k.endswith("_id") else k[:-5]
        rec.setdefault("resource_ids", {})[noun] = val
    elif k in _IDENTITY_MAP:
        rec[_IDENTITY_MAP[k]] = val
    elif k == "scarce":
        # Expensive-to-replace account (phone-verified, KYC, purchase-gated, invite-only, device-
        # bound): the calling harness parks every write that touches it.
        rec["scarce"] = val.lower() in ("true", "yes", "1", "y")
    else:
        rec[k] = val


def record_usable(rec: dict) -> bool:
    """A record must identify a tenant: a token, an object id, an explicit auth-header identity
    (two-part / non-Bearer auth), or an identity+password pair."""
    if not isinstance(rec, dict):
        return False
    if rec.get("access_token") or rec.get("object_id") or rec.get("auth_headers"):
        return True
    has_identity = any(rec.get(k) for k in ("email", "username", "account"))
    return bool(has_identity and rec.get("password"))


def _norm_auth_headers(v) -> list[str]:
    """A credential's explicit auth header set -> list of "Name: Value". Accepts a list of such strings
    or a {name: value} dict. Preserves a two-part auth identity (Basic + an app-id/tenant header) that a
    single access_token can't express, so lane synthesis can thread it into the attacker's lane headers."""
    if isinstance(v, dict):
        return [f"{k}: {val}" for k, val in v.items() if val not in (None, "")]
    if isinstance(v, list):
        return [h.strip() for h in v if isinstance(h, str) and ":" in h]
    return []


def _clean(rec: dict) -> dict:
    """Map an already-structured record (from JSON/LLM) through the canonical vocab."""
    out: dict = {}
    for k, v in rec.items():
        if k == "resource_ids" and isinstance(v, dict):
            out.setdefault("resource_ids", {}).update(
                {str(rk).lower(): str(rv) for rk, rv in v.items() if rv not in (None, "", [])})
        elif _norm_key(k) == "auth_headers":
            hdrs = _norm_auth_headers(v)
            if hdrs:
                out["auth_headers"] = hdrs
        elif _norm_key(k) == "cookie_domains" and isinstance(v, list):
            # Host scoping for a credential (lane synthesis's host_covered). Dropping the list would
            # unscope the record, so its key is sent to every host instead of only its own.
            doms = [str(d).strip().lower() for d in v if isinstance(d, str) and d.strip()]
            if doms:
                out["cookie_domains"] = doms
        elif isinstance(v, (str, int, float)) and str(v) != "":
            _assign(out, k, str(v))
    return out


# ── deterministic parser ────────────────────────────────────────────────────────
def _parse_json(text: str) -> list[dict] | None:
    """A whole-file JSON object or array of objects, else None (not JSON)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return [_clean(data)]
    if isinstance(data, list):
        return [_clean(r) for r in data if isinstance(r, dict)]
    return None


def _parse_jsonl(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return []          # not JSONL — bail to the kv/userpass parsers
        if isinstance(rec, dict):
            out.append(_clean(rec))
    return out


def _parse_kv_and_userpass(text: str) -> list[dict]:
    """key:value / key=value blocks (blank-line or header separated) AND bare email:password lines.
    A header (`[userA]`, `# B`, `---`) or blank line closes the current record."""
    records: list[dict] = []
    cur: dict = {}

    def flush():
        nonlocal cur
        if cur and record_usable(cur):
            records.append(cur)
        cur = {}

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            flush()
            continue
        if _HEADER_RE.match(line):
            flush()
            m = re.match(r"^\s*\[(.+)\]\s*$", line)  # [userA] seeds the account name
            if m:
                cur["account"] = m.group(1).strip()
            continue
        kv = _KV_RE.match(line)
        if kv and not _EMAIL_RE.match(kv.group(2).split()[0] if kv.group(2).split() else ""):
            _assign(cur, kv.group(1), kv.group(2))
            continue
        up = _USERPASS_RE.match(line)
        if up:
            # A standalone user:pass line is its own record (unless we're mid key:value block).
            if cur and not any(k in cur for k in ("email", "username")):
                _assign(cur, "email", up.group(1))
                _assign(cur, "password", up.group(2))
            else:
                flush()
                r: dict = {}
                _assign(r, "email", up.group(1))
                _assign(r, "password", up.group(2))
                if record_usable(r):
                    records.append(r)
            continue
        if kv:  # kv whose value looked email-ish but wasn't user:pass — keep it
            _assign(cur, kv.group(1), kv.group(2))
    flush()
    return records


def parse_freeform(text: str) -> list[dict]:
    """Deterministic extraction, trying the shapes in order of confidence. Never raises."""
    if not text or not text.strip():
        return []
    js = _parse_json(text)
    if js is not None:
        return [r for r in js if record_usable(r)]
    jl = _parse_jsonl(text)
    if jl:
        return [r for r in jl if record_usable(r)]
    return _parse_kv_and_userpass(text)


# ── LLM fallback (opt-in) ───────────────────────────────────────────────────────
_LLM_PROMPT = (
    "Extract every credential/account below into JSON Lines: one JSON object per account, on its "
    "own line, nothing else (no prose, no code fences). Use ONLY these keys when present: account, "
    "email, username, password, access_token, object_id, resource_ids (an object mapping a resource "
    "name to this account's id for it, e.g. {\"devices\": \"...\"}). Omit keys you don't find. Do "
    "not invent values.\n\nINPUT:\n"
)


def _llm_command(model: str) -> list[str]:
    """The fallback LLM invocation, WITHOUT the prompt (llm_extract appends it as the -p argument).
    Default keeps everything in Claude via the Grimnir wrapper: `claude --model <m> -p <prompt>`.
    Override the whole command via $GRIMNIR_CREDS_LLM_CMD to point at another model (`my-llm-cli -p`)
    or a LOCAL model later — this one line is the swap seam."""
    override = os.environ.get("GRIMNIR_CREDS_LLM_CMD", "").strip()
    if override:
        return override.split()
    return ["claude", "--model", model, "-p"]


def parse_llm_output(stdout: str) -> list[dict]:
    """Pull JSON objects out of the model's stdout (tolerant of stray prose / fences)."""
    out = []
    for line in (stdout or "").splitlines():
        line = line.strip().strip("`")
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            cleaned = _clean(rec)
            if record_usable(cleaned):
                out.append(cleaned)
    return out


def llm_extract(text: str, model: str) -> list[dict]:
    """Ship the file to the fallback model (prompt passed as the -p argument) and parse structured
    records back. Best-effort — any failure yields no records rather than raising. Routed through
    ai_log.invoke_llm so the call is logged (prompt is SENSITIVE here — it embeds the cred file — so
    only its size/hash is logged, never the text) with usage."""
    _ai_log = _load_ai_log()
    if _ai_log is None:
        raise RuntimeError(LLM_UNAVAILABLE)
    stdout, _rec = _ai_log.invoke_llm(_llm_command(model), _LLM_PROMPT + text,
                                      seam="creds-normalize", model=model,
                                      sensitive_prompt=True, timeout=120)
    return parse_llm_output(stdout)


# ── I/O ─────────────────────────────────────────────────────────────────────────
def discover_freeform(project_dir: str) -> list[str]:
    files, seen = [], set()
    for pat in _FREEFORM_GLOBS:
        for f in (_glob.glob(os.path.join(project_dir, pat))
                  + _glob.glob(os.path.join(project_dir, "*", pat))):
            if f not in seen and os.path.isfile(f):
                seen.add(f)
                files.append(f)
    return files


def _dedup_key(rec: dict) -> str:
    # header-auth records (API keys) carry no access_token; two keys for one user are two credentials
    headers = "|".join(sorted(h for h in rec.get("auth_headers") or [] if isinstance(h, str)))
    return rec.get("access_token") or headers or rec.get("object_id") or \
        f"{rec.get('email','')}|{rec.get('username','')}|{rec.get('account','')}"


def _redact(rec: dict) -> dict:
    """A copy with secret VALUES masked, for --dry-run eyeballing without leaking to the terminal."""
    secret = set(_TOKEN_KEYS) | {"password", "private_key", "client_secret", "api_key", "apikey",
                                 "secret", "secret_key"}
    def mask(v: str) -> str:
        return v[:2] + "***" + f"({len(v)} chars)"

    out = {}
    for k, v in rec.items():
        if k in secret and isinstance(v, str) and v:
            out[k] = mask(v)
        elif k in ("auth_headers", "headers", "cookies") and isinstance(v, list):
            # "Name: value" header lines carry the credential in the value half
            out[k] = [f"{h.split(':', 1)[0]}: {mask(h.split(':', 1)[1].strip())}"
                      if isinstance(h, str) and ":" in h else h for h in v]
        elif k in ("auth_headers", "headers", "cookies") and isinstance(v, dict):
            out[k] = {n: mask(x) if isinstance(x, str) and x else x for n, x in v.items()}
        else:
            out[k] = v
    return out


def normalize(project_dir: str, use_llm: bool, model: str) -> tuple[list[dict], dict]:
    """(records, summary). Deterministic first; --llm only for files the parser could not read."""
    summary = {"files": 0, "deterministic": 0, "llm": 0, "records": 0, "unparsed": []}
    records: list[dict] = []
    for path in discover_freeform(project_dir):
        summary["files"] += 1
        try:
            text = open(path, errors="ignore").read()
        except OSError:
            continue
        recs = parse_freeform(text)
        if recs:
            summary["deterministic"] += len(recs)
        elif use_llm and text.strip():
            print(f"[creds-normalize] LLM fallback on {os.path.basename(path)} "
                  f"-> {model} (CLOUD)", file=sys.stderr)
            recs = llm_extract(text, model)
            summary["llm"] += len(recs)
            if not recs:
                summary["unparsed"].append(os.path.basename(path))
        elif text.strip():
            summary["unparsed"].append(os.path.basename(path))
        for r in recs:
            r.setdefault("source", "creds-normalize")
            records.append(r)
    # Dedup, preserving first-seen order (deterministic).
    seen, deduped = set(), []
    for r in records:
        k = _dedup_key(r)
        if k and k not in seen:
            seen.add(k)
            deduped.append(r)
    summary["records"] = len(deduped)
    return deduped, summary


def write_vault(records: list[dict], out_path: str, force: bool) -> tuple[int, str]:
    """Write records to credentials.jsonl. Never clobbers a non-empty vault: without --force it
    refuses; with --force it MERGES (appends records whose dedup key is new), preserving what's
    there. Returns (added_count, message)."""
    existing: list[dict] = []
    if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        if not force:
            return 0, f"refusing to touch existing {out_path} (use --force to merge)"
        for line in open(out_path, errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                existing.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    have = {_dedup_key(r) for r in existing}
    added = [r for r in records if _dedup_key(r) not in have]
    # A captured token ages on a timer, so downstream tooling's creds-liveness check judges it by
    # freshness (captured_at). Stamp when the record enters the vault if it carries a token and
    # has no capture time yet; standing-only creds (no token) get no false freshness stamp.
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for r in added:
        if any(r.get(k) for k in _TOKEN_KEYS) and not r.get("captured_at"):
            r["captured_at"] = now
    # The vault holds passwords and live tokens: owner-only, whether created here or merged into.
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | (os.O_APPEND if existing else os.O_TRUNC), 0o600)
    os.chmod(out_path, 0o600)
    with os.fdopen(fd, "w") as fh:
        for r in added:
            fh.write(json.dumps(r) + "\n")
    return len(added), f"wrote {len(added)} new record(s) to {out_path}"


# ── CLI ─────────────────────────────────────────────────────────────────────────
def _cmd_normalize(a: argparse.Namespace) -> int:
    if not os.path.isabs(a.project_dir):
        print("--project-dir must be an absolute path", file=sys.stderr)
        return 2
    if a.llm and _load_ai_log() is None:
        print(f"creds-normalize: {LLM_UNAVAILABLE}; rerun without --llm (the deterministic parser "
              "needs no model)", file=sys.stderr)
        return 2
    records, summary = normalize(a.project_dir, a.llm, a.model)
    if a.json:
        print(json.dumps(summary, indent=2))
        return 0
    if a.dry_run:
        for r in records:
            print(json.dumps(_redact(r)))
        print(f"[creds-normalize] {summary['records']} record(s) from {summary['files']} file(s) "
              f"(deterministic={summary['deterministic']}, llm={summary['llm']}); wrote nothing",
              file=sys.stderr)
        return 0
    if not records:
        print(f"[creds-normalize] no usable records "
              f"(unparsed: {', '.join(summary['unparsed']) or 'none'})", file=sys.stderr)
        return 0
    out_path = a.out or os.path.join(a.project_dir, "credentials.jsonl")
    added, msg = write_vault(records, out_path, a.force)
    print(f"[creds-normalize] {msg}")
    return 0


def _cmd_selftest(_a: argparse.Namespace) -> int:
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        fails += 0 if cond else 1

    kv = parse_freeform("[userA]\nemail: a@x.io\npassword: p1\nobject_id: 1001\n"
                        "device_id: DB-A\n\n[userB]\nemail: b@x.io\npassword: p2\nobject_id: 1002")
    check("kv-block -> two records", len(kv) == 2)
    check("object_id parsed", kv[0].get("object_id") == "1001")
    check("owned resource id -> resource_ids[device]", kv[0].get("resource_ids") == {"device": "DB-A"})
    up = parse_freeform("a@x.io:secretpass\nb@x.io:otherpass")
    check("user:pass lines -> two records", len(up) == 2 and up[0]["password"] == "secretpass")
    js = parse_freeform('[{"account":"A","token":"T1","object_id":"1"}]')
    check("json array -> token normalized to access_token", js and js[0].get("access_token") == "T1")
    check("token record is usable", record_usable({"access_token": "x"}))
    check("bare email (no pass/id) is NOT usable", not record_usable({"email": "a@x.io"}))
    red = _redact({"access_token": "supersecretvalue", "email": "a@x.io"})
    check("redaction masks the token, keeps email", "***" in red["access_token"] and red["email"] == "a@x.io")
    red = _redact({"auth_headers": ["X-Api-Key: supersecretvalue"], "headers": {"Authorization": "Bearer abcdef"}})
    check("two API keys for one user stay two records",
          _dedup_key({"object_id": "1", "auth_headers": ["K: a"]}) != _dedup_key({"object_id": "1", "auth_headers": ["K: b"]}))
    check("redaction masks header values, keeps header names",
          red["auth_headers"][0].startswith("X-Api-Key: ") and "supersecret" not in red["auth_headers"][0]
          and "abcdef" not in red["headers"]["Authorization"])
    check("llm output parser tolerates fences/prose",
          len(parse_llm_output('```\n{"object_id":"9","token":"z"}\nchatter\n```')) == 1)
    print("ALL PASS" if not fails else f"{fails} FAIL")
    return 1 if fails else 0


def main() -> int:
    p = argparse.ArgumentParser(prog="creds-normalize.py",
                                description="Normalize freeform creds into credentials.jsonl")
    sub = p.add_subparsers(dest="cmd")
    sub.required = False

    p.add_argument("--project-dir", help="absolute engagement dir")
    p.add_argument("--out", help="output vault (default: <project-dir>/credentials.jsonl)")
    p.add_argument("--llm", action="store_true", help="LLM fallback for unparsed files (CLOUD; opt-in)")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"LLM fallback model (default {DEFAULT_MODEL})")
    p.add_argument("--json", action="store_true", help="print a summary object; write nothing")
    p.add_argument("--dry-run", action="store_true", help="print records (secrets redacted); write nothing")
    p.add_argument("--force", action="store_true", help="merge into an existing credentials.jsonl")

    st = sub.add_parser("selftest", help="pure-logic self-check")
    st.set_defaults(func=_cmd_selftest)

    a = p.parse_args()
    if getattr(a, "func", None):
        return a.func(a)
    if not a.project_dir:
        p.error("--project-dir is required")
    return _cmd_normalize(a)


if __name__ == "__main__":
    sys.exit(main())
