#!/usr/bin/env python3
"""
infoleak-confirm.py — the response-pattern oracle (Grimnir confirmation harness).

Fires ONE request (the target), derives a nonexistent-sibling CONTROL, scans both bodies against a
tiered, high-precision pattern library, and writes evidence/<id>/infoleak.json with a machine-readable
verdict. A leak is real only when a sensitive pattern is present in the TARGET and ABSENT from the
control — the control defeats the blanket-error-page / static-template false positive that would
otherwise flag every URL on the host. It complements authz-confirm's 4-way differential with a
response-pattern oracle.

The pattern library + control differential also fit path-traversal / LFI / SSTI: each reduces to
"a signature appeared in the response that no benign response carries." This file owns the matcher
and the control; a new injection point reuses them.

  infoleak-confirm.py --finding-id FINDING-007 --project-dir ~/workspace/prog \
     --method GET --url 'https://host/.git/config' [-H 'Authorization: Bearer T'] \
     [--control-url 'https://host/<known-404>'] [--body '{...}']

Verdict (from scan(target) minus scan(control)):
  confirmed    a HIGH-signal pattern (private key / etc-passwd / .git config / live cloud secret /
               env-file secret dump) present in the target and NOT in the control — unambiguous,
               nothing benign carries it.
  leak-likely  a MEDIUM-signal pattern (stack trace / SQL error / internal host / directory listing /
               a bare JWT) present in the target and not the control — a real candidate that needs a
               human to rule out own-data / expected-error before it ships.
  negative     no differential pattern — nothing the control did not also have.
  inconclusive the target request failed (status 0 / transport error): proved nothing.

Secret VALUES are never written to evidence — only the pattern name and a masked sample (Public
Repository Hygiene + never leak a live credential into an artifact). Zero LLM, fully deterministic.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module)
import egress as _egress  # noqa: E402  the program's egress proxy: every request rides it or refuses

# ── the pattern library ───────────────────────────────────────────────────────
# Each entry: (name, tier, compiled regex). HIGH = unambiguous; nothing benign legitimately carries
# it, so a differential hit is `confirmed`. MEDIUM = suspicious but could be own-data or an expected
# error, so it is `leak-likely` (a human rules it out). Precision over recall on purpose: a noisy
# oracle that cries leak on every 500 page is worse than a quiet one, because a false confirm can
# reach a report.
_HIGH = [
    ("private_key",     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("etc_passwd",      r"root:[^:\n]*:0:0:"),
    ("git_config",      r"\[core\][\s\S]{0,60}repositoryformatversion"),
    ("aws_access_key",  r"\bAKIA[0-9A-Z]{16}\b"),
    ("google_api_key",  r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("slack_token",     r"\bxox[baprs]-[0-9A-Za-z]{10,}"),
    ("stripe_live_key", r"\bsk_live_[0-9A-Za-z]{16,}\b"),
    ("github_token",    r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    ("env_secret_dump", r"(?im)^(?:DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY|"
                        r"API_SECRET|RAILS_MASTER_KEY|DJANGO_SECRET_KEY)\s*=\s*\S+"),
]
_MEDIUM = [
    ("stack_trace_py",   r"Traceback \(most recent call last\):"),
    ("stack_trace_java", r"\bat [\w.$]+\([\w]+\.java:\d+\)"),
    ("stack_trace_net",  r"\bat [\w.]+\.[\w<>]+\([^)]*\) in .+?:line \d+"),
    ("php_error",        r"(?:Fatal error|Parse error|Warning|Notice): .+? in .+? on line \d+"),
    ("sql_error",        r"(?:SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|"
                         r"Unclosed quotation mark|psql: |PG::\w+Error|SQLite3::)"),
    ("internal_host",    r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                         r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|localhost)"
                         r"[:/]|\b[\w-]+\.(?:internal|svc\.cluster\.local)\b"),
    ("dir_listing",      r"<title>Index of /|Directory listing for /"),
    ("jwt",              r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}"),
    ("spring_actuator",  r'"activeProfiles"[\s\S]{0,80}"propertySources"'),
]
PATTERNS = [(n, "high", re.compile(r)) for n, r in _HIGH] + \
           [(n, "medium", re.compile(r)) for n, r in _MEDIUM]


def _mask(value: str) -> str:
    """A recognizable but non-usable sample of a matched secret: first 4 + last 2, middle masked.
    Short values are fully masked. NEVER return the raw value into an artifact."""
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}{'*' * (len(v) - 6)}{v[-2:]}"


def scan(text: str) -> list[dict]:
    """Every pattern that fires in `text`, as {pattern, tier, sample(masked)}. Deterministic order
    (library order). One entry per pattern name (first match), so a body full of JWTs is one hit."""
    out, seen = [], set()
    for name, tier, rx in PATTERNS:
        if name in seen:
            continue
        m = rx.search(text or "")
        if m:
            out.append({"pattern": name, "tier": tier, "sample": _mask(m.group(0))})
            seen.add(name)
    return out


def classify_infoleak(target_status: int, target_body: str, control_body: str) -> tuple[str, str, list]:
    """Pure verdict. A pattern counts only if it is in the target and NOT in the control (the
    differential kills a site-wide template / error page that carries the signature everywhere).

    Positive-control guard mirrors authz-confirm: if the target request never returned a body
    (status 0 = transport error), we proved nothing — inconclusive, not negative, so a dead host
    never masquerades as 'no leak here'."""
    if target_status == 0:
        return "inconclusive", "target request failed (transport error) — nothing was tested", []
    t_hits = scan(target_body)
    c_names = {h["pattern"] for h in scan(control_body)}
    differential = [h for h in t_hits if h["pattern"] not in c_names]
    highs = [h for h in differential if h["tier"] == "high"]
    meds = [h for h in differential if h["tier"] == "medium"]
    if highs:
        names = ", ".join(h["pattern"] for h in highs)
        return "confirmed", f"high-signal leak present in target, absent from control: {names}", differential
    if meds:
        names = ", ".join(h["pattern"] for h in meds)
        return "leak-likely", f"medium-signal pattern present in target, absent from control: {names}", differential
    if t_hits and not differential:
        return "negative", "matched patterns also present in the control (site-wide, not a targeted leak)", []
    return "negative", "no sensitive pattern in the response", []


# ── request + control ─────────────────────────────────────────────────────────
def fetch(method: str, url: str, headers: list[str], body: str | None = None) -> dict:
    cmd = ["curl", "-sS", "-g", "-m", "20", "-o", "-", "-w", "\n__HTTP_%{http_code}__", "-X", method]
    cmd += _egress.curl_args(_egress.proxy())
    for h in headers:
        cmd += ["-H", h]
    if body is not None:
        cmd += ["--data-binary", body]
        if not any(h.lower().startswith("content-type:") for h in headers):
            cmd += ["-H", "Content-Type: application/json"]
    cmd += [url]
    _pace.before(url)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception as e:
        return {"status": 0, "len": 0, "sha": "", "body": "", "err": str(e)}
    status, rbody = 0, out
    if "\n__HTTP_" in out:
        rbody, _, tail = out.rpartition("\n__HTTP_")
        status = int(tail.replace("__", "").strip() or 0)
        _pace.after(url, status)
    b = rbody.encode("utf-8", "replace")
    return {"status": status, "len": len(b), "sha": hashlib.sha256(b).hexdigest()[:16], "body": rbody}


def derive_control_url(url: str) -> str:
    """A sibling that should NOT exist: insert a random segment into the path (or a random query key
    when the URL is query-only). The control's job is to carry the host's static template / global
    error page WITHOUT the targeted leak, so a match that survives the differential is target-specific."""
    nonce = "zz" + secrets.token_hex(4)
    m = re.match(r"^([a-zA-Z][\w+.-]*://[^/?#]+)(/[^?#]*)?(\?[^#]*)?", url)
    if not m:
        return url
    host, path, query = m.group(1), m.group(2) or "/", m.group(3) or ""
    path = path.rstrip("/") + "/" + nonce
    return f"{host}{path}{query}"


def main() -> int:
    ap = argparse.ArgumentParser(prog="infoleak-confirm.py")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True)
    ap.add_argument("--control-url", default=None,
                    help="explicit negative-control URL (default: a derived nonexistent sibling)")
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--body", default=None)
    a = ap.parse_args()
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env

    control_url = a.control_url or derive_control_url(a.url)
    target = fetch(a.method, a.url, a.headers, a.body)
    control = fetch(a.method, control_url, a.headers, a.body)
    verdict, why, differential = classify_infoleak(target["status"], target["body"], control["body"])

    rec = {
        "schema": 1, "finding_id": a.finding_id, "vuln_class": "infoleak",
        "verdict": verdict, "why": why, "ts": datetime.now(timezone.utc).isoformat(),
        "matched": differential,   # masked samples only — never the raw secret
        "differential": {
            "target": {"url": a.url, **{k: target[k] for k in ("status", "len", "sha")}},
            "control": {"url": control_url, **{k: control[k] for k in ("status", "len", "sha")}},
        },
        "negative_control": f"response-pattern differential (target vs nonexistent sibling): {why}",
    }
    d = os.path.join(a.project_dir, "evidence", a.finding_id)
    os.makedirs(d, exist_ok=True)
    json.dump(rec, open(os.path.join(d, "infoleak.json"), "w"), indent=2)
    print(json.dumps({k: rec[k] for k in ("finding_id", "verdict", "why")}, indent=2))
    print(f"wrote {d}/infoleak.json")
    if target["status"] == 0:
        print("  ! target request failed (transport error) — verdict inconclusive", file=sys.stderr)
    return 0


if __name__ == "__main__":
    main()
