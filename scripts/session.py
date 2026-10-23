#!/usr/bin/env python3
"""session.py — live sessions for our own test accounts: store, harvest, rotation-safe refresh.

Every authed lane consumes a session, and sessions rot: access tokens expire in minutes, refresh
tokens are often single-use, and the newest working pair usually exists only as a login response
buried in Caido history. This keeps one store per engagement and owns the refresh chain.

  harvest   scan Caido history (read-only SQLite) for the newest token mint per account and
            client; learn the refresh request from a captured refresh; flag a refresh token a
            later request already spent; learn the login request for login.py
  list      what the store holds and what state it's in (never prints a token)
  get       a live access token for one account: refreshes when it's near expiry and writes the
            rotated refresh token to disk BEFORE returning it
  refresh   refresh every entry (or one account) that is near expiry; prints states, not tokens
  check     liveness by use: one GET per live session to the engagement's who-am-I URL
  sync      copy live access tokens into credentials.jsonl, where downstream tooling
            reads them
  config    persist auth hosts (an auth domain outside scope.md, e.g. a separate SSO host)

STORE  $PROJECT_DIR/sessions.json, mode 600:
  accounts.<account>.clients.<client> = {access_token, refresh_token, id_token, token_type,
      access_exp, refresh_exp, claims (non-secret subset), minted_by, minted_at, source,
      refresh_state, rotates, chain[] (hashes of spent refresh tokens), inflight}
  recipes.refresh.<client>, recipes.login.<client> = templated requests learned from history
A refresh writes a pending marker, sends, appends the raw response to sessions.journal.jsonl
(fsynced, mode 600), then updates the store. A crash between the server rotating the token and
the store update is recovered from the journal on the next call, so the chain head is never lost.

Requests go out RoE-paced with roe.json's required headers. Refreshing or logging into our own
accounts is ordinary account use, so it isn't scope-gated; harvest only reads hosts that match
the engagement's scope domains or a configured auth host.

Exit codes for `get`: 0 token printed, 3 needs a login (no refresh path, or the refresh was
rejected or already spent), 4 no such account/client, 5 BLOCKED (with --login: a human step such
as an OTP or CAPTCHA). `get --login` / `refresh --login` fall back to login.py.
"""
from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import fcntl
import gzip
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import uuid
import zlib
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "confirm"))
try:
    import _pace  # noqa: E402  RoE pacing (also puts scripts/ on the path)
except Exception:  # pragma: no cover
    _pace = None
try:
    import roe as _roe
except Exception:  # pragma: no cover
    _roe = None
try:
    import scope as _scope
except Exception:  # pragma: no cover
    _scope = None
try:
    import activity as _activity
except Exception:  # pragma: no cover
    _activity = None
import egress as _egress  # noqa: E402 — the program's egress proxy: refresh/check ride it or raise

STORE = "sessions.json"
JOURNAL = "sessions.journal.jsonl"
DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
SAFE_CLAIMS = ("sub", "azp", "client_id", "cid", "aud", "iss", "exp", "iat", "scope", "scp", "email",
               "preferred_username", "token_use", "typ", "uid", "user_id", "tid", "org_id")
DROP_HEADERS = {"content-length", "host", "connection", "accept-encoding", "proxy-connection",
                "transfer-encoding", "te", "keep-alive", "upgrade", "if-none-match", "if-modified-since"}
STATIC_EXT = {"js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "map",
              "webp", "mp4", "mp3", "pdf", "zip", "wasm"}
MAX_BODY = 1_000_000
JOURNAL_KEEP_DAYS = 7


class NeedsLogin(Exception):
    pass


# ── small helpers ────────────────────────────────────────────────────────────
def now() -> float:
    return time.time()


def iso(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else ""


def thash(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()[:16] if tok else ""


def jwt_claims(tok: str) -> dict | None:
    """The payload of a JWT-shaped string, unverified. None for anything else."""
    if not isinstance(tok, str) or tok.count(".") != 2 or not tok.startswith("eyJ"):
        return None
    try:
        seg = tok.split(".")[1]
        data = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        out = json.loads(data)
        return out if isinstance(out, dict) else None
    except (ValueError, json.JSONDecodeError):
        return None


def safe_claims(c: dict | None) -> dict:
    return {k: c[k] for k in SAFE_CLAIMS if c and k in c}


def client_of(claims: dict | None) -> str:
    if not claims:
        return ""
    for k in ("azp", "client_id", "cid"):
        if claims.get(k):
            return str(claims[k])
    aud = claims.get("aud")
    if isinstance(aud, str) and aud:
        return aud
    return ""


# ── raw HTTP parsing (Caido stores wire bytes) ───────────────────────────────
def _dechunk(b: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(b):
        j = b.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(b[i:j].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return b
        if n == 0:
            break
        out += b[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return bytes(out)


def _decode_body(headers: list[tuple[str, str]], body: bytes) -> bytes:
    h = {k.lower(): v.lower() for k, v in headers}
    if "chunked" in h.get("transfer-encoding", ""):
        body = _dechunk(body)
    enc = h.get("content-encoding", "")
    try:
        if "gzip" in enc:
            body = gzip.decompress(body)
        elif "deflate" in enc:
            body = zlib.decompress(body) if body[:1] == b"\x78" else zlib.decompress(body, -15)
        elif "br" in enc:
            import brotli  # type: ignore
            body = brotli.decompress(body)
        elif "zstd" in enc:
            import zstandard  # type: ignore
            body = zstandard.ZstdDecompressor().decompress(body)
    except Exception:  # noqa: BLE001  undecodable stays raw; extraction just finds nothing
        pass
    return body


def parse_http(raw: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    """(start line, headers, decoded body) of a raw HTTP/1.x message."""
    head, _, body = raw.partition(b"\r\n\r\n")
    if not _:
        head, _, body = raw.partition(b"\n\n")
    lines = head.decode("latin-1").splitlines()
    start = lines[0] if lines else ""
    headers = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return start, headers, _decode_body(headers, body)


def hget(headers: list[tuple[str, str]], name: str) -> str:
    return next((v for k, v in headers if k.lower() == name.lower()), "")


# ── token extraction ─────────────────────────────────────────────────────────
_KEYS = {"access_token": "access", "accesstoken": "access", "token": "access", "jwt": "access",
         "auth_token": "access", "authtoken": "access", "session_token": "access", "sessiontoken": "access",
         "id_token": "id", "idtoken": "id", "refresh_token": "refresh", "refreshtoken": "refresh"}
_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9._~+/=-]{16,}$")
_GENERIC = {"token", "jwt", "auth_token", "authtoken", "session_token", "sessiontoken"}
# An exchange that plausibly mints a session. A bare "token" key elsewhere (a push, CSRF, embed, or
# paging token) is not a login, and an unrecognized subject is only stored from one of these.
AUTH_PATH = re.compile(r"login|log-in|signin|sign-in|sign_in|token|oauth|auth|session|refresh|otp|"
                       r"verify|callback|sso|saml|account/?connect", re.I)


def _num(v) -> int:
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    return int(v) if isinstance(v, str) and v.isdigit() else 0


def _walk(obj, found: dict, depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower().replace("-", "_")
            kind = _KEYS.get(key)
            if kind and isinstance(v, str) and _TOKEN_SHAPE.match(v) and kind not in found:
                if key in _GENERIC:
                    found.setdefault("_generic", []).append(v)
                else:
                    found[kind] = v
            elif str(k).lower() in ("expires_in", "expiresin") and _num(v) and "expires_in" not in found:
                found["expires_in"] = _num(v)
            elif str(k).lower() in ("refresh_expires_in", "refreshexpiresin") and _num(v):
                found.setdefault("refresh_expires_in", _num(v))
            elif str(k).lower() == "token_type" and isinstance(v, str):
                found.setdefault("token_type", v)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _walk(v, found, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:20]:
            _walk(v, found, depth + 1)


def extract_tokens(status: int, headers: list[tuple[str, str]], body: bytes, url: str = "") -> dict | None:
    """{access, refresh, id, expires_in, token_type, cookies} from a 2xx response, or None when it
    mints nothing. A Set-Cookie carrying a JWT counts (named *refresh* -> refresh, else access). A
    generic key ("token", "jwt") counts only beside a refresh token or lifetime, or on an auth-shaped
    URL. An id_token with no access_token is the bearer (Firebase-style)."""
    if not 200 <= status < 300:
        return None
    found: dict = {}
    if len(body) <= MAX_BODY and body.strip()[:1] in (b"{", b"["):
        try:
            _walk(json.loads(body), found)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    for k, v in headers:
        if k.lower() != "set-cookie":
            continue
        name, _, rest = v.partition("=")
        val = rest.split(";", 1)[0].strip()
        if jwt_claims(val):
            kind = "refresh" if "refresh" in name.lower() else "access"
            if kind not in found:
                found[kind] = val
                found[f"{kind}_cookie"] = name.strip()     # this token travels as a cookie, not a bearer
            found.setdefault("cookies", {})[name.strip()] = kind
    generic = found.pop("_generic", [])
    if generic and not found.get("access") and (found.get("refresh") or found.get("expires_in") or AUTH_PATH.search(url)):
        found["access"] = generic[0]
    if not found.get("access") and found.get("id"):
        found["access"] = found["id"]
    if not (found.get("access") or found.get("refresh")):
        return None
    return found


def _body_identity(body: bytes, ctype: str) -> dict:
    """email/username fields from a login request body (JSON or form)."""
    out: dict = {}
    try:
        txt = body.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return out
    pairs: list = []
    if "json" in ctype or txt.lstrip().startswith("{"):
        try:
            doc = json.loads(txt)
            stack = [doc]
            while stack:
                o = stack.pop()
                if isinstance(o, dict):
                    for k, v in o.items():
                        if isinstance(v, (dict, list)):
                            stack.append(v)
                        else:
                            pairs.append((str(k), v))
                elif isinstance(o, list):
                    stack.extend(o[:10])
        except json.JSONDecodeError:
            pass
    else:
        pairs = parse_qsl(txt, keep_blank_values=True)
    for k, v in pairs:
        kl = k.lower()
        if isinstance(v, str) and v:
            if "email" in kl and "@" in v:
                out.setdefault("email", v)
            elif kl in ("username", "user", "login", "user_name", "phone", "identifier"):
                out.setdefault("username", v)
    return out


_PASS_KEYS = re.compile(r"pass(word)?|pwd|secret", re.I)
_OTP_KEYS = re.compile(r"^(otp|code|otp_code|verification_code|mfa_code|totp|pin)$", re.I)


# ── store ────────────────────────────────────────────────────────────────────
def store_path(pd: str) -> str:
    return os.path.join(pd, STORE)


@contextlib.contextmanager
def locked(pd: str):
    """Exclusive lock across processes for every read-modify-write of the store."""
    with open(os.path.join(pd, STORE + ".lock"), "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def load(pd: str) -> dict:
    try:
        with open(store_path(pd)) as fh:
            st = json.load(fh)
    except (OSError, json.JSONDecodeError):
        st = {}
    st.setdefault("schema", 1)
    st.setdefault("accounts", {})
    st.setdefault("recipes", {"refresh": {}, "login": {}})
    st["recipes"].setdefault("refresh", {})
    st["recipes"].setdefault("login", {})
    st["recipes"].setdefault("exchange", {})
    st.setdefault("config", {})
    st["config"].setdefault("auth_hosts", [])
    st["config"].setdefault("aliases", {})
    return st


def _write_private(path: str, text: str) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def save(pd: str, st: dict) -> None:
    st["updated_at"] = iso(now())
    _write_private(store_path(pd), json.dumps(st, indent=2, sort_keys=True))


def journal_append(pd: str, rec: dict) -> None:
    path = os.path.join(pd, JOURNAL)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def journal_read(pd: str) -> list[dict]:
    out = []
    try:
        with open(os.path.join(pd, JOURNAL)) as fh:
            for line in fh:
                with contextlib.suppress(json.JSONDecodeError):
                    out.append(json.loads(line))
    except OSError:
        pass
    return out


def journal_prune(pd: str) -> None:
    cutoff = now() - JOURNAL_KEEP_DAYS * 86400
    rows = [r for r in journal_read(pd) if r.get("ts", 0) >= cutoff]
    path = os.path.join(pd, JOURNAL)
    if os.path.exists(path):
        _write_private(path, "".join(json.dumps(r) + "\n" for r in rows))


def entry_state(e: dict, min_ttl: int = 0) -> str:
    """live | expiring | expired | refreshable | dead — what `get` will be able to do."""
    t = now()
    exp = e.get("access_exp")
    if e.get("access_rejected"):
        return "refreshable" if e.get("refresh_token") and (e.get("refresh_state") or "fresh") == "fresh" else "dead"
    if not e.get("access_token") and e.get("cookie_header"):
        return "live"            # a cookie session: no expiry we can read, checked by use
    if e.get("access_token") and (exp is None or exp - t > min_ttl):
        return "live" if exp is None or exp - t > 300 else "expiring"
    rs = e.get("refresh_state") or ""
    if e.get("refresh_token") and rs in ("", "fresh") and not (e.get("refresh_exp") and e["refresh_exp"] < t):
        return "refreshable"
    return "dead" if e.get("access_token") or e.get("refresh_token") else "empty"


def apply_mint(e: dict, mint: dict, minted_at: float, minted_by: str, source: dict) -> dict:
    """Fold a token mint into a store entry. A mint without a refresh token keeps the old one
    (a non-rotating server); one with a new refresh token moves the chain head."""
    old_refresh = e.get("refresh_token") or ""
    acc = mint.get("access") or ""
    claims = jwt_claims(acc) or jwt_claims(mint.get("id") or "") or {}
    e["access_token"] = acc or e.get("access_token", "")
    if mint.get("id"):
        e["id_token"] = mint["id"]
    e["token_type"] = mint.get("token_type") or e.get("token_type") or "Bearer"
    ac = jwt_claims(acc)
    e["access_exp"] = (ac or {}).get("exp") or (minted_at + mint["expires_in"] if mint.get("expires_in") else None)
    if acc and not ac and not mint.get("expires_in"):
        e["access_exp"] = None   # opaque token, no lifetime given: unknown, checked by use
    new_refresh = mint.get("refresh") or ""
    if new_refresh and new_refresh != old_refresh:
        if old_refresh:
            e.setdefault("chain", []).append(thash(old_refresh))
            e["chain"] = e["chain"][-20:]
            e["rotates"] = True
        e["refresh_token"] = new_refresh
        rc = jwt_claims(new_refresh)
        e["refresh_exp"] = (rc or {}).get("exp") or (
            minted_at + mint["refresh_expires_in"] if mint.get("refresh_expires_in") else None)
        e["refresh_state"] = "fresh"
    elif new_refresh and old_refresh and minted_by == "refresh":
        e["rotates"] = False
        e["refresh_state"] = "fresh"
    elif minted_by == "refresh" and old_refresh and not new_refresh:
        e["rotates"] = False
    if claims:
        e["claims"] = safe_claims(claims)
    if mint.get("cookies"):
        e["cookie_names"] = mint["cookies"]
    if acc:
        if mint.get("access_cookie"):
            e["access_cookie"] = mint["access_cookie"]
        else:
            e.pop("access_cookie", None)
    e["minted_by"], e["minted_at"], e["source"] = minted_by, minted_at, source
    e.pop("inflight", None)
    e.pop("access_rejected", None)
    return e


# ── accounts ─────────────────────────────────────────────────────────────────
def vault_index(pd: str) -> list[tuple[str, set]]:
    """[(account label, identifiers)] from credentials.jsonl: email, username, ids, JWT sub."""
    out = []
    path = os.path.join(pd, "credentials.jsonl")
    try:
        lines = open(path, errors="ignore").read().splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        label = next((str(r[k]) for k in ("account", "label", "username", "email", "name") if r.get(k)), "")
        ids = {str(r[k]).lower() for k in ("email", "username", "user", "login", "account", "label",
                                            "sub", "object_id", "user_id", "account_id") if r.get(k)}
        for k in ("token", "access_token", "id_token", "refresh_token"):
            c = jwt_claims(str(r.get(k) or ""))
            if c:
                ids |= {str(c[x]).lower() for x in ("sub", "email", "preferred_username", "uid") if c.get(x)}
        if label:
            out.append((label, ids))
    return out


def match_account(index: list[tuple[str, set]], idents: set) -> str:
    idents = {str(i).lower() for i in idents if i}
    for label, ids in index:
        if ids & idents:
            return label
    return ""


# ── Caido history (read-only) ────────────────────────────────────────────────
def caido_data_dir() -> str:
    return os.environ.get("CAIDO_DATA_DIR") or os.path.expanduser("~/.local/share/caido")


def caido_projects(data_dir: str, names: list[str] | None = None) -> list[tuple[str, str]]:
    """[(name, dir)] newest first, optionally filtered by name or id."""
    out = []
    pdb = os.path.join(data_dir, "projects.db")
    rows = []
    if os.path.exists(pdb):
        with contextlib.suppress(sqlite3.Error):
            con = sqlite3.connect(f"file:{pdb}?mode=ro", uri=True)
            rows = con.execute("SELECT id, name FROM projects").fetchall()
            con.close()
    names_by_id = {r[0]: r[1] for r in rows}
    root = os.path.join(data_dir, "projects")
    for pid in os.listdir(root) if os.path.isdir(root) else []:
        d = os.path.join(root, pid)
        if os.path.exists(os.path.join(d, "database.caido")):
            name = names_by_id.get(pid, pid)
            if not names or name in names or pid in names:
                out.append((name, d))
    out.sort(key=lambda x: os.path.getmtime(os.path.join(x[1], "database.caido")), reverse=True)
    return out


def scope_domains(pd: str, extra: list[str]) -> list[str]:
    """Base domains to harvest from: the scope's host patterns reduced to their registrable
    domain, plus configured auth hosts."""
    doms = set()
    if _scope is not None:
        with contextlib.suppress(Exception):
            for p in _scope.load(pd).in_patterns:
                h = (p.host or "").lstrip("*.").strip(".")
                if h and "*" not in h and not _PACKAGE_ID.match(h):
                    doms.add(base_domain(h))
    return sorted(doms | {h.lower() for h in extra if h})


_PACKAGE_ID = re.compile(r"^(com|org|net|io|app|de|uk|co)\.[a-z0-9_]+\.[a-z0-9_.]+$", re.I)  # an app id, not a host


def base_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def iter_exchanges(proj_dir: str, domains: list[str], since_ms: int):
    """(id, created_ms, host, port, tls, method, path, query, status, req_raw, resp_raw) ascending,
    for requests to the given domains with a response, skipping static files."""
    if not domains:
        return
    con = sqlite3.connect(f"file:{os.path.join(proj_dir, 'database.caido')}?mode=ro", uri=True)
    con.execute("ATTACH DATABASE ? AS raw", (f"file:{os.path.join(proj_dir, 'database_raw.caido')}?mode=ro",))
    cond = " OR ".join(["(r.host = ? OR r.host LIKE ?)"] * len(domains))
    args: list = []
    for d in domains:
        args += [d, "%." + d]
    q = f"""SELECT r.id, r.created_at, r.host, r.port, r.is_tls, r.method, r.path, r.query,
                   resp.status_code, rq.data, rs.data, IFNULL(r.file_extension, '')
            FROM requests r JOIN responses resp ON resp.id = r.response_id
            JOIN raw.requests_raw rq ON rq.id = r.raw_id
            JOIN raw.responses_raw rs ON rs.id = resp.raw_id
            WHERE r.created_at >= ? AND r.method NOT IN ('OPTIONS', 'HEAD') AND resp.length <= ?
              AND ({cond}) ORDER BY r.created_at, r.id"""
    try:
        for row in con.execute(q, [since_ms, MAX_BODY] + args):
            ext = (row[11] or os.path.splitext(row[6] or "")[1].lstrip(".")).lower()
            if ext in STATIC_EXT:
                continue
            yield row[:11]
    finally:
        con.close()


def _template(method: str, url: str, headers: list[tuple[str, str]], body: bytes,
              subs: dict[str, str]) -> dict:
    """A replayable request with each secret value replaced by its {placeholder}."""
    txt = body.decode("utf-8", "replace")
    hs = []
    for k, v in headers:
        if k.lower() in DROP_HEADERS:
            continue
        hs.append([k, v])
    for val, ph in sorted(subs.items(), key=lambda x: -len(x[0])):
        if len(val) < 4:
            continue
        url = url.replace(val, ph)
        txt = txt.replace(val, ph)
        for h in hs:
            h[1] = h[1].replace(val, ph)
    return {"method": method, "url": url, "headers": hs, "body": txt}


def _url(host: str, port: int, tls: int, path: str, query: str) -> str:
    scheme = "https" if tls else "http"
    default = 443 if tls else 80
    hp = host if port in (default, 0, None) else f"{host}:{port}"
    return f"{scheme}://{hp}{path}{'?' + query if query else ''}"


def harvest(pd: str, projects: list[tuple[str, str]], domains: list[str], since_days: int = 30,
            dry_run: bool = False, log=print) -> dict:
    """Fold Caido token mints into the store. Returns a summary (no secrets)."""
    index = vault_index(pd)
    aliases = load(pd)["config"].get("aliases", {})
    since_ms = int((now() - since_days * 86400) * 1000)
    mints: dict[tuple, dict] = {}          # (account, client) -> newest mint
    refresh_owner: dict[str, tuple] = {}   # refresh token -> (account, client)
    spent: dict[str, dict] = {}            # refresh token -> {at, status, id, minted}
    recipes_refresh: dict[str, dict] = {}
    recipes_login: dict[str, dict] = {}
    last_access: dict[tuple, str] = {}
    cookie_owner: dict[str, tuple] = {}    # live session-cookie token -> ((account, client), cookie name)
    recipes_exchange: dict[str, dict] = {}
    host_clients: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    recent: collections.deque = collections.deque(maxlen=40)   # for an OTP login's send-code step
    seen = 0
    for pname, pdir in projects:
        try:
            rows = iter_exchanges(pdir, domains, since_ms)
            for (rid, ms, host, port, tls, method, path, query, status, rq, rs) in rows:
                seen += 1
                _sl, rqh, rqb = parse_http(bytes(rq))
                _sl2, rsh, rsb = parse_http(bytes(rs))
                url = _url(host, port, tls, path, query)
                recent.append({"rid": rid, "ms": ms, "method": method, "url": url, "rqh": rqh, "rqb": rqb,
                               "status": status, "rsb": rsb})
                rq_text = rqb.decode("utf-8", "replace") + "\n" + "\n".join(v for _, v in rqh) + "\n" + url
                used = [t for t in refresh_owner if t in rq_text]
                bearer = hget(rqh, "authorization").split(" ", 1)
                if 200 <= status < 300 and len(bearer) == 2 and bearer[0].lower() == "bearer":
                    hc = client_of(jwt_claims(bearer[1].strip()))
                    if hc:
                        host_clients[host][hc] += 1     # this host accepted this client's bearer
                mint = extract_tokens(status, rsh, rsb, url)
                for t in used:
                    spent[t] = {"at": ms / 1000, "status": status, "id": rid, "minted": bool(mint)}
                if not mint:
                    continue
                at = ms / 1000
                acc_claims = jwt_claims(mint.get("access") or "") or jwt_claims(mint.get("id") or "") or {}
                client = client_of(acc_claims) or client_of(jwt_claims(mint.get("refresh") or "")) or "default"
                account = ""
                if used:
                    account, client0 = refresh_owner[used[0]]
                    client = client_of(acc_claims) or client0
                cookie_hdr = hget(rqh, "cookie")
                via = next(((t, o) for t, o in cookie_owner.items() if cookie_hdr and t in cookie_hdr), None)
                exchanged = False
                if not used and via and via[1][0][1] != client and mint.get("access") != via[0]:
                    # Another client's token minted for a request that carried this account's session
                    # cookie: a cross-client exchange (a web session cookie -> an API bearer).
                    account = via[1][0][0]
                    exchanged = True
                if not account:
                    body_id = _body_identity(rqb, hget(rqh, "content-type"))
                    idents = {acc_claims.get(k) for k in ("sub", "email", "preferred_username", "uid")}
                    idents |= set(body_id.values())
                    account = match_account(index, idents)
                    if not account and AUTH_PATH.search(path):
                        account = (acc_claims.get("email") or body_id.get("email") or body_id.get("username")
                                   or (f"sub:{acc_claims['sub']}" if acc_claims.get("sub") else ""))
                    elif not account:
                        # a token for a subject we already labeled from its login keeps that label
                        account = next((k[0] for k, m in mints.items() if (jwt_claims(m["mint"].get("access") or "")
                                        or {}).get("sub") == acc_claims.get("sub") and acc_claims.get("sub")), "")
                account = aliases.get(account, account)
                if not account:
                    continue
                src = {"caido_project": pname, "request_id": rid, "url": url.split("?")[0]}
                key = (account, client)
                prev = mints.get(key)
                if not prev or at >= prev["at"]:
                    mints[key] = {"at": at, "mint": mint, "source": src,
                                  "via": "refresh" if used else "exchange" if exchanged else "login",
                                  "prev_refresh": used[0] if used else ""}
                if used:
                    # rotation is learned from the refresh itself: a new token back means single-use
                    mints[key]["rotates"] = bool(mint.get("refresh")) and mint["refresh"] != used[0]
                if mint.get("refresh"):
                    refresh_owner[mint["refresh"]] = key
                if exchanged and (method == "GET" or AUTH_PATH.search(path)):
                    src_tok, ((_a, src_client), src_cookie) = via
                    hs = [(k, v) for k, v in rqh if k.lower() != "cookie"]
                    jar = [c.strip() for c in cookie_hdr.split(";") if c.strip()]
                    jar = [c for c in jar if not jwt_claims(c.partition("=")[2]) and not c.startswith(src_cookie + "=")]
                    hs.append(("Cookie", "; ".join(jar + [f"{src_cookie}={src_tok}"])))
                    recipes_exchange[client] = {**_template(method, url, hs, rqb, {src_tok: "{source_token}"}),
                                                "source_client": src_client, "source_cookie": src_cookie,
                                                "learned_from": src, "learned_at": iso(at)}
                if used:
                    subs = {used[0]: "{refresh_token}"}
                    old = last_access.get(refresh_owner[used[0]], "")
                    if old:
                        subs[old] = "{access_token}"
                    recipes_refresh[client] = {**_template(method, url, rqh, rqb, subs),
                                               "learned_from": src, "learned_at": iso(at)}
                else:
                    ctype = hget(rqh, "content-type")
                    tpl = _login_template(method, url, rqh, rqb, ctype, list(recent)[:-1])
                    if tpl:
                        recipes_login[client] = {**tpl, "learned_from": src, "learned_at": iso(at)}
                if mint.get("access"):
                    last_access[key] = mint["access"]
                if mint.get("access_cookie") and SESSION_COOKIE.search(mint["access_cookie"]):
                    cookie_owner[mint["access"]] = (key, mint["access_cookie"])
        except sqlite3.Error as e:
            log(f"[harvest] {pname}: {e}")
    summary = {"exchanges_read": seen, "domains": domains, "projects": [p for p, _ in projects],
               "entries": [], "refresh_recipes": sorted(recipes_refresh), "login_recipes": sorted(recipes_login),
               "exchange_recipes": sorted(recipes_exchange)}
    lock = locked(pd) if not dry_run else contextlib.nullcontext()
    with lock:
        st = load(pd)
        for (account, client), m in sorted(mints.items()):
            e = st["accounts"].setdefault(account, {"clients": {}})["clients"].setdefault(client, {})
            action = "kept-newer-store"
            if (e.get("minted_at") or 0) <= m["at"]:
                apply_mint(e, m["mint"], m["at"], f"caido-{m['via']}", m["source"])
                if "rotates" in m:
                    e["rotates"] = m["rotates"]
                action = "updated"
            rt = e.get("refresh_token") or ""
            sp = spent.get(rt)
            if rt and sp and sp["at"] > (e.get("minted_at") or 0):
                # A later request carried this refresh token. If it minted, the newer pair belongs to
                # whoever made that request (we kept it above when it was ours); if it was rejected or
                # its response wasn't a mint, a rotating server has already burned this token.
                e["refresh_state"] = "spent" if sp["minted"] else f"spent-failed:{sp['status']}"
            summary["entries"].append({"account": account, "client": client, "action": action,
                                       "state": entry_state(e), "minted_at": iso(e.get("minted_at")),
                                       "refresh_state": e.get("refresh_state", "")})
        for c, r in recipes_refresh.items():
            st["recipes"]["refresh"][c] = r
        for c, r in recipes_login.items():
            st["recipes"]["login"][c] = r
        for c, r in recipes_exchange.items():
            st["recipes"]["exchange"][c] = r
        hcmap = st["config"].setdefault("host_clients", {})
        for h, cnt in host_clients.items():
            hcmap[h] = cnt.most_common(1)[0][0]
        if not dry_run:
            save(pd, st)
    if not dry_run and _activity is not None and summary["entries"]:
        _activity.emit(pd, "cred", "session", f"session harvest: {len(summary['entries'])} account/client "
                       f"entries from {len(projects)} Caido project(s)", verdict="n/a")
    return summary


def _flat_strings(doc, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(doc, dict):
        for k, v in doc.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, str):
                out[key] = v
            elif isinstance(v, (dict, list)):
                out.update(_flat_strings(v, key))
    elif isinstance(doc, list):
        for i, v in enumerate(doc[:10]):
            out.update(_flat_strings(v, f"{prefix}.{i}" if prefix else str(i)))
    return out


def _body_pairs(body: bytes, ctype: str) -> list | None:
    txt = body.decode("utf-8", "replace")
    if "json" in ctype or txt.lstrip().startswith("{"):
        try:
            return list(_flat_strings(json.loads(txt)).items())
        except json.JSONDecodeError:
            return None
    return parse_qsl(txt, keep_blank_values=True)


def _login_template(method: str, url: str, headers, body: bytes, ctype: str,
                    recent: list[dict] | None = None) -> dict | None:
    """The login request as a template: identity -> {username}, password -> {password}, an OTP
    field -> {otp} (and requires_otp). For an OTP login, the send-code request just before it
    becomes `pre`, and any value the verify step echoes from pre's response (a challenge id)
    becomes {pre.<key>}. None when the body carries no credential-looking field."""
    pairs = _body_pairs(body, ctype)
    if pairs is None:
        return None
    subs: dict[str, str] = {}
    requires_otp = False
    for k, v in pairs:
        leaf = str(k).rsplit(".", 1)[-1]
        if not isinstance(v, str) or not v:
            continue
        if _PASS_KEYS.search(leaf) and "token" not in leaf.lower():
            subs[v] = "{password}"
        elif _OTP_KEYS.match(leaf):
            subs[v] = "{otp}"
            requires_otp = True
    ident = _body_identity(body, ctype)
    for v in ident.values():
        subs.setdefault(v, "{username}")
    if not any(p in ("{password}", "{otp}") for p in subs.values()):
        return None
    pre, chain = None, []
    if requires_otp and recent:
        otp_vals = [v for v, p in subs.items() if p == "{otp}"]
        idv = list(ident.values())
        host = urlsplit(url).hostname
        btxt = body.decode("utf-8", "replace") + url + " ".join(v for _, v in headers)
        for ex in reversed(recent):
            text = ex["rqb"].decode("utf-8", "replace")
            if not (200 <= ex["status"] < 300) or urlsplit(ex["url"]).hostname != host or ex["method"] == "GET":
                continue
            if any(o in text for o in otp_vals):
                continue
            try:
                echoed = _flat_strings(json.loads(ex["rsb"]))
            except (json.JSONDecodeError, UnicodeDecodeError):
                echoed = {}
            echo = [k for k, v in echoed.items() if len(v) >= 8 and v in btxt and v not in subs]
            sent_identity = bool(_body_identity(ex["rqb"], hget(ex["rqh"], "content-type")))
            if echo or (idv and any(v in text for v in idv)) or (sent_identity and not idv):
                pre = ex
                for k in echo:
                    subs[echoed[k]] = "{pre." + k + "}"
                chain = echo
                break
    tpl = _template(method, url, headers, body, subs)
    tpl["requires_otp"] = requires_otp
    tpl["kind"] = "http"
    if pre is not None:
        pre_ident = _body_identity(pre["rqb"], hget(pre["rqh"], "content-type")) or ident
        tpl["pre"] = _template(pre["method"], pre["url"], pre["rqh"], pre["rqb"],
                               {v: "{username}" for v in pre_ident.values()})
        tpl["pre"]["chain"] = chain
    return tpl


# ── live requests ────────────────────────────────────────────────────────────
# Per-request headers a replay must not reuse: a repeated idempotency key can return the server's
# cached response to the ORIGINAL request (the old tokens), and a repeated request id is a tell.
UNIQUE_HEADER = re.compile(r"idempotency|request-?id|correlation-?id|^traceparent$|^x-amzn-trace-id$", re.I)


def render(tpl: dict, values: dict[str, str]) -> dict:
    def sub(s: str) -> str:
        for k, v in values.items():
            s = s.replace("{" + k + "}", v)
        return s
    headers = []
    for k, v in tpl.get("headers", []):
        if UNIQUE_HEADER.search(k) and re.fullmatch(r"[0-9a-fA-F-]{16,}", v or ""):
            v = str(uuid.uuid4()) if "-" in v else uuid.uuid4().hex
        headers.append([k, sub(v)])
    return {"method": tpl["method"], "url": sub(tpl["url"]), "headers": headers, "body": sub(tpl.get("body", ""))}


def send(pd: str, req: dict, timeout: float = 30) -> tuple[int, list[tuple[str, str]], bytes]:
    hs = dict((k, v) for k, v in req["headers"])
    if _roe is not None:
        with contextlib.suppress(Exception):
            for line in _roe.required_header_lines(pd):
                k, v = line.split(":", 1)
                hs[k.strip()] = v.strip()
    if not any(k.lower() == "user-agent" for k in hs):
        hs["User-Agent"] = DEFAULT_UA
    data = req["body"].encode() if req.get("body") else None
    r = urllib.request.Request(req["url"], data=data, method=req["method"], headers=hs)
    if _pace is not None:
        _pace.before(req["url"])
    try:
        # Own-account request, operator-learned: it rides the program's egress proxy like every
        # other live request (EgressError propagates — a session must not be refreshed direct).
        resp = _egress.opener(proxy=_egress.proxy(pd)).open(r, timeout=timeout)  # noqa: S310
    except urllib.error.HTTPError as e:
        resp = e
    except (urllib.error.URLError, OSError, ValueError):
        return 0, [], b""
    body = resp.read(MAX_BODY)
    headers = list(resp.headers.items()) if resp.headers else []
    status = getattr(resp, "status", None) or resp.code
    if _pace is not None:
        _pace.after(req["url"], status)
    return status, headers, _decode_body(headers, body)


def _recover(pd: str, st: dict, account: str, client: str, e: dict) -> bool:
    """Apply a journaled refresh response the store never absorbed (crash after send)."""
    inf = e.get("inflight")
    if not inf:
        return False
    for r in reversed(journal_read(pd)):
        if r.get("head") == inf.get("head") and r.get("ts", 0) >= inf.get("ts", 0) - 1:
            mint = extract_tokens(r.get("status", 0), [tuple(h) for h in r.get("headers", [])],
                                  r.get("body", "").encode(), r.get("url", ""))
            if mint:
                apply_mint(e, mint, r["ts"], "refresh", {"recovered_from": JOURNAL})
                save(pd, st)
                return True
            break
    e.pop("inflight", None)
    save(pd, st)
    return False


def pick(st: dict, account: str, client: str = "") -> tuple[str, dict]:
    a = st["accounts"].get(account)
    if not a or not a.get("clients"):
        raise KeyError(account)
    if client:
        if client not in a["clients"]:
            raise KeyError(f"{account}/{client}")
        return client, a["clients"][client]
    c = max(a["clients"], key=lambda k: a["clients"][k].get("minted_at") or 0)
    return c, a["clients"][c]


def refresh_entry(pd: str, account: str, client: str = "", min_ttl: int = 120, force: bool = False) -> dict:
    """Make the entry live, refreshing when needed. The lock covers read-refresh-write, so two
    callers never spend the same single-use refresh token."""
    if _pace is not None:
        _pace.init(pd)
    with locked(pd):
        st = load(pd)
        if client and account in st["accounts"] and client not in st["accounts"][account]["clients"] \
                and client in st["recipes"]["exchange"]:
            st["accounts"][account]["clients"][client] = {}
        client, e = pick(st, account, client)
        _recover(pd, st, account, client, e)
        if not force and e.get("access_token") and not e.get("access_rejected") and \
                (e.get("access_exp") is None or e["access_exp"] - now() > min_ttl):
            e["last_used"] = now()
            save(pd, st)
            return e
        if entry_state(e) != "refreshable" and not (force and e.get("refresh_token")):
            ex = st["recipes"]["exchange"].get(client)
            src = st["accounts"][account]["clients"].get((ex or {}).get("source_client", ""), {})
            if ex and entry_state(src) in ("live", "expiring") and src.get("access_token"):
                return _exchange(pd, st, account, client, e, ex, src)
            raise NeedsLogin(f"{account}/{client}: no usable refresh token "
                             f"({e.get('refresh_state') or 'none'}); a login is needed")
        recipe = st["recipes"]["refresh"].get(client)
        if not recipe:
            raise NeedsLogin(f"{account}/{client}: no refresh request learned for this client; "
                             "harvest a history that includes one refresh, or log in")
        rt = e["refresh_token"]
        req = render(recipe, {"refresh_token": rt, "access_token": e.get("access_token", "")})
        e["inflight"] = {"head": thash(rt), "ts": now()}
        save(pd, st)
        status, headers, body = send(pd, req)
        journal_append(pd, {"ts": now(), "account": account, "client": client, "head": thash(rt),
                            "url": req["url"], "status": status, "headers": headers,
                            "body": body.decode("utf-8", "replace")})
        mint = extract_tokens(status, headers, body, req["url"])
        if not mint:
            e.pop("inflight", None)
            e["refresh_state"] = f"rejected:{status}"
            save(pd, st)
            _emit(pd, f"session refresh rejected for {account}/{client} (HTTP {status})", "blocked")
            raise NeedsLogin(f"{account}/{client}: refresh rejected (HTTP {status}); a login is needed")
        apply_mint(e, mint, now(), "refresh", {"url": req["url"].split("?")[0]})
        e["last_used"] = now()
        save(pd, st)
        journal_prune(pd)
        _emit(pd, f"session refreshed for {account}/{client}", "n/a")
        return e


def _exchange(pd: str, st: dict, account: str, client: str, e: dict, ex: dict, src: dict) -> dict:
    """Mint `client`'s token from the same account's live session cookie (learned exchange). No
    single-use chain is spent, but the response is journaled like a refresh."""
    req = render(ex, {"source_token": src["access_token"]})
    status, headers, body = send(pd, req)
    journal_append(pd, {"ts": now(), "account": account, "client": client, "head": "exchange",
                        "url": req["url"], "status": status, "headers": headers,
                        "body": body.decode("utf-8", "replace")[:200000]})
    mint = extract_tokens(status, headers, body, req["url"])
    if not mint or client_of(jwt_claims(mint.get("access") or "")) not in ("", client):
        _emit(pd, f"session exchange for {account}/{client} minted nothing (HTTP {status})", "blocked")
        raise NeedsLogin(f"{account}/{client}: the exchange from {ex['source_client']} returned no "
                         f"{client} token (HTTP {status}); the source session may be logged out")
    apply_mint(e, mint, now(), "exchange", {"url": req["url"].split("?")[0], "from": ex["source_client"]})
    e["last_used"] = now()
    save(pd, st)
    journal_prune(pd)
    _emit(pd, f"session minted for {account}/{client} from its {ex['source_client']} session", "n/a")
    return e


def _emit(pd: str, summary: str, verdict: str) -> None:
    if _activity is not None:
        _activity.emit(pd, "cred", "session", summary, verdict=verdict)


# ── credentials.jsonl sync ───────────────────────────────────────────────────
_TOKEN_FIELDS = ("token", "access_token", "bearer", "jwt")


SESSION_COOKIE = re.compile(r"session|sid$|^sess", re.I)


def is_cookie_session(e: dict) -> bool:
    """A credential that only travels as a cookie: a session-named JWT cookie or a cookie jar."""
    if e.get("access_token") and e.get("access_cookie"):
        return bool(SESSION_COOKIE.search(e["access_cookie"]))
    return bool(e.get("cookie_header") and not e.get("access_token"))


def _cookie_set(ah: list, pairs: list[tuple[str, str]]) -> list:
    """Set each name=value in the record's Cookie header (one line), keeping its other cookies."""
    cur = next((h for h in ah if isinstance(h, str) and h.lower().startswith("cookie:")), "")
    parts = [c.strip() for c in cur.split(":", 1)[1].split(";")] if cur else []
    for name, val in pairs:
        parts = [c for c in parts if c and not c.startswith(name + "=")] + [f"{name}={val}"]
    line = "Cookie: " + "; ".join(p for p in parts if p)
    return [h for h in ah if h is not cur] + [line] if line != cur else ah


def _cookie_pairs(e: dict) -> list[tuple[str, str]]:
    if e.get("access_token") and e.get("access_cookie"):
        return [(e["access_cookie"], e["access_token"])]
    out = []
    for c in (e.get("cookie_header") or "").split(";"):
        n, _, v = c.strip().partition("=")
        if n:
            out.append((n, v))
    return out


def _drop_expired(r: dict, acct: str, changes: list) -> None:
    """Flag every vault JWT (token fields and auth_headers lines) whose exp has passed."""
    for f in _TOKEN_FIELDS:
        tok = str(r.get(f) or "")
        c = jwt_claims(tok)
        if c and c.get("exp") and c["exp"] < now():
            r["token_expired"] = tok
            del r[f]
            changes.append({"account": acct, "client": "", "field": f"{f} (expired, moved to token_expired)",
                            "exp": iso(c["exp"])})
    if isinstance(r.get("auth_headers"), list):
        keep, dead = [], []
        for h in r["auth_headers"]:
            toks = re.findall(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", h) if isinstance(h, str) else []
            if toks and all((jwt_claims(t) or {}).get("exp", now() + 1) < now() for t in toks):
                dead.append(h)
            else:
                keep.append(h)
        if dead:
            r["auth_headers"] = keep
            r["auth_headers_expired"] = dead
            changes.append({"account": acct, "client": "", "exp": "",
                            "field": f"auth_headers ({len(dead)} expired, moved to auth_headers_expired)"})


def sync(pd: str, dry_run: bool = False) -> list[dict]:
    """Merge each account's live credentials into its credentials.jsonl record(s): every live
    session cookie into the Cookie header, and the newest live bearer into the token field. Expired
    vault JWTs are flagged, not trusted. A bearer replaces only a bearer from the same client (a
    record pinned to a client, by `client`/`azp` or by the client of the live token it holds, never
    receives another client's token). Unparseable lines and every other field are preserved.
    Returns what changed (no values)."""
    path = os.path.join(pd, "credentials.jsonl")
    try:
        lines = open(path, errors="ignore").read().splitlines()
    except OSError:
        return []
    st = load(pd)
    index = [(label, ids) for label, ids in vault_index(pd)]
    changes, out = [], []
    for line in lines:
        try:
            r = json.loads(line) if line.strip() and not line.lstrip().startswith("#") else None
        except json.JSONDecodeError:
            r = None
        if not isinstance(r, dict):
            out.append(line)
            continue
        label = next((str(r[k]) for k in ("account", "label", "username", "email", "name") if r.get(k)), "")
        acct = label if label in st["accounts"] else ""
        if not acct:
            ids = next((ids for lbl, ids in index if lbl == label), set())
            acct = next((a for a in st["accounts"] if a.lower() in ids or
                         any(str(c.get("claims", {}).get("sub", "")).lower() in ids
                             for c in st["accounts"][a]["clients"].values())), "")
        if not acct:
            out.append(line)
            continue
        clients = st["accounts"][acct]["clients"]
        live = {k: v for k, v in clients.items() if entry_state(v) in ("live", "expiring")}
        if not live:
            out.append(line)
            continue
        before = json.dumps(r, sort_keys=True)
        _drop_expired(r, acct, changes)
        explicit = str(r.get("client") or r.get("azp") or "")
        held_tok = str(next((r[k] for k in _TOKEN_FIELDS if r.get(k)), "") or "")
        held = client_of(jwt_claims(held_tok))
        if held and held in str(r.get("session_client") or "").split(","):
            held = ""      # a token this sync wrote earlier doesn't pin the record to its client
        cookie_clients = [k for k, v in live.items() if is_cookie_session(v)]
        bearer_clients = [k for k, v in live.items() if v.get("access_token") and k not in cookie_clients]
        if explicit:
            cookie_clients = [k for k in cookie_clients if k == explicit]
            bearer_clients = [k for k in bearer_clients if k == explicit]
        elif held:
            # the record holds an unexpired bearer from a known client: only that client may replace it
            bearer_clients = [k for k in bearer_clients if k == held]
        ah = r.get("auth_headers") if isinstance(r.get("auth_headers"), list) else []
        used = []
        for k in cookie_clients:
            new_ah = _cookie_set(ah, _cookie_pairs(live[k]))
            if new_ah != ah:
                ah = new_ah
                changes.append({"account": acct, "client": k, "exp": iso(live[k].get("access_exp")),
                                "field": "auth_headers[Cookie " + ",".join(n for n, _ in _cookie_pairs(live[k])) + "]"})
            used.append(k)
        if cookie_clients:
            r["auth_headers"] = ah
        hcmap = st["config"].get("host_clients", {})
        if bearer_clients:
            cover = collections.Counter(hcmap.values())
            k = max(bearer_clients, key=lambda c: (cover.get(c, 0), live[c].get("minted_at") or 0))
            e = live[k]
            new = e["access_token"]
            field = next((f for f in _TOKEN_FIELDS if r.get(f)), "token")
            old = str(r.get(field) or "")
            if old != new:
                r[field] = new
                if old and isinstance(r.get("auth_headers"), list):
                    r["auth_headers"] = [h.replace(old, new) if isinstance(h, str) else h for h in r["auth_headers"]]
                elif old and isinstance(r.get("auth_headers"), dict):
                    r["auth_headers"] = {n: (v.replace(old, new) if isinstance(v, str) else v)
                                         for n, v in r["auth_headers"].items()}
                r["token_exp"] = iso(e.get("access_exp"))
                changes.append({"account": acct, "client": k, "field": field, "exp": iso(e.get("access_exp"))})
            used.append(k)
        if not explicit and not held:
            # Per-host bearers: a host that answered one client's token in history gets that token,
            # when it differs from the record's default (lane synthesis applies it per lane host).
            ha = {}
            for h, c in sorted(hcmap.items()):
                ent = live.get(c)
                if ent and ent.get("access_token") and c not in cookie_clients and \
                        ent["access_token"] != r.get("token"):
                    ha[h] = f"Authorization: Bearer {ent['access_token']}"
            if ha != (r.get("host_auth") or {}):
                if ha:
                    r["host_auth"] = ha
                else:
                    r.pop("host_auth", None)
                changes.append({"account": acct, "client": "", "exp": "",
                                "field": f"host_auth ({len(ha)} host(s) with their own bearer)"})
        if used:
            r["session_client"] = ",".join(used)
        out.append(json.dumps(r) if json.dumps(r, sort_keys=True) != before else line)
    if changes and not dry_run:
        with locked(pd):
            with open(path, errors="ignore") as fh:
                _write_private(path + ".bak", fh.read())     # the vault as it was, one generation
            _write_private(path, "\n".join(out) + "\n")
        _emit(pd, f"session sync: {len(changes)} credential change(s); re-synthesize lanes", "n/a")
    return changes


# ── CLI ──────────────────────────────────────────────────────────────────────
def _pd(a) -> str:
    pd = os.path.abspath(os.path.expanduser(a.project_dir))
    if not os.path.isdir(pd):
        sys.exit(f"session.py: no such project dir {pd}")
    return pd


def _rows(st: dict) -> list[dict]:
    rows = []
    for acct, a in sorted(st["accounts"].items()):
        for c, e in sorted(a.get("clients", {}).items()):
            exp = e.get("access_exp")
            rows.append({"account": acct, "client": c, "state": entry_state(e),
                         "access_ttl_s": int(exp - now()) if exp else None,
                         "refresh": bool(e.get("refresh_token")), "refresh_state": e.get("refresh_state", ""),
                         "rotates": e.get("rotates"), "refresh_recipe": c in st["recipes"]["refresh"],
                         "login_recipe": c in st["recipes"]["login"] or "*" in st["recipes"]["login"],
                         "minted_by": e.get("minted_by", ""), "minted_at": iso(e.get("minted_at")),
                         "sub": (e.get("claims") or {}).get("sub", "")})
    return rows


def cmd_list(a) -> int:
    st = load(_pd(a))
    rows = _rows(st)
    if a.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("no sessions stored; run `session.py harvest`")
        return 0
    print(f"{'account':<28} {'client':<20} {'state':<11} {'ttl':>7}  refresh  recipe  minted_by")
    for r in rows:
        ttl = "" if r["access_ttl_s"] is None else (f"{r['access_ttl_s'] // 60}m" if r["access_ttl_s"] > 0 else "exp")
        rf = (r["refresh_state"] or "yes") if r["refresh"] else "-"
        rec = ("R" if r["refresh_recipe"] else "-") + ("L" if r["login_recipe"] else "-")
        print(f"{r['account'][:28]:<28} {r['client'][:20]:<20} {r['state']:<11} {ttl:>7}  {rf[:7]:<7}  "
              f"{rec:<6}  {r['minted_by']}")
    return 0


def cmd_harvest(a) -> int:
    pd = _pd(a)
    st = load(pd)
    hosts = list(st["config"].get("auth_hosts", [])) + (a.host or [])
    domains = scope_domains(pd, hosts) if not a.only_hosts else sorted(set(hosts))
    if not domains:
        print("no domains to harvest: scope.md has no parseable host and no --host was given", file=sys.stderr)
        return 2
    projects = caido_projects(a.caido_dir or caido_data_dir(), a.caido_project)
    if not projects:
        print("no Caido project found", file=sys.stderr)
        return 2
    s = harvest(pd, projects, domains, since_days=a.since_days, dry_run=a.dry_run)
    if a.json:
        print(json.dumps(s, indent=2))
        return 0
    print(f"read {s['exchanges_read']} exchanges on {', '.join(domains)} from {', '.join(s['projects'])}")
    for e in s["entries"]:
        print(f"  {e['account']:<28} {e['client']:<20} {e['action']:<16} {e['state']:<11} "
              f"{e['refresh_state'] or ''}  minted {e['minted_at']}")
    print(f"refresh recipes: {', '.join(s['refresh_recipes']) or 'none'}; "
          f"login recipes: {', '.join(s['login_recipes']) or 'none'}; "
          f"exchange recipes: {', '.join(s['exchange_recipes']) or 'none'}" + ("  (dry run, not saved)" if a.dry_run else ""))
    return 0


def cmd_get(a) -> int:
    pd = _pd(a)
    try:
        e = refresh_entry(pd, a.account, a.client or "", a.min_ttl) if not a.no_refresh else pick(load(pd), a.account, a.client or "")[1]
    except KeyError as k:
        if not a.login:
            print(f"no session for {k}", file=sys.stderr)
            return 4
        rc, e = _login_fallback(pd, a.account, a.client or "", f"no session for {k}")
        if rc:
            return rc
    except NeedsLogin as n:
        if not a.login:
            print(str(n), file=sys.stderr)
            return 3
        rc, e = _login_fallback(pd, a.account, a.client or "", str(n))
        if rc:
            return rc
    tok = e.get("access_token") or ""
    if not tok and e.get("cookie_header") and a.format == "header":
        print(f"Cookie: {e['cookie_header']}")
        return 0
    if not tok:
        print("entry has no access token", file=sys.stderr)
        return 3
    if a.format == "header":
        print(auth_header(e)[0])
    elif a.format == "json":
        print(json.dumps({"access_token": tok, "access_exp": e.get("access_exp"), "claims": e.get("claims", {})}))
    else:
        print(tok)
    return 0


def storage_state(e: dict, domain: str, user_agent: str = "", fingerprint: dict | None = None) -> dict:
    """A Playwright storageState for one cookie session, plus the user_agent and client-hint headers
    authed-crawl.py pins for fingerprint parity. Every cookie goes on `domain` (".example.com" covers
    its subdomains); only the session cookie carries an expiry."""
    jar = {}
    for part in (e.get("cookie_header") or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name:
            jar[name] = value
    if e.get("access_cookie") and e.get("access_token"):
        jar[e["access_cookie"]] = e["access_token"]
    exp = int(e["access_exp"]) if e.get("access_exp") else -1
    cookies = [{"name": n, "value": v, "domain": domain, "path": "/", "secure": True, "httpOnly": True,
                "sameSite": "Lax", "expires": exp if n == e.get("access_cookie") else -1}
               for n, v in jar.items()]
    return {"cookies": cookies, "origins": [], "user_agent": user_agent,
            "fingerprint_headers": dict(fingerprint or {})}


def _cookie_domain(e: dict) -> str:
    host = (urlsplit((e.get("source") or {}).get("url") or "").hostname or "")
    return "." + ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else ""


def cmd_storage_state(a) -> int:
    """Write an account's cookie session as a session file for authed-crawl.py (mode 600)."""
    pd = _pd(a)
    st = load(pd)
    client = a.client or next((c for c, ce in (st["accounts"].get(a.account) or {}).get("clients", {}).items()
                               if is_cookie_session(ce)), "")
    try:
        _client, e = pick(st, a.account, client)
    except KeyError as k:
        print(f"no session for {k}", file=sys.stderr)
        return 4
    if not is_cookie_session(e):
        print(f"{a.account}/{_client} is not a cookie session; pass --client for the account's cookie entry",
              file=sys.stderr)
        return 3
    domain = a.domain or _cookie_domain(e)
    if not domain:
        print("cannot infer the cookie domain from the entry; pass --domain .example.com", file=sys.stderr)
        return 2
    ua, fp = a.user_agent, {}
    if a.fingerprint_from:
        with open(a.fingerprint_from) as fh:
            src = json.load(fh)
        ua, fp = ua or src.get("user_agent") or "", src.get("fingerprint_headers") or {}
    if not ua:
        try:
            with open(os.path.join(pd, "request-headers.json")) as fh:
                rh = json.load(fh)
            ua = next((v for k, v in rh.items() if k.lower() == "user-agent"), "") if isinstance(rh, dict) else ""
        except (OSError, json.JSONDecodeError):
            pass
    out = os.path.abspath(os.path.expanduser(a.out))
    _write_private(out, json.dumps(storage_state(e, domain, ua, fp), indent=2))
    print(f"wrote {out}: {a.account}/{_client} on {domain}, user agent {'set' if ua else 'NOT set'}, "
          f"{len(fp)} client-hint header(s)")
    return 0


def _login_fallback(pd: str, account: str, client: str, why: str) -> tuple[int, dict]:
    """Run login.py for an entry nothing can refresh. (exit code, entry); 0 = logged in."""
    import login as _login
    print(f"{why}; logging in", file=sys.stderr)
    try:
        c = _login.login(pd, account, client)
    except _login.Blocked as b:
        _emit(pd, f"session login BLOCKED for {account}: {b}", "blocked")
        print(f"BLOCKED: {b}", file=sys.stderr)
        return 5, {}
    except _login.Failed as f:
        print(f"login failed: {f}", file=sys.stderr)
        return 3, {}
    return 0, load(pd)["accounts"][account]["clients"][c]


def auth_header(e: dict) -> list[str]:
    if e.get("access_token") and e.get("access_cookie"):
        return [f"Cookie: {e['access_cookie']}={e['access_token']}"]
    if e.get("access_token"):
        tt = e.get("token_type") or "Bearer"
        return [f"Authorization: {'Bearer' if tt.lower() == 'bearer' else tt} {e['access_token']}"]
    if e.get("cookie_header"):
        return [f"Cookie: {e['cookie_header']}"]
    return []


def check_entry(pd: str, account: str, client: str, url: str, expect: str = "") -> int:
    """One GET to the engagement's who-am-I URL with this session: liveness by use, since an
    unexpired token can still be revoked or its account suspended. Records the status."""
    with locked(pd):
        st = load(pd)
        e = st["accounts"][account]["clients"][client]
        hdr = auth_header(e)
    if not hdr:
        return 0
    k, v = hdr[0].split(": ", 1)
    status, _h, body = send(pd, {"method": "GET", "url": url, "headers": [[k, v]], "body": ""})
    if 200 <= status < 300 and expect and not re.search(expect, body[:200000].decode("utf-8", "replace")):
        status = 401        # answered, but not as a signed-in user (a logged-out 200)
    with locked(pd):
        st = load(pd)
        e = st["accounts"][account]["clients"][client]
        e["verified"] = {"status": status, "at": now(), "url": url.split("?")[0]}
        if status in (401, 403):
            e["access_rejected"] = status
        else:
            e.pop("access_rejected", None)
        save(pd, st)
    return status


def cmd_check(a) -> int:
    pd = _pd(a)
    if _pace is not None:
        _pace.init(pd)
    st = load(pd)
    url = a.url or st["config"].get("whoami_url", "")
    expect = a.expect or st["config"].get("whoami_expect", "")
    if not url:
        print("no who-am-I URL: pass --url once (it is remembered), e.g. the API's /me", file=sys.stderr)
        return 2
    if a.url:
        with locked(pd):
            st = load(pd)
            st["config"]["whoami_url"] = a.url
            st["config"]["whoami_expect"] = a.expect
            save(pd, st)
    rc = 0
    for acct, ad in sorted(st["accounts"].items()):
        for c, e in sorted(ad.get("clients", {}).items()):
            if (a.account and acct != a.account) or entry_state(e) not in ("live", "expiring"):
                continue
            status = check_entry(pd, acct, c, url, expect)
            verdict = "live" if 200 <= status < 300 else "REJECTED" if status in (401, 403) else f"HTTP {status}"
            print(f"  {acct:<28} {c:<20} {verdict}")
            rc = rc or (0 if 200 <= status < 300 else 3)
    return rc


def cmd_refresh(a) -> int:
    pd = _pd(a)
    st = load(pd)
    rc = 0
    targets = [(acct, c) for acct, ad in st["accounts"].items() for c in ad.get("clients", {})
               if not a.account or acct == a.account]
    for acct, ad in st["accounts"].items():        # clients an exchange can mint that this account lacks
        for c, ex in st["recipes"]["exchange"].items():
            if (not a.account or acct == a.account) and c not in ad.get("clients", {}) \
                    and entry_state(ad.get("clients", {}).get(ex.get("source_client"), {})) in ("live", "expiring"):
                targets.append((acct, c))
    for acct, c in targets:
        try:
            e = refresh_entry(pd, acct, c, a.min_ttl, force=a.force)
            ttl = int(e["access_exp"] - now()) // 60 if e.get("access_exp") else None
            print(f"  {acct:<28} {c:<20} live  ({'?' if ttl is None else f'{ttl}m'} left, {e.get('minted_by')})")
        except NeedsLogin as n:
            if a.login:
                code, _e = _login_fallback(pd, acct, c, str(n))
                print(f"  {acct:<28} {c:<20} " + ("logged in" if code == 0 else
                      "BLOCKED (human needed)" if code == 5 else "LOGIN FAILED"))
                rc = max(rc, code)
            else:
                print(f"  {acct:<28} {c:<20} NEEDS LOGIN: {n}")
                rc = max(rc, 3)
    if a.sync:
        ch = sync(pd)
        print(f"sync: {len(ch)} credential record(s) updated" + ("; re-synthesize lanes" if ch else ""))
    return rc


def cmd_sync(a) -> int:
    ch = sync(_pd(a), dry_run=a.dry_run)
    for c in ch:
        what = (f"{c['field']} (was exp {c['exp']})" if "expired" in c["field"]
                else f"{c['field']} <- live session (exp {c['exp'] or 'unknown'})")
        print(f"  {c['account']:<28} {c['client']:<20} {what}")
    n = len({c["account"] for c in ch})
    print(f"{'would change' if a.dry_run else 'changed'} {n} account record(s)" +
          ("; re-synthesize lanes (lane synthesis bakes tokens into headers)" if ch and not a.dry_run else ""))
    return 0


def cmd_config(a) -> int:
    pd = _pd(a)
    with locked(pd):
        st = load(pd)
        hosts = set(st["config"].get("auth_hosts", []))
        hosts |= {h.lower() for h in a.auth_host or []}
        hosts -= {h.lower() for h in a.remove_auth_host or []}
        st["config"]["auth_hosts"] = sorted(hosts)
        for al in a.alias or []:
            src, _, dst = al.partition("=")
            if src and dst:
                st["config"]["aliases"][src.strip()] = dst.strip()
                # fold an already-harvested entry under the new name
                if src.strip() in st["accounts"]:
                    moved = st["accounts"].pop(src.strip())
                    st["accounts"].setdefault(dst.strip(), {"clients": {}})["clients"].update(moved["clients"])
        save(pd, st)
    print(json.dumps(st["config"], indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="session.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def p(name, fn, help_):
        s = sub.add_parser(name, help=help_)
        s.add_argument("--project-dir", required=True)
        s.set_defaults(fn=fn)
        return s
    s = p("harvest", cmd_harvest, "fold Caido token mints into the store")
    s.add_argument("--caido-dir", default="")
    s.add_argument("--caido-project", action="append", help="project name or id (default: all, newest first)")
    s.add_argument("--host", action="append", help="extra domain to read (an auth host outside scope)")
    s.add_argument("--only-hosts", action="store_true", help="read only --host/auth hosts, not scope domains")
    s.add_argument("--since-days", type=int, default=30)
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--json", action="store_true")
    s = p("list", cmd_list, "show stored sessions and their state (no tokens)")
    s.add_argument("--json", action="store_true")
    s = p("get", cmd_get, "print a live access token, refreshing first if needed")
    s.add_argument("--account", required=True)
    s.add_argument("--client", default="")
    s.add_argument("--min-ttl", type=int, default=120, help="refresh when fewer seconds than this remain")
    s.add_argument("--format", choices=("token", "header", "json"), default="token")
    s.add_argument("--no-refresh", action="store_true")
    s.add_argument("--login", action="store_true", help="log in (login.py) when nothing can be refreshed")
    s = p("refresh", cmd_refresh, "refresh entries near expiry (prints states, never tokens)")
    s.add_argument("--account", default="")
    s.add_argument("--min-ttl", type=int, default=600)
    s.add_argument("--force", action="store_true", help="refresh even if the access token is live")
    s.add_argument("--sync", action="store_true", help="then copy live tokens into credentials.jsonl")
    s.add_argument("--login", action="store_true", help="log in (login.py) where nothing can be refreshed")
    s = p("check", cmd_check, "verify live sessions by use: one GET to a who-am-I URL each")
    s.add_argument("--url", default="", help="who-am-I URL (remembered in sessions.json config)")
    s.add_argument("--expect", default="", help="regex the body must match when signed in (remembered "
                   "with --url); for endpoints that answer 200 to a logged-out caller too")
    s.add_argument("--account", default="")
    s = p("sync", cmd_sync, "copy live access tokens into credentials.jsonl")
    s.add_argument("--dry-run", action="store_true")
    s = p("storage-state", cmd_storage_state, "write an account's cookie session as an authed-crawl.py "
          "session file (mode 600)")
    s.add_argument("--account", required=True)
    s.add_argument("--client", default="", help="the account's cookie entry (default: its first cookie session)")
    s.add_argument("--out", required=True)
    s.add_argument("--domain", default="", help="cookie domain, e.g. .example.com (default: from the "
                   "entry's source URL)")
    s.add_argument("--user-agent", default="", help="default: request-headers.json's User-Agent")
    s.add_argument("--fingerprint-from", default="", help="take user_agent and client-hint headers from "
                   "this existing session file, so the crawl presents as the browser that made the traffic")
    s = p("config", cmd_config, "persist auth hosts and subject aliases for harvest")
    s.add_argument("--auth-host", action="append")
    s.add_argument("--remove-auth-host", action="append")
    s.add_argument("--alias", action="append", help="SUBJECT=ACCOUNT, e.g. sub:abc123=a1 (links a token "
                   "subject to a credentials.jsonl account)")
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
