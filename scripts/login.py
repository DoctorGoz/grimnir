#!/usr/bin/env python3
"""login.py — mint a fresh session for one of our own test accounts, then store it via session.py.

session.py keeps sessions alive by refreshing them. When there's nothing left to refresh (no
refresh token, the chain was spent, or the server revoked it), this logs in again:

  http     replay the login request session.py learned from Caido history, with the account's
           username and password from credentials.jsonl. For an OTP login, the learned send-code
           step runs first and its echoed values (a challenge id) carry into the verify step.
  browser  Playwright Chromium: open the login page, fill the identity and password fields
           (one-page or two-step forms), submit, and capture tokens from the network responses
           and JWT-shaped values in storage. Cookie-only sessions are stored as a Cookie header
           plus a Playwright storage state.
  auto     http when a recipe exists, else browser (the default)

  login.py --project-dir DIR --account a1 [--client web] [--mode auto|http|browser]
           [--login-url URL] [--headful] [--otp CODE | --otp-prompt] [--force]

Stops and reports BLOCKED (exit 5) instead of grinding when a human is needed: an OTP with no
--otp/--otp-prompt (the send-code step has run, so the code is on its way; rerun with --otp CODE
within 10 minutes to resume), a CAPTCHA or bot challenge, or an MFA prompt. Never tries to get
around any of them. At most one login attempt per account every 15 minutes unless --force, so a
wrong password can't lock the account. Credentials and tokens are never printed.

Exit codes: 0 logged in and stored, 2 usage/config, 3 login failed, 5 BLOCKED (human needed).
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import egress as _egress  # noqa: E402 — the program's egress proxy: login rides it or refuses
import session as S  # noqa: E402

ATTEMPT_GAP = 15 * 60
OTP_PENDING_TTL = 10 * 60
CAPTCHA = re.compile(r"recaptcha|hcaptcha|challenges\.cloudflare\.com|turnstile|arkoselabs|funcaptcha|"
                     r"geetest|captcha-delivery|perimeterx|px-captcha", re.I)
IDENTITY_SEL = ("input[type=email]", "input[autocomplete=username]", "input[autocomplete=email]",
                "input[name*=email i]", "input[id*=email i]", "input[name*=user i]", "input[id*=user i]",
                "input[name*=login i]", "input[name=identifier]", "input[type=tel]", "input[type=text]")
PASSWORD_SEL = ("input[type=password]",)
OTP_SEL = ("input[autocomplete=one-time-code]", "input[name*=otp i]", "input[id*=otp i]",
           "input[name*=code i]", "input[inputmode=numeric]")
SUBMIT_SEL = ("button[type=submit]", "input[type=submit]", "button:has-text('Log in')",
              "button:has-text('Sign in')", "button:has-text('Continue')", "button:has-text('Next')")


class Blocked(Exception):
    pass


class Failed(Exception):
    pass


def account_creds(pd: str, account: str) -> dict:
    """username + password for `account` from credentials.jsonl (matched by account/label/email)."""
    for label, _ids in S.vault_index(pd):
        if label != account:
            continue
        with open(os.path.join(pd, "credentials.jsonl"), errors="ignore") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(r, dict):
                    continue
                lab = next((str(r[k]) for k in ("account", "label", "username", "email", "name") if r.get(k)), "")
                if lab == account:
                    return {"username": str(r.get("email") or r.get("username") or r.get("login") or
                                            r.get("phone") or ""),
                            "password": str(r.get("password") or r.get("pass") or "")}
    return {"username": "", "password": ""}


def _guard_attempts(pd: str, account: str, force: bool) -> None:
    with S.locked(pd):
        st = S.load(pd)
        last = st.setdefault("login_attempts", {}).get(account, 0)
        if not force and S.now() - last < ATTEMPT_GAP:
            raise Failed(f"a login for {account} was attempted {int(S.now() - last)}s ago; "
                         f"waiting {ATTEMPT_GAP // 60} min between attempts protects the account from "
                         "lockout (use --force to override)")
        st["login_attempts"][account] = S.now()
        S.save(pd, st)


def _store(pd: str, account: str, client: str, mint: dict | None, how: str, url: str,
           cookie_header: str = "", state_path: str = "") -> str:
    with S.locked(pd):
        st = S.load(pd)
        claims = S.jwt_claims((mint or {}).get("access") or "") or {}
        client = S.client_of(claims) or client or "default"
        e = st["accounts"].setdefault(account, {"clients": {}})["clients"].setdefault(client, {})
        if mint:
            S.apply_mint(e, mint, S.now(), how, {"url": url.split("?")[0]})
        else:
            e.update(minted_by=how, minted_at=S.now(), source={"url": url.split("?")[0]})
        if cookie_header:
            e["cookie_header"] = cookie_header
        if state_path:
            e["storage_state"] = state_path
        st.get("login_attempts", {}).pop(account, None)
        if (st.get("pending_otp") or {}).get("account") == account:
            st.pop("pending_otp")
        S.save(pd, st)
    S._emit(pd, f"session login ({how}) for {account}/{client}", "n/a")
    return client


# ── http replay ──────────────────────────────────────────────────────────────
def _get_otp(a, pd: str, account: str) -> str:
    if a.otp:
        return a.otp.strip()
    if a.otp_prompt:
        sys.stderr.write(f"OTP for {account}: ")
        sys.stderr.flush()
        return sys.stdin.readline().strip()
    return ""


def login_http(pd: str, account: str, client: str, recipe: dict, creds: dict, a) -> str:
    vals = {"username": creds["username"], "password": creds["password"]}
    if recipe.get("requires_otp"):
        st = S.load(pd)
        pend = st.get("pending_otp") or {}
        resume = (a.otp and pend.get("account") == account and pend.get("client") == client
                  and S.now() - pend.get("ts", 0) < OTP_PENDING_TTL)
        if resume:
            vals.update(pend.get("vars", {}))
        elif recipe.get("pre"):
            pre = S.render(recipe["pre"], vals)
            status, _h, body = S.send(pd, pre)
            if not 200 <= status < 300:
                raise Failed(f"the send-code step returned HTTP {status}")
            try:
                flat = S._flat_strings(json.loads(body))
            except (json.JSONDecodeError, UnicodeDecodeError):
                flat = {}
            for k in recipe["pre"].get("chain", []):
                if k in flat:
                    vals["pre." + k] = flat[k]
            with S.locked(pd):
                st = S.load(pd)
                st["pending_otp"] = {"account": account, "client": client, "ts": S.now(),
                                     "vars": {k: v for k, v in vals.items() if k.startswith("pre.")}}
                S.save(pd, st)
        code = _get_otp(a, pd, account)
        if not code:
            raise Blocked(f"{account} logs in with a one-time code"
                          + (" and the code has been sent" if recipe.get("pre") else
                             " (no send-code step was learned: trigger the code in the app)")
                          + f"; rerun with --otp CODE within {OTP_PENDING_TTL // 60} min, or use --otp-prompt")
        vals["otp"] = code
    elif not creds["password"]:
        raise Failed(f"credentials.jsonl has no password for {account}")
    req = S.render(recipe, vals)
    if re.search(r"\{(username|password|otp|pre\.[^}]+)\}", req["body"] + req["url"]):
        raise Failed("the learned login request has a value this run couldn't fill; re-harvest a fresh login")
    status, headers, body = S.send(pd, req)
    mint = S.extract_tokens(status, headers, body, req["url"])
    if not mint:
        txt = body[:4000].decode("utf-8", "replace")
        if CAPTCHA.search(txt):
            raise Blocked(f"the login endpoint asked for a CAPTCHA (HTTP {status}); log in once in a browser")
        raise Failed(f"login replay returned HTTP {status} with no token")
    return _store(pd, account, client, mint, "login-http", req["url"])


# ── browser ──────────────────────────────────────────────────────────────────
def _first_visible(page, sels, timeout_ms=0):
    for sel in sels:
        try:
            loc = page.locator(sel)
            for i in range(min(loc.count(), 5)):
                el = loc.nth(i)
                if el.is_visible() and el.is_enabled():
                    return el
        except Exception:  # noqa: BLE001
            continue
    return None


def _captcha_present(page) -> bool:
    try:
        for f in page.frames:
            if CAPTCHA.search(f.url or ""):
                return True
        return bool(CAPTCHA.search(page.content()[:200000]))
    except Exception:  # noqa: BLE001
        return False


def _submit(page, field) -> None:
    btn = _first_visible(page, SUBMIT_SEL)
    if btn is not None:
        btn.click()
    else:
        field.press("Enter")


def login_browser(pd: str, account: str, client: str, login_url: str, creds: dict, a) -> str:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise Failed("playwright is not installed (pip install playwright && playwright install chromium)")
    if not creds["username"]:
        raise Failed(f"credentials.jsonl has no username/email for {account}")
    hdrs = {}
    if S._roe is not None:
        try:
            for line in S._roe.required_header_lines(pd):
                k, v = line.split(":", 1)
                hdrs[k.strip()] = v.strip()
        except Exception:  # noqa: BLE001
            pass
    ua = next((v for k, v in hdrs.items() if k.lower() == "user-agent"), S.DEFAULT_UA)
    hdrs = {k: v for k, v in hdrs.items() if k.lower() != "user-agent"}
    mints: list[tuple[float, dict, str]] = []
    sdir = os.path.join(pd, "sessions")
    os.makedirs(sdir, mode=0o700, exist_ok=True)

    def on_response(resp):
        try:
            if resp.request.resource_type not in ("xhr", "fetch", "document"):
                return
            body = resp.body() if resp.status < 300 else b""
            m = S.extract_tokens(resp.status, list(resp.headers.items()), body, resp.url)
            if m:
                mints.append((S.now(), m, resp.url))
        except Exception:  # noqa: BLE001
            pass

    with sync_playwright() as p:
        proxy = _egress.playwright_proxy(_egress.proxy(pd))
        # An intercepting proxy (Caido) re-signs TLS with its own CA; trust it only when proxied.
        # The context flag alone does not cover headless chromium, so pass the launch arg too.
        b = p.chromium.launch(headless=not a.headful, proxy=proxy,
                              args=["--ignore-certificate-errors"] if proxy else [])
        try:
            ctx = b.new_context(user_agent=ua, extra_http_headers=hdrs, ignore_https_errors=bool(proxy))
            page = ctx.new_page()
            page.route("**/*", lambda rt: rt.abort() if rt.request.resource_type in ("image", "media", "font")
                       else rt.continue_())
            page.on("response", on_response)
            if S._pace is not None:
                S._pace.before(login_url)
            page.goto(login_url, wait_until="domcontentloaded", timeout=a.timeout * 1000)
            page.wait_for_timeout(1500)
            if _captcha_present(page):
                raise Blocked("the login page shows a CAPTCHA or bot challenge; log in once by hand "
                              "(Caido capture), then run session.py harvest")
            pw = _first_visible(page, PASSWORD_SEL)
            ident = _first_visible(page, IDENTITY_SEL)
            if ident is None and pw is None:
                raise Failed(f"no login form found at {login_url}; pass --login-url for the sign-in page")
            if ident is not None:
                ident.fill(creds["username"])
            if pw is None:                     # two-step: identity first
                _submit(page, ident)
                page.wait_for_timeout(2500)
                pw = _first_visible(page, PASSWORD_SEL)
            if pw is not None:
                if not creds["password"]:
                    raise Failed(f"credentials.jsonl has no password for {account}")
                pw.fill(creds["password"])
                _submit(page, pw)
            page.wait_for_timeout(3000)
            with contextlib.suppress(Exception):
                page.wait_for_load_state("networkidle", timeout=10000)
            if not mints and _captcha_present(page):
                raise Blocked("a CAPTCHA appeared after submitting; log in once by hand, then harvest")
            otp = _first_visible(page, OTP_SEL)
            if otp is not None and not mints:
                code = _get_otp(a, pd, account)
                if not code:
                    raise Blocked(f"{account} needs a one-time code after the password; "
                                  "rerun with --otp-prompt to type it while the browser waits")
                otp.fill(code)
                _submit(page, otp)
                page.wait_for_timeout(3000)
                with contextlib.suppress(Exception):
                    page.wait_for_load_state("networkidle", timeout=10000)
            # tokens the SPA kept in storage rather than returned in a body we saw
            if not mints:
                with contextlib.suppress(Exception):
                    stash = page.evaluate("""() => { const o = {};
                      for (const s of [localStorage, sessionStorage]) for (let i = 0; i < s.length; i++) {
                        const k = s.key(i); o[k] = s.getItem(k); } return o; }""")
                    found: dict = {}
                    for k, v in (stash or {}).items():
                        try:
                            S._walk(json.loads(v), found)
                        except (json.JSONDecodeError, TypeError):
                            if isinstance(v, str) and S.jwt_claims(v):
                                found.setdefault("refresh" if "refresh" in k.lower() else "access", v)
                    found.pop("_generic", None)
                    if found.get("access") or found.get("refresh"):
                        mints.append((S.now(), found, page.url))
            state_path = os.path.join(sdir, f"{re.sub(r'[^A-Za-z0-9_.-]', '_', account)}.state.json")
            ctx.storage_state(path=state_path)
            # Record the UA the session was minted under: authed-crawl.py replays it, and a server that
            # binds a session to its User-Agent revokes the session on the first request from another.
            with open(state_path, encoding="utf-8") as fh:
                st = json.load(fh)
            st["user_agent"] = ua
            with open(state_path, "w", encoding="utf-8") as fh:
                json.dump(st, fh)
            os.chmod(state_path, 0o600)
            host = urlsplit(login_url).hostname or ""
            base = S.base_domain(host)
            cookies = [c for c in ctx.cookies() if c["domain"].lstrip(".").endswith(base)]
            cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            if S._pace is not None:
                S._pace.after(login_url, 200)
            still_form = _first_visible(page, PASSWORD_SEL) is not None
            if not mints and (still_form or not cookies):
                shot = os.path.join(sdir, f"{re.sub(r'[^A-Za-z0-9_.-]', '_', account)}.login-failed.png")
                with contextlib.suppress(Exception):
                    page.screenshot(path=shot)
                raise Failed(f"no session after submitting (still on a login form: {still_form}); see {shot}")
            mint = max(mints, key=lambda m: (bool(m[1].get("refresh")), m[0]))[1] if mints else None
            return _store(pd, account, client, mint, "login-browser", login_url,
                          cookie_header=cookie_header if not mint else "", state_path=state_path)
        finally:
            b.close()


# ── entry point ──────────────────────────────────────────────────────────────
def login(pd: str, account: str, client: str = "", mode: str = "auto", login_url: str = "", a=None) -> str:
    a = a or argparse.Namespace(otp="", otp_prompt=False, headful=False, timeout=45, force=False)
    if S._pace is not None:
        S._pace.init(pd)
    st = S.load(pd)
    creds = account_creds(pd, account)
    recipes = st["recipes"]["login"]
    rc = client if client in recipes else (next(iter(recipes)) if len(recipes) == 1 and not client else "")
    recipe = recipes.get(rc)
    url = login_url or st["config"].get("login_urls", {}).get(client or rc or "default", "")
    if not url and recipe:
        url = next((v for k, v in recipe.get("headers", []) if k.lower() == "referer"), "")
    resuming = bool(a.otp) and (st.get("pending_otp") or {}).get("account") == account
    if not resuming:
        _guard_attempts(pd, account, getattr(a, "force", False))
    if mode in ("auto", "http") and recipe:
        try:
            return login_http(pd, account, rc, recipe, creds, a)
        except Failed:
            if mode == "http" or not url:
                raise
    elif mode == "http":
        raise Failed(f"no login request learned for {client or 'this engagement'}; run session.py harvest "
                     "after one login, or use --mode browser --login-url URL")
    if not url:
        raise Failed("no login page known; pass --login-url (it is remembered per client)")
    if login_url:
        with S.locked(pd):
            st = S.load(pd)
            st["config"].setdefault("login_urls", {})[client or rc or "default"] = login_url
            S.save(pd, st)
    return login_browser(pd, account, client or rc, url, creds, a)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="login.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("--project-dir", required=True)
    ap.add_argument("--account", required=True)
    ap.add_argument("--client", default="")
    ap.add_argument("--mode", choices=("auto", "http", "browser"), default="auto")
    ap.add_argument("--login-url", default="")
    ap.add_argument("--headful", action="store_true", help="visible browser (use xvfb-run on a headless host)")
    ap.add_argument("--otp", default="", help="the one-time code (resumes a pending send-code step)")
    ap.add_argument("--otp-prompt", action="store_true", help="read the code from stdin when it's needed")
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--force", action="store_true", help="skip the 15-minute gap between attempts")
    ap.add_argument("--sync", action="store_true", help="then copy the live token into credentials.jsonl")
    a = ap.parse_args(argv)
    pd = os.path.abspath(os.path.expanduser(a.project_dir))
    if not os.path.isdir(pd):
        print(f"no such project dir {pd}", file=sys.stderr)
        return 2
    try:
        client = login(pd, a.account, a.client, a.mode, a.login_url, a)
    except Blocked as e:
        S._emit(pd, f"session login BLOCKED for {a.account}: {e}", "blocked")
        print(f"BLOCKED: {e}", file=sys.stderr)
        return 5
    except Failed as e:
        print(f"login failed: {e}", file=sys.stderr)
        return 3
    e = S.load(pd)["accounts"][a.account]["clients"][client]
    ttl = int(e["access_exp"] - S.now()) // 60 if e.get("access_exp") else None
    print(f"logged in: {a.account}/{client} via {e.get('minted_by')} "
          f"({'cookie session' if e.get('cookie_header') and not e.get('access_token') else 'token'}, "
          f"{'?' if ttl is None else f'{ttl}m'} left, refresh {'yes' if e.get('refresh_token') else 'no'})")
    if a.sync:
        ch = S.sync(pd)
        print(f"sync: {len(ch)} credential record(s) updated" + ("; re-synthesize lanes" if ch else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
