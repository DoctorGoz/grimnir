---
name: csrf
description: Cross-site request forgery testing (CWE-352, WSTG-SESS-05). Use on cookie-authenticated state-changing endpoints.
allowed-tools: Read, Grep, Glob, Bash
---

# CSRF Skill (CWE-352)

Force a logged-in victim's browser to make a state-changing request. Only relevant
when auth rides on **ambient credentials** (cookies) and the server lacks an
unpredictable, verified anti-CSRF token. Pure Bearer/Authorization-header APIs are
generally not CSRF-able.

## Prerequisites
- A state-changing action (POST/PUT/PATCH/DELETE, or a GET that changes state)
  authenticated by a cookie that the browser sends automatically.

## Methodology

### Step 1: Check the defenses
- Is there an anti-CSRF token? Is it actually **validated** (remove/blank/reuse it)?
- `SameSite` on the session cookie: `None` (vulnerable cross-site), `Lax` (GET-only
  top-level), `Strict` (mostly safe). Confirm the real value.
- Does it rely on a custom header (e.g. `X-Requested-With`)? Can JSON be sent as a
  simple request (`text/plain`/form) to dodge preflight?

### Step 2: Token attacks
Remove the token; send a blank token; reuse another user's token; swap method;
change `Content-Type` to a simple type; downgrade JSON to form-encoded.

### Step 3: Build the PoC
An auto-submitting HTML form (or `fetch` with `credentials:'include'`) hosted on a
different origin that triggers the action as the victim.

### Step 4: Confirm the effect
Load the PoC as a logged-in victim (second account) and verify the state changed.

## Payloads / wordlists
CSRF PoC HTML templates.

## Validate (negative control)
- **Attack:** the cross-origin PoC, executed as the victim, causes the server-side
  state change (re-read as the victim to confirm).
- **Negative control:** the same request WITHOUT the session cookie fails, and the
  request WITH a correct token from the legit flow succeeds — proving the token is
  the missing/!validated control, not something else.

## Evidence to capture
The PoC HTML, the victim-context request it generated, and the confirmed state
change (before/after re-read). Note SameSite + token behaviour.

## False-positive traps
- Auth via Authorization header / non-cookie (browser won't auto-attach) — not CSRF.
- `SameSite=Lax/Strict` already blocks the cross-site send for this method.
- A token that IS validated (your removal/blank test fails) — not vulnerable.
- Action has no security impact (e.g. toggling a personal non-sensitive pref) — Low.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after a cross-origin PoC changes victim state.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "cross-origin PoC changes victim email; same request without cookie fails; token-present legit flow succeeds (SameSite=None, token not validated)" --by specter
```
