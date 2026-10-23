---
name: open-redirect
description: Test for open redirect and redirect-based vulnerabilities (CWE-601). Use on login/logout/SSO return URLs, tracking links, and any redirect_uri / next / returnTo parameter.
allowed-tools: Read, Grep, Glob, Bash
---

# Open Redirect Testing Skill (CWE-601)

Open redirect on its own is often Low, but it is a force-multiplier: it chains into
OAuth/SSO token theft (`redirect_uri`), phishing, and sometimes SSRF. Score it by
what it chains into, not in isolation.

## Prerequisites
- Endpoints that take a destination: `next`, `url`, `returnTo`, `redirect`,
  `dest`, `continue`, `r`, `callback`, `redirect_uri`, `RelayState`.

## Methodology

### Step 1: Find redirect sinks
Grep crawled URLs and JS for the parameter names above. Check login, logout,
SSO/OAuth start, email links, and post-action redirects.

### Step 2: Baseline the allowed behavior
Submit a legitimate same-origin value and capture the `Location` header (or JS
`location` assignment) so you know the normal redirect shape.

### Step 3: Payloads (defeat naive allowlists)
- `https://evil.example`, `//evil.example`, `/\evil.example`, `https:evil.example`
- `https://target.example.com.evil.example` (suffix match bypass)
- `https://evil.example%23@target.example.com`, `@evil.example`
- Whitelisted-host-as-path: `https://target.example.com/redir?url=https://evil.example`
- Encoded: `%2f%2fevil.example`, double-encoded, CRLF for header injection.

### Step 4: OAuth/SSO redirect_uri abuse (the high-value case)
If `redirect_uri` is reflected, try registered-prefix bypass, path traversal,
and subdomain takeover targets. A redirect that carries a `code`/`token`/
`access_token` to an attacker origin is High/Critical, not Low.

## Payloads / wordlists
`specter/wordlists/` (add an `open-redirect.txt` if not present).

## Validate (negative control)
- **Attack:** show the server emits `Location: https://evil.example` (or the
  browser navigates there) for your payload.
- **Negative control:** show a plain external value WITHOUT the bypass is rejected
  / rewritten to same-origin. That difference proves an allowlist exists and your
  payload defeats it (otherwise it is just an intended redirect, not a vuln).

## Evidence to capture
The request + the `Location` response header (or a screenshot of the cross-origin
navigation). For OAuth, capture the leaked `code`/token reaching the attacker URL.

## False-positive traps
- An endpoint intended to redirect anywhere (documented behavior) is not a vuln.
- Reflected-but-not-followed values (returned in body, never in `Location`).
- Redirect that strips credentials/fragment before leaving origin.

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check above.

- Score by chain: bare redirect is Low; `redirect_uri` token exfil is High/Critical.
- Only `confirmed` findings ship.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method negative-control --method screenshot \
  --negative-control "payload -> Location: https://evil.example; plain external value -> rewritten to same-origin" --by specter
```
