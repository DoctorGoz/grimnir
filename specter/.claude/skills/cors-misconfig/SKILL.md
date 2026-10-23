---
name: cors-misconfig
description: CORS and security-misconfiguration testing (API8:2023, CWE-942/CWE-16). Use to find permissive cross-origin policies that leak authenticated data.
allowed-tools: Read, Grep, Glob, Bash
---

# CORS & Security Misconfiguration Skill (API8:2023)

A CORS bug only matters if it lets an attacker origin read **authenticated**
responses. Reflected-origin + `Access-Control-Allow-Credentials: true` on a
data endpoint is the High case; everything else is usually Info/Low.

## Prerequisites
- An endpoint that returns user-specific data with cookies/Authorization.

## Methodology

### Step 1: Probe ACAO reflection
Send `Origin: https://evil.example` and inspect response headers:
- `Access-Control-Allow-Origin: https://evil.example` (reflected) + `...-Credentials: true` => exploitable.
- `ACAO: *` with credentials is ignored by browsers (not exploitable as-is).
- `ACAO: null` + credentials => exploitable from a sandboxed iframe (`Origin: null`).

### Step 2: Test weak allowlist logic
- Suffix/prefix bypass: `https://target.example.com.evil.example`, `https://eviltarget.example.com`
- Subdomain trust: `https://anything.target.example.com` (chain with subdomain takeover/XSS).
- Scheme/port confusion, trailing dot, case.

### Step 3: Other misconfigs (API8)
Missing security headers (HSTS, X-Content-Type-Options), verbose errors/stack
traces, directory listing, debug endpoints, default creds on admin panels,
permissive methods (TRACE/PUT). Score each by concrete impact.

## Payloads / wordlists
Origin variants list; `specter/wordlists/`.

## Validate (negative control)
- **Attack:** show ACAO reflects the attacker origin AND ACAC is true on a response
  containing victim data — ideally a small PoC page that reads the body cross-origin.
- **Negative control:** a benign/expected origin behaves the same way? If the server
  reflects ANY origin only without credentials, it is not exploitable — say so.

## Evidence to capture
Request with `Origin:` + the response ACAO/ACAC headers + the sensitive body. A
working cross-origin read PoC (HTML) elevates it from theoretical to confirmed.

## False-positive traps
- `ACAO: *` without credentials — browsers block credentialed reads; not a vuln.
- Reflected origin on an endpoint with no auth/sensitive data — Info at most.
- Header present but the endpoint returns nothing cross-origin-worth-reading.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after proving a credentialed cross-origin read of victim data.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "Origin: evil.example reflected in ACAO + ACAC:true on /api/me; PoC page reads victim body cross-origin" --by specter
```
