---
name: auth-testing
description: Authentication and session management testing covering JWT, OAuth, RBAC, and credential attacks. Maps to OWASP API2 and WSTG-ATHN/SESS.
allowed-tools: Read, Grep, Glob, Bash
---
# Authentication Testing Skill

## WSTG-ATHN Coverage
- ATHN-02: Default credentials (admin/admin, admin/password, root/root)
- ATHN-03: Weak lockout (10-50 failed attempts, check for lockout)
- ATHN-04: Auth bypass (no token, empty token, method override, path tricks)
- ATHN-07: Weak password policy (short, no complexity, common passwords)
- ATHN-09: Password reset (predictable tokens, token reuse, enumeration)
- ATHN-11: MFA bypass (skip step, OTP brute-force, status manipulation)

## JWT Testing (SESS-10)
See jwt-analysis skill for full methodology.

## OAuth 2.0 Testing (ATHZ-05)
1. Fetch /.well-known/openid-configuration
2. Test redirect_uri manipulation
3. Test state parameter (remove, reuse, predict)
4. Test PKCE (omit code_challenge, plain method)
5. Test scope escalation
6. Test cross-client token acceptance
7. Test device code flow

## Session Management (SESS-01 to SESS-09)
- Cookie attributes: Secure, HttpOnly, SameSite
- Session fixation, timeout, concurrent sessions

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** The bypass must succeed where a correctly-authenticated baseline is required, and FAIL for a properly-denied control. Capture the working-vs-blocked differential.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by specter
```
