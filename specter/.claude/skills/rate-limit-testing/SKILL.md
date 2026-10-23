---
name: rate-limit-testing
description: Rate limiting and resource consumption testing. Maps to OWASP API4. Tests auth endpoints, sensitive operations, and bypass techniques.
allowed-tools: Read, Grep, Glob, Bash
---
# Rate Limit Testing Skill (API4:2023)

## Basic Check
Send 50-100 identical requests. Look for 429 response, Retry-After, X-RateLimit headers.

## Bypass Techniques
### Header Rotation
X-Forwarded-For, X-Originating-IP, X-Remote-IP, X-Client-IP, True-Client-IP

### Path Variation
/api/v3/login vs /Api/V3/Login vs /api/v3/login/ vs /api/v3/login?x=1

### HTTP/2 Multiplexing
Hundreds of parallel streams on single connection.

### GraphQL Batching
Array: multiple queries in one request. Alias: 100 aliases = 100 operations as 1 HTTP request.

### IP Rotation
fireprox, Burp IPRotate, rotating proxies

## Priority Endpoints
1. Login  2. Password reset  3. OTP/MFA  4. Registration  5. Payment  6. API key gen  7. File upload

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Show the sensitive operation actually SUCCEEDED N times past the documented limit with effect (e.g. N OTP attempts accepted), not merely N HTTP 200s.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by specter
```
