---
name: xss
description: Cross-site scripting testing — reflected, stored, and DOM-based (CWE-79, WSTG-CLNT-01/INPV). Use on any sink that reflects user input into HTML/JS/attributes.
allowed-tools: Read, Grep, Glob, Bash
---

# XSS Testing Skill (CWE-79)

Reflected, stored, and DOM XSS. Severity is driven by context and victim: a
self-XSS is Low; stored XSS hitting other users or an admin panel is High. Score by
who executes it and what it reaches (session, CSRF token, admin actions).

## Prerequisites
- A reflection point: query/path/body params, headers (Referer, User-Agent),
  filenames, or stored fields (profile, comments, support tickets).

## Methodology

### Step 1: Find reflections
Inject a unique canary (`grmnr1337`) into every parameter and locate where it
echoes — HTML body, attribute, `<script>`, URL, JSON later rendered, etc.

### Step 2: Determine context, then break out
- **HTML body:** `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`
- **Attribute:** `"><svg onload=alert(1)>` or event-handler injection `" onmouseover=alert(1) x="`
- **JS string:** `';alert(1)//` / `</script><svg onload=alert(1)>`
- **URL/href:** `javascript:alert(1)`
- **Encode to beat filters:** HTML entities, `\u` escapes, double-encoding, mixed case, `<svG>`.

### Step 3: Stored XSS
Submit the payload to persisted fields; then load the page **as the victim role**
(different account / admin view) to confirm it executes there, not just for you.

### Step 4: DOM XSS
Trace `location`/`document.URL`/`postMessage`/`localStorage` (sources) into
`innerHTML`/`eval`/`document.write`/jQuery `.html()` (sinks). Use the headless
browser to confirm client-side execution (Caido alone won't render it).

## Payloads / wordlists
PortSwigger XSS cheat sheet; `specter/wordlists/` (add `xss-payloads.txt`).

## Validate (negative control)
- **Attack:** capture the payload actually **executing** — a screenshot of the
  `alert`/DOM change, or an out-of-band hit (blind XSS to your collaborator).
- **Negative control:** show the canary WITHOUT the breakout stays inert (encoded /
  text-only). That proves the breakout, not just reflection. Reflection != XSS.

## Evidence to capture
The request with payload + a **screenshot** of execution (use `--method screenshot`),
or the blind-XSS callback. For stored, capture the victim-context render.

## False-positive traps
- Reflection that is HTML-encoded on output (inert) — not XSS.
- Execution only in your own session with no victim path (self-XSS) — Low.
- A CSP that actually blocks the script (test whether your vector bypasses it).

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote to `confirmed` only after the screenshot/out-of-band proof above, via `scripts/validate-finding.sh`. Self-XSS or encoded reflections do not ship.

**Produce the proof with the harness, then promote from it.** The primitive writes
`$PROJECT_DIR/evidence/<id>/*.json`; `--from-evidence` reads that record and promotes
only if it says `confirmed`, carrying the class, control and method across:

```bash
# 1. record the class up front so the evidence gate arms itself
bash scripts/finding.sh --project-dir "$PROJECT_DIR" --agent specter --severity high \
  --title '<what you proved>' --description '<...>' --impact '<...>' --class xss

# 2. produce the proof
python3 scripts/confirm/render-confirm.py --finding-id SPE-NNN --project-dir "$PROJECT_DIR" \
  --url 'https://TARGET/search?q=PAYLOAD' --cookie "session=$SESSION"

# 3. promote from the artifact
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --from-evidence
```

Promoting by hand below is the fallback for when the harness cannot reach the target.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method screenshot --method out-of-band \
  --negative-control "payload executes (screenshot); plain canary renders HTML-encoded/inert" --by specter
```
