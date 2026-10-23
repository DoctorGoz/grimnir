---
name: file-upload
description: Insecure file upload testing (CWE-434, WSTG-BUSL-09). Use on any avatar/document/import upload to reach RCE, stored XSS, SSRF, or overwrite.
allowed-tools: Read, Grep, Glob, Bash
---

# Insecure File Upload Skill (CWE-434)

Uploads chain into many outcomes: web-shell RCE, stored XSS (HTML/SVG), SSRF/XXE
(via parsed formats), path traversal overwrite, or DoS. The finding is the
**reachable consequence**, not "it accepted a .php".

## Prerequisites
- An upload endpoint and knowledge of where files are served from (path, host, CDN).

## Methodology

### Step 1: Baseline
Upload a benign file; note the stored path, filename transformation, content-type,
and whether the file is served back from a web-executable location.

### Step 2: Defeat type checks
- Extension: `.php`, `.phtml`, `.php5`, `.asp;.jpg`, double `shell.php.jpg`, case `.PHp`, trailing dot/space/`%00`.
- Content-Type spoof: send `image/png` with script bytes.
- Magic-byte prefix: `GIF89a;<?php ...`.
- Parser formats: SVG (XSS/XXE), XML/DOCX (XXE), images (ImageTragick), ZIP (zip-slip path traversal).

### Step 3: Path control
Try `../` in filename, absolute paths, overwriting existing files / configs.

### Step 4: Prove the consequence
- RCE: request the uploaded shell and run a harmless command (in scope, non-destructive).
- Stored XSS: load the served SVG/HTML as a victim.
- SSRF/XXE: out-of-band callback from the parser.

## Payloads / wordlists
Extension/bypass list; `specter/wordlists/`.

## Validate (negative control)
- **Attack:** demonstrate the consequence (shell output / XSS screenshot / OOB hit).
- **Negative control:** show a normal upload does NOT execute / is served with a safe
  content-type. "Accepted the file" alone is not a finding without a reachable sink.

## Evidence to capture
The upload request, the served URL, and proof of execution (command output,
screenshot, or OOB callback). Keep PoC shells inert (`phpinfo()`-class, no damage).

## False-positive traps
- File stored but served from a non-executable / sandboxed origin (no RCE).
- Extension accepted but renamed/neutralised on disk.
- "SVG accepted" with CSP/sanitisation that blocks script.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after demonstrating the reachable consequence.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro --method out-of-band \
  --negative-control "uploaded shell.php executes (cmd output); benign .png served as image/png, no execution" --by specter
```
