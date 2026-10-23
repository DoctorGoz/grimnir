---
name: cert-pinning-bypass
description: Certificate pinning bypass for mobile apps. MOB04. Defeat pinning (Frida/objection) to enable MITM — and assess whether pinning is present/robust.
allowed-tools: Read, Grep, Glob, Bash
---

# Certificate Pinning Bypass Skill (MOB04)

Pinning is a defense; bypassing it is a means (to MITM), and *weak/absent* pinning
is itself a finding. Report the security posture (no pinning = trivial MITM;
bypassable pinning = lower severity) and use the bypass to unlock `dynamic-mitm`.

## Prerequisites
- Rooted device / rig with Frida server running, objection installed, target app.

## Methodology

### Step 1: Confirm pinning is the blocker
If proxying yields no traffic, confirm it's pinning (not proxy/CA misconfig): system-
trust the CA first; if still blocked, it's likely pinning.

### Step 2: Generic bypass
```bash
objection -g <package> explore -s "android sslpinning disable"
frida -U -f <package> -l frida-multiple-unpinning.js --no-pause
```

### Step 3: App-specific pinning
If generic scripts fail, find the pinning implementation in the decompiled code
(`apk-static-analysis`): OkHttp `CertificatePinner`, TrustManager, network-security-
config `<pin-set>`, Flutter (patch the BoringSSL `ssl_verify` symbol). Hook/patch it.

### Step 4: Verify + proceed
With pinning bypassed, traffic flows to the proxy → continue in `dynamic-mitm`.

## Validate (negative control)
- **Attack:** demonstrate traffic now decrypts through the proxy after the bypass.
- **Negative control:** before the bypass, the same setup showed NO traffic (proving
  pinning was active). This distinguishes "no pinning at all" (higher severity —
  no bypass needed) from "pinning present but bypassable" (lower).

## Evidence to capture
The bypass method, before (blocked) vs after (decrypted) proxy capture, and a note
on whether pinning was absent vs present-but-bypassed (drives severity).

## False-positive traps
- Claiming "no pinning" when you actually ran a bypass script (re-test clean).
- A debug build with pinning disabled that differs from the production build.
- Bypass works only with root the real threat model wouldn't have (note assumptions).

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh`. Severity: absent pinning > bypassable pinning. Chain to the MITM/data finding it enables.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nomad \
  --id NOM-NNN --state confirmed --method manual-repro \
  --negative-control "no proxy traffic pre-bypass (pinning active); after objection unpinning, full TLS traffic decrypts" --by nomad
```
