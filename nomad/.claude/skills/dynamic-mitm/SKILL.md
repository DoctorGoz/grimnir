---
name: dynamic-mitm
description: Dynamic traffic interception (MITM) for mobile apps. MOB03. Capture and test the app's live API traffic through Caido.
allowed-tools: Read, Grep, Glob, Bash
---

# Dynamic MITM Skill (MOB03)

Route the app's traffic through a proxy to see and manipulate the live API calls.
This turns the mobile engagement into an API engagement (hand off to Specter/Nimbus)
and reveals cleartext / weak-TLS issues.

## Prerequisites
- A controlled device or the rooted emulator rig with the Caido CA installed as a
  system/user trust anchor (see `mitm-setup.sh` and the rig runbook).

## Methodology

### Step 1: Bring up the rig + proxy
Start the emulator/device, set the HTTP proxy to Caido, install the Caido CA. For
Android 7+, system-trust the CA (AlwaysTrustUserCerts / Magisk module) since apps
ignore user CAs by default.

### Step 2: Drive the app, capture traffic
Exercise login, core flows, and sensitive actions. In Caido (`caido-mode` skill),
filter by the app's hosts and review request/response history.

### Step 3: Find transport flaws
Cleartext HTTP, TLS without cert/host validation (set proxy without pinning bypass —
if traffic still flows, validation is weak), sensitive data in URLs/headers,
tokens that don't rotate.

### Step 4: If traffic doesn't appear
Likely certificate pinning → hand to `cert-pinning-bypass`. Confirm it's pinning
(not just a proxy misconfig) before reporting pinning as present.

### Step 5: Hand off
Captured endpoints + auth → Specter (`bola`/`auth`/`injection`), cloud calls → Nimbus.

## Validate (negative control)
- **Attack:** capture decrypted sensitive traffic through the proxy (proof the
  channel is interceptable), or show a tampered request changes server behavior.
- **Negative control:** a properly-pinned app of the same vendor refuses to connect
  through the proxy — showing this app's traffic is genuinely interceptable, not a
  test artifact.

## Evidence to capture
Caido request/response showing the decrypted sensitive traffic (export curl for
PoC), the proxy/CA setup used, and the tamper result if applicable.

## False-positive traps
- You only saw traffic because YOU disabled pinning — note pinning WAS present (lower sev).
- The "cleartext" was to a non-sensitive CDN/analytics host.
- Emulator-only behavior that differs from a real device.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after capturing decrypted sensitive traffic (or a confirmed tamper).

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nomad \
  --id NOM-NNN --state confirmed --method manual-repro \
  --negative-control "login captured in cleartext via proxy with NO pinning bypass; a pinned sibling app refuses the proxy" --by nomad
```
