---
name: frida-instrumentation
description: Runtime instrumentation with Frida/objection — bypass root/jailbreak & tamper detection, hook auth/crypto, manipulate client-side controls. MOB09.
allowed-tools: Read, Grep, Glob, Bash
---

# Frida Instrumentation Skill (MOB09)

Hook the running app to bypass client-side controls and observe/alter internals.
The finding is a **security control that relies on the client** being defeatable
(root/jailbreak detection, tamper checks, client-side auth/limits), or a secret/key
recovered at runtime.

## Prerequisites
- Rooted device / rig, Frida server matching the Frida client version, objection.

## Methodology

### Step 1: Attach
```bash
frida-ps -U                                  # confirm app is visible
objection -g <package> explore
```

### Step 2: Bypass client-side defenses
Root/jailbreak detection (`android root detection bypass`), emulator detection,
debugger/tamper checks, screenshot/Frida-detection. Note each defeated control.

### Step 3: Hook for secrets / logic
Hook crypto (`android hooking watch class javax.crypto.Cipher`) to capture
keys/plaintext, dump in-memory tokens, intercept auth decisions, flip
client-side feature flags / paywalls / OTP-verified booleans.

### Step 4: Assess real impact
Client-side control bypass matters only if the server doesn't re-enforce it. If the
backend independently validates, the client bypass is low/Info — verify server-side.

## Validate (negative control)
- **Attack:** demonstrate the control defeated AND a resulting security impact (e.g.
  premium unlocked AND the server honors it; OTP check bypassed AND login succeeds).
- **Negative control:** the server rejects the tampered action when client checks are
  re-enforced server-side — if so, the client bypass alone is low severity. State which.

## Evidence to capture
The Frida/objection commands, the defeated control, and the server-side outcome
(does the backend accept the tampered state?).

## False-positive traps
- Bypassing a client check the server also enforces (no real impact).
- Recovering a key that is non-sensitive or rotates per session.
- Behavior only reproducible on a rooted device the threat model excludes.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after showing the bypass yields a server-honored impact (or a genuinely client-trusted control).

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nomad \
  --id NOM-NNN --state confirmed --method manual-repro \
  --negative-control "Frida flips 'otpVerified'; backend accepts login (server-trusted client flag); control account without hook is blocked" --by nomad
```
