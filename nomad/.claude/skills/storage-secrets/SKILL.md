---
name: storage-secrets
description: Insecure local storage, logging, and session handling on device. MOB02/08. Find sensitive data written in the clear on the device.
allowed-tools: Read, Grep, Glob, Bash
---

# Insecure Storage & Session Skill (MOB02/08)

Apps often persist sensitive data (tokens, PII, card data) insecurely on device.
Goal: recover sensitive data from the device's app storage, logs, or backups, and
assess session/token handling.

## Prerequisites
- Rooted device / rig with the app installed and exercised (logged in, used flows).

## Methodology

### Step 1: Inspect app data directory
```bash
adb shell run-as com.acme.app ls -R /data/data/com.acme.app/
```
Check `shared_prefs/*.xml` (plaintext tokens/flags), `databases/*.db` (open with
sqlite3 — unencrypted SQLCipher?), `files/`, `cache/`.

### Step 2: External storage & backups
World-readable files on external storage; `allowBackup=true` → `adb backup` and
extract (Android), iOS file protection class / Keychain accessibility.

### Step 3: Logs & clipboard
`adb logcat` while using the app — secrets/tokens/PII logged? Sensitive data copied
to the clipboard or shown in screenshots/recents (no FLAG_SECURE).

### Step 4: Session & token handling
Where are auth tokens stored (prefs vs Keystore/Keychain)? Do they expire / rotate?
Is biometric-gated data actually protected, or just UI-gated?

## Methodology — Keystore note
Data "encrypted" with a key that's also on-device (hardcoded or derivable) is not
protected. Verify keys are in the hardware-backed Keystore/Keychain, not in code.

## Validate (negative control)
- **Attack:** recover actual sensitive data (a live session token, PII, card data)
  from device storage/logs/backup, and show it is usable (token authenticates).
- **Negative control:** a properly-secured field (e.g. one in the Keystore) is NOT
  recoverable the same way. Distinguishes a real exposure from expected behavior.

## Evidence to capture
The file/log path + recovered data (redacted), and proof of usability (e.g. the
extracted token authenticates to the backend). Note storage mechanism.

## False-positive traps
- "Token in prefs" that is short-lived and useless once expired (lower sev).
- Data that is actually Keystore-encrypted (key not on device).
- Non-sensitive cached data flagged as a leak.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after recovering usable sensitive data with a negative control.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nomad \
  --id NOM-NNN --state confirmed --method manual-repro \
  --negative-control "shared_prefs holds plaintext session JWT; replays to api.acme.com OK; a Keystore-held key is not extractable the same way" --by nomad
```
