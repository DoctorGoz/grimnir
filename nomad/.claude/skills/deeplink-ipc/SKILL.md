---
name: deeplink-ipc
description: Exported component & deeplink/URL-scheme abuse (Android IPC, iOS universal links). MOB05/06. Reach internal screens/actions from another app or a web page.
allowed-tools: Read, Grep, Glob, Bash
---

# Deeplink & IPC Abuse Skill (MOB05/06)

Exported activities/services/receivers/content-providers and deeplinks/URL schemes
are the app's external attack surface. Goal: invoke privileged functionality, bypass
auth, inject parameters, or read provider data from an unprivileged context.

## Prerequisites
- Manifest analysis from `apk-static-analysis` (exported components + intent filters,
  custom URL schemes, `assetlinks.json` / `apple-app-site-association`).

## Methodology

### Step 1: Enumerate the surface
Exported `activity`/`service`/`receiver`/`provider` (`android:exported="true"` or
implicit via intent-filter), custom schemes (`myapp://`), App Links / Universal Links.

### Step 2: Invoke exported components (Android, via adb)
```bash
adb shell am start -n com.acme.app/.SecretActivity                 # direct launch
adb shell am start -a android.intent.action.VIEW -d "myapp://reset?token=x"
adb shell content query --uri content://com.acme.app.provider/users  # provider read
```
From a separate unprivileged app, attempt the same to model a real attacker.

### Step 3: Deeplink parameter abuse
Inject into deeplink params: open-redirect/webview XSS (if a deeplink loads a URL in
a WebView → chain to Specter `xss`), auth-token handling, IDOR via id params,
bypassing the login screen by deep-linking past it.

### Step 4: Content provider issues
Unprotected providers (data read/write), path-traversal in provider file access,
SQL injection in provider query selection.

## Payloads / wordlists
`nomad/wordlists/deeplink-schemes.txt`.

## Validate (negative control)
- **Attack:** show a concrete impact reached externally — internal screen opened
  without auth, provider data read from another app/`adb`, a deeplink param causing
  account action.
- **Negative control:** a properly-protected component rejects the same external
  invocation (permission denied / requires signature). Proves the exported one is the gap.

## Evidence to capture
The `am start`/`content query`/deeplink invocation, the resulting access (screenshot
or data), and the denied control.

## False-positive traps
- Exported component that immediately checks auth/permission internally (no impact).
- Provider exported but `android:permission`-protected.
- Deeplink that loads only trusted content with validated params.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after an external invocation yields real impact with a negative control.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nomad \
  --id NOM-NNN --state confirmed --method manual-repro --method negative-control \
  --negative-control "adb content query on exported provider dumps user rows; a permission-protected provider returns SecurityException" --by nomad
```
