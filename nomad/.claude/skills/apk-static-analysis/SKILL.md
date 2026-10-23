---
name: apk-static-analysis
description: APK/IPA static analysis — decompile, manifest, hardcoded secrets, endpoints, weak crypto. MOB01/07/10. The richest source of backend attack surface.
allowed-tools: Read, Grep, Glob, Bash
---

# APK Static Analysis Skill (MOB01/07/10)

Decompile the app and mine it for secrets, backend endpoints, weak crypto, and
dangerous config. Static analysis usually yields the leads the other agents exploit.

## Prerequisites
- The APK/IPA (`scripts/pull-apk.sh <package.id>` for installed Android apps,
  including split APKs) and the package/bundle id confirmed in scope.

## Methodology

### Step 1: Decompile
```bash
~/tools/jadx/bin/jadx -d out/ app.apk            # Java/Kotlin source
apktool d app.apk -o smali/                       # manifest + resources + smali
```

### Step 2: Manifest review
`minSdk`/`targetSdk`, `android:debuggable`, `allowBackup`, `usesCleartextTraffic`,
`networkSecurityConfig`, exported components, custom permissions, deeplink/intent
filters (hand exported/deeplink details to `deeplink-ipc`).

### Step 3: Secrets & endpoints
```bash
grep -rEi 'api[_-]?key|secret|token|password|AKIA|firebaseio|s3\.amazonaws' out/
```
Collect base URLs, API paths, third-party keys, Firebase configs, cloud buckets.
Check `strings.xml`, `assets/`, `res/raw/`, BuildConfig, and `.so` libs.

### Step 4: Crypto & storage hints
Hardcoded keys/IVs, ECB mode, weak hashing (MD5/SHA1 for auth), custom crypto;
note where data is stored (prefs/SQLite/files) for `storage-secrets`.

### Step 5: Route, don't just collect
Endpoints → Specter; cloud keys/buckets → Nimbus; AI endpoints → ARTEMIS.

## Payloads / wordlists
`nomad/wordlists/secret-patterns.txt`.

## Validate (negative control)
- **Attack:** for a secret/endpoint, prove it is LIVE — the key authenticates to the
  backend, or the endpoint returns data. For crypto, show the key actually decrypts
  real app data.
- **Negative control:** a revoked/garbage key of the same shape is rejected; a
  random endpoint 404s. Distinguishes a live secret from a dead/placeholder string.

## Evidence to capture
The decompiled location of the secret/endpoint (redacted) + the authenticating
request/response proving impact + the negative control.

## False-positive traps
- Example/test/placeholder keys; client ids that are meant to be public (OAuth public client).
- Endpoints that require additional server-side auth (key alone insufficient).
- Third-party SDK secrets for an OUT-OF-SCOPE service.

## Validate & Promote

Findings from this skill are born `theoretical` (see the repo-root `CLAUDE.md`). Promote via `scripts/validate-finding.sh` only after proving the secret/endpoint is live and impactful. Chain backend exploitation to Specter/Nimbus.

```bash
bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --agent nomad \
  --id NOM-NNN --state confirmed --method manual-repro --method negative-control \
  --negative-control "strings.xml key -> 200 from api.acme.com/orders; revoked key same shape -> 401" --by nomad
```
