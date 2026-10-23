Delegate full mobile application security audit to Nomad for $ARGUMENTS

## Steps
1. Verify the project directory `$PROJECT_DIR` exists and scope is defined
2. **Confirm the app package / bundle id is in scope** (beware the out-of-scope-app trap: bundled SDKs and sister apps may be OOS)
3. Acquire the app: `bash scripts/pull-apk.sh <package.id> "$PROJECT_DIR/apk/<package.id>"` (Android, needs adb) or supply the APK/IPA
4. Prepare Nomad handoff payload with target (package id / app), scope, test accounts, and **`project_dir`** (absolute path)
5. Delegate to nomad agent with phase: full-audit
6. Monitor progress via status updates
7. When complete, review findings in `$PROJECT_DIR/nomad/findings/`
8. Update engagement status

## The mobile app is a window onto the backend
Route every discovered backend endpoint to Specter and every cloud key/bucket to
Nimbus via the intel feed. Many mobile findings (hardcoded key, MITM-able traffic)
become backend findings when chained.

## Asset Map Integration
If `$PROJECT_DIR/asset-map.json` exists, include in Nomad's handoff:
- App-link metadata (`assetlinks.json`, `apple-app-site-association`), deeplink schemes, store links
- Any intel items tagged `needs-nomad` from `intel.jsonl`

## Nomad Phases
1. Acquire (pull APK/IPA incl. splits)
2. Static (decompile, manifest, secrets, endpoints, crypto)
3. Rig (emulator/device + Caido CA MITM)
4. Dynamic (intercept traffic, insecure storage, logs, session)
5. Instrument (Frida/objection: pinning bypass, control bypass)
6. Report Generation

## State Integration
Before delegating: `bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent nomad --phase static --status in_progress`
After completion: `bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent nomad`

## Intel Logging — MANDATORY in Handoff

Include this block (correct `--agent` flag) in the handoff prompt:

```
When you discover anything relevant to other agents (backend endpoints, cloud keys, AI features, internal hosts, hardcoded credentials), you MUST log it:

bash scripts/intel.sh add \
  --project-dir "$PROJECT_DIR" \
  --agent nomad \
  --type endpoint --confidence high \
  --url "https://api.acme.com/v1/orders" --method GET \
  --tag needs-specter --tag high-value

MANDATORY: Log intel AS YOU FIND things, not at the end.
```

**IMPORTANT**: The flag is `--agent`, NOT `--source`. Always include the RESOLVED `"project_dir"` (the absolute value of `$PROJECT_DIR`, e.g. `/home/you/workspace/acme-corp`) in the handoff payload — never a string still containing `$GRIMNIR_WORKSPACE` or `~`, which the specialist would take literally.
