Delegate full network & infrastructure security audit to Hunter for $ARGUMENTS

## Steps
1. Verify the project directory `$PROJECT_DIR` exists and scope is defined
2. Prepare Hunter handoff payload with target, scope, rate limits, and **`project_dir`** (absolute path)
3. Delegate to hunter agent with phase: full-audit
4. Or run: `bash hunter/scripts/full-audit.sh TARGET [OPTIONS]`
5. Monitor progress via status updates
6. When complete, review findings in `$PROJECT_DIR/hunter/findings/`
7. Update engagement status

## Asset Map Integration
If `$PROJECT_DIR/asset-map.json` exists (produced by HUGINN Phase 0), include relevant sections in Hunter's handoff:
- `hosts`, `subdomains` (with resolved IPs), `certificates`
- Tell Hunter to SKIP its own discovery phase and go directly to enumeration/testing
- Include any intel items tagged `needs-hunter` from `intel.jsonl`

## Hunter Phases
1. Host Discovery & Port Scanning
2. Service Detection & Version Fingerprinting
3. Vulnerability Scanning (nuclei + nmap NSE + searchsploit)
4. Credential Testing (default creds, spraying)
5. Service Exploitation (validated PoC only)
6. Privilege Escalation Checks
7. Report Generation

## State Integration
Before delegating, update state: `bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent hunter --phase discover --status in_progress`
After completion, check for intel: `bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent hunter`

## Intel Logging — MANDATORY in Handoff

When constructing the handoff prompt for Hunter, you MUST include instructions to log cross-agent intel. Include this exact block (with correct `--agent` flag):

```
When you discover anything relevant to other agents (web services, API endpoints, AI features on hosts), you MUST log it:

bash scripts/intel.sh add \
  --project-dir "$PROJECT_DIR" \
  --agent hunter \
  --type service --confidence confirmed \
  --host 10.10.10.50 --port 443 --protocol tcp \
  --service-name nginx --service-version "1.24.0" \
  --tag needs-specter

MANDATORY: Log at least 3 intel items during the engagement. Do this AS YOU FIND things, not at the end.
```

**IMPORTANT**: The flag is `--agent`, NOT `--source`. Always include the RESOLVED `"project_dir"` (the absolute value of `$PROJECT_DIR`, e.g. `/home/you/workspace/acme-corp`) in the handoff payload — never a string still containing `$GRIMNIR_WORKSPACE` or `~`, which the specialist would take literally.
