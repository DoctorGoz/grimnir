Delegate full cloud & IaaS security audit to Nimbus for $ARGUMENTS

## Steps
1. Verify the project directory `$PROJECT_DIR` exists and scope is defined
2. **Confirm the in-scope cloud account IDs / subscriptions / projects** and that credentials provided are authorized for testing
3. Prepare Nimbus handoff payload with target (cloud account/asset), scope, credentials, and **`project_dir`** (absolute path)
4. Delegate to nimbus agent with phase: full-audit
5. Or run: `bash nimbus/scripts/cloud-recon.sh [aws|azure|gcp]`
6. Monitor progress via status updates
7. When complete, review findings in `$PROJECT_DIR/nimbus/findings/`
8. Update engagement status

## Safety — read before delegating
Cloud testing touches shared control planes. The handoff MUST instruct Nimbus to:
- Stay strictly within the confirmed in-scope account(s); no cross-tenant or provider-infrastructure testing
- Be **non-destructive**: enumerate and read only; prove access with a minimal read (`sts get-caller-identity`, one object), never bulk exfil, delete, or resource-creation sprees
- Mind cost and noise (no crypto, no DoS)

## Asset Map Integration
If `$PROJECT_DIR/asset-map.json` exists (produced by HUGINN Phase 0), include relevant sections in Nimbus's handoff:
- cloud `technologies` (provider/CDN/origin signals), bucket names, cloud keys found in JS
- Any intel items tagged `needs-nimbus` from `intel.jsonl`

## Nimbus Phases
1. Identify (provider/account, credential triage)
2. Enumerate (IAM, storage, compute, serverless, containers, secrets)
3. Assess (posture vs CIS, public exposure, over-permissive policies)
4. Escalate (IAM privesc, assume-role chains, metadata/SSRF credential theft)
5. Exploit (minimal-proof access, non-destructive)
6. Report Generation

## State Integration
Before delegating, update state: `bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent nimbus --phase identify --status in_progress`
After completion, check for intel: `bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent nimbus`

## Intel Logging — MANDATORY in Handoff

When constructing the handoff prompt for Nimbus, you MUST include instructions to log cross-agent intel. Include this exact block (with correct `--agent` flag):

```
When you discover anything relevant to other agents (web/API on cloud hosts, exposed VMs, AI services, mobile backends, leaked credentials), you MUST log it:

bash scripts/intel.sh add \
  --project-dir "$PROJECT_DIR" \
  --agent nimbus \
  --type credential --confidence confirmed \
  --name "Usable STS creds from IMDS via SSRF" \
  --tag needs-specter --tag high-value

MANDATORY: Log intel AS YOU FIND things, not at the end.
```

**IMPORTANT**: The flag is `--agent`, NOT `--source`. Always include the RESOLVED `"project_dir"` (the absolute value of `$PROJECT_DIR`, e.g. `/home/you/workspace/acme-corp`) in the handoff payload — never a string still containing `$GRIMNIR_WORKSPACE` or `~`, which the specialist would take literally.
