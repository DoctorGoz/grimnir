Delegate full API & web security audit to Specter for $ARGUMENTS

## Steps
1. Verify the project directory `$PROJECT_DIR` exists and scope is defined
2. Prepare Specter handoff payload with target, scope, auth, rate limit, and **`project_dir`** (absolute path)
3. Delegate to specter agent with phase: full-audit
4. Or run: `bash specter/scripts/full-audit.sh TARGET [TOKEN]`
5. Monitor progress via status updates
6. When complete, review findings in `$PROJECT_DIR/specter/findings/`
7. Update engagement status

## Asset Map Integration
If `$PROJECT_DIR/asset-map.json` exists (produced by HUGINN Phase 0), include relevant sections in Specter's handoff:
- `endpoints`, `technologies`, `auth_mechanisms`, `waf`, `js_analysis`
- Tell Specter to SKIP its own recon phase and go directly to testing
- Include any intel items tagged `needs-specter` from `intel.jsonl`

## Specter Phases
1. WAF Detection
2. Crawling & JS Analysis
3. Endpoint Discovery & Fuzzing
4. OpenAPI/Swagger Spec Analysis
5. Nuclei Scanning
6. Auth/AuthZ Testing
7. Injection Testing
8. GraphQL/gRPC Testing (if applicable)
9. Report Generation

## State Integration
Before delegating, update state: `bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent specter --phase recon --status in_progress`
After completion, check for intel: `bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent specter`

## Intel Logging — MANDATORY in Handoff

When constructing the handoff prompt for Specter, you MUST include instructions to log cross-agent intel. Include this exact block (with correct `--agent` flag):

```
When you discover anything relevant to other agents (AI/LLM endpoints, network services, infrastructure details), you MUST log it:

bash scripts/intel.sh add \
  --project-dir "$PROJECT_DIR" \
  --agent specter \
  --type endpoint --confidence high \
  --url "https://example.com/ai/chat" --method POST \
  --tag needs-artemis

MANDATORY: Log at least 3 intel items during the engagement. Do this AS YOU FIND things, not at the end.
```

**IMPORTANT**: The flag is `--agent`, NOT `--source`. Always include the RESOLVED `"project_dir"` (the absolute value of `$PROJECT_DIR`, e.g. `/home/you/workspace/acme-corp`) in the handoff payload — never a string still containing `$GRIMNIR_WORKSPACE` or `~`, which the specialist would take literally.
