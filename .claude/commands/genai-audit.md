Delegate full GenAI/LLM security audit to ARTEMIS for $ARGUMENTS

## Steps
1. Verify the project directory `$PROJECT_DIR` exists and scope is defined
2. Prepare ARTEMIS handoff payload with target, scope, API key, rate limit, and **`project_dir`** (absolute path)
3. Delegate to artemis agent with phase: full-audit
4. Or run: `bash artemis/scripts/full-genai-audit.sh TARGET [API_KEY] [ENG_ID]`
5. Monitor progress via status updates
6. When complete, review findings in `$PROJECT_DIR/artemis/findings/`
7. Update engagement status

## Asset Map Integration
If `$PROJECT_DIR/asset-map.json` exists (produced by HUGINN Phase 0), include relevant sections in ARTEMIS's handoff:
- `ai_indicators`, `endpoints` (AI-related), `technologies` (AI category)
- Tell ARTEMIS to SKIP its own recon phase and go directly to testing
- Include any intel items tagged `needs-artemis` from `intel.jsonl`

## ARTEMIS Phases
1. Reconnaissance & Model Fingerprinting
2. System Prompt Extraction
3. Prompt Injection Testing
4. Guardrail Assessment
5. Data Extraction Testing
6. Agent Tool Enumeration (if agentic)
7. Output Handling Testing
8. Report Generation

## State Integration
Before delegating, update state: `bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent artemis --phase recon --status in_progress`
After completion, check for intel: `bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent artemis`

## Intel Logging — MANDATORY in Handoff

When constructing the handoff prompt for ARTEMIS, you MUST include instructions to log cross-agent intel. Include this exact block (with correct `--agent` flag):

```
When you discover anything relevant to other agents (API endpoints, auth tokens in AI responses, exposed services, infrastructure details), you MUST log it:

bash scripts/intel.sh add \
  --project-dir "$PROJECT_DIR" \
  --agent artemis \
  --type vulnerability_hint --confidence medium \
  --hint "System prompt reveals admin API at /admin/users" \
  --affected "https://target.com/admin/users" \
  --tag needs-specter

MANDATORY: Log at least 3 intel items during the engagement. Do this AS YOU FIND things, not at the end.
```

**IMPORTANT**: The flag is `--agent`, NOT `--source`. Always include the RESOLVED `"project_dir"` (the absolute value of `$PROJECT_DIR`, e.g. `/home/you/workspace/acme-corp`) in the handoff payload — never a string still containing `$GRIMNIR_WORKSPACE` or `~`, which the specialist would take literally.
