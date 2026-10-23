---
name: js-analysis
description: JavaScript analysis — extract endpoints, secrets, and client-side logic from JS bundles. HUGINN Phase 4. A top source of hidden API surface.
allowed-tools: Read, Grep, Glob, Bash
---

# JavaScript Analysis Skill (HUGINN Phase 4)

Modern SPAs ship their API surface in JS. Parsing bundles reveals hidden
endpoints, parameter names, feature flags, and sometimes live secrets.

## Methodology

### Step 1: Run the JS pipeline
The dedicated JS analysis pipeline handles collection, download, beautification,
endpoint extraction, secret hunting, and fingerprinting in one pass:

```bash
bash huginn/scripts/js-pipeline.sh --project-dir "$PROJECT_DIR" --target "$TARGET"
```

This replaces manual per-URL curl+linkfinder loops with systematic multi-phase
analysis. Output files are annotated with source file references.

### Step 2: Review extracted endpoints
Pipeline output: `$PROJECT_DIR/recon/js-endpoints.txt` — each endpoint annotated
with its source JS file and approximate line number. Look for API base URLs,
route templates, GraphQL operations, and internal hostnames.

### Step 3: Review discovered secrets
Pipeline output: `$PROJECT_DIR/recon/js-secrets.txt` — secrets annotated with
source. **Note and route — do NOT exploit.** Validate liveness is a specialist's job.

### Step 4: Review configs and fingerprints
Pipeline output: `$PROJECT_DIR/recon/js-interesting.txt` (configs/Firebase/S3 URLs)
and `$PROJECT_DIR/recon/js-stack.json` (detected frameworks/bundlers/libraries).
Route configs to the appropriate specialist.

## Output to record
js_analysis: endpoints[], secrets[] (redacted), interesting strings → asset map.

## Log & Route
HUGINN produces **intel and an asset map**, not findings. Log discovered endpoints/secrets and route them.

```bash
bash scripts/intel.sh add --project-dir "$PROJECT_DIR" --agent huginn \
  --type credential --confidence high --name "AWS key in app.js (unverified)" \
  --tag needs-specter --tag needs-nimbus --tag high-value
```
Cloud keys/buckets → `needs-nimbus`; API endpoints → `needs-specter`; Firebase/app config → `needs-nomad`; AI endpoints → `needs-artemis`. Always mark secrets `high-value`. (cloud/mobile tags apply once those agents are enabled.)
