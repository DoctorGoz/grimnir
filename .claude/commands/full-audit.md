Run combined security audit against $ARGUMENTS

Orchestrates HUGINN (recon) and all applicable specialist agents for comprehensive coverage.

## Steps

1. Verify the project directory `$PROJECT_DIR` exists with scope and classification
2. Determine target layers:
   - Infrastructure layer (for Hunter)
   - API/web layer endpoints (for Specter)
   - AI/LLM endpoints (for ARTEMIS)

3. **Phase 0: Unified Reconnaissance (HUGINN)** — ALWAYS runs first
   - Delegate to huginn agent (foreground, wait for completion)
   - HUGINN runs: `bash huginn/scripts/recon-pipeline.sh TARGET --project-dir "$PROJECT_DIR"`
   - Then builds: `bash huginn/scripts/asset-map.sh --project-dir "$PROJECT_DIR" --target TARGET`
   - Produces: `$PROJECT_DIR/asset-map.json` + pre-populated `$PROJECT_DIR/intel.jsonl`
   - All raw recon data goes to `$PROJECT_DIR/recon/`

4. **Phase 1: Launch Specialists (parallel) + HUGINN Correlator (background)**
   - Read `$PROJECT_DIR/asset-map.json` and include relevant sections in each specialist's handoff
   - Read `$PROJECT_DIR/intel.jsonl` for routed discoveries
   - Launch applicable specialists in parallel:
     - Hunter: infrastructure audit (if network targets in scope)
     - Specter: API/web audit (if web/API targets in scope)
     - ARTEMIS: GenAI audit (if AI features detected)
     - Nimbus: cloud/IaaS audit (if cloud account/storage/serverless/K8s in scope)
     - Nomad: mobile audit (if an APK/IPA / mobile app is in scope)
   - Launch HUGINN correlator in background:
     `bash huginn/scripts/correlator.sh --project-dir "$PROJECT_DIR" --interval 30`

5. **Phase 2: Cross-Domain Testing**
   - After specialists complete, review cross-agent intel
   - Test attack chains that span multiple layers
   - This phase is orchestrated by GRIMNIR directly

6. **Phase 3: Unified Reporting**
   - Delegate to report-compiler agent
   - Merge all findings, deduplicate, identify chains
   - Generate unified report

## Specialist Handoff with Asset Map

When launching specialists AFTER HUGINN completes, include asset map data in each handoff:

```
## HUGINN Recon Results (Phase 0)

An asset map has been generated at $PROJECT_DIR/asset-map.json. Key findings:
[paste relevant sections from asset-map.json]

Pre-populated intel entries are in $PROJECT_DIR/intel.jsonl.
Check for items tagged needs-<your-agent>:
bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent <agent-name>

SKIP your own recon phase — HUGINN already completed it. Go directly to testing.
```

## State & Intel Integration

**Before each phase**, update engagement state:
```bash
# Phase 0: HUGINN recon
bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent huginn \
  --phase recon --status in_progress --progress 0.1

# Phase 1: Specialists
bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent specter \
  --phase assessment --status in_progress --progress 0.1

# Between phases, route intel to the next agent:
bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent specter
bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent artemis
bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent nimbus
bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent nomad
```

**After each agent completes**, check for cross-agent intel before starting the next phase. Intel tagged `needs-specter`, `needs-artemis`, `needs-hunter`, `needs-nimbus`, or `needs-nomad` should be passed to the respective agent.

**After reporting**, mark engagement complete:
```bash
jq '.report_generated = true | .report_path = "report.md"' "$PROJECT_DIR/state.json" > tmp.$$.json && mv tmp.$$.json "$PROJECT_DIR/state.json"
```

## Intel Logging — MANDATORY in Every Handoff

Every agent handoff prompt MUST include intel logging instructions with:
1. The correct flag: `--agent` (NOT `--source`)
2. A concrete example using the correct agent name
3. A MANDATORY minimum of 3 intel items per agent per engagement
4. Instruction to log intel AS THEY FIND things, not at the end

Example block to include in each agent's handoff:
```
MANDATORY INTEL LOGGING: You MUST log cross-agent discoveries using:
bash scripts/intel.sh add \
  --project-dir "$PROJECT_DIR" \
  --agent <your-agent-name> \
  --type <endpoint|service|technology|vulnerability_hint|note> \
  --confidence <confirmed|high|medium|low> \
  [type-specific flags] \
  --tag <needs-specter|needs-artemis|needs-hunter|high-value>

Log at least 3 intel items during testing. Do this AS YOU FIND things.
```

**IMPORTANT**: ALL agent delegations MUST include the RESOLVED `"project_dir"` (the absolute value of `$PROJECT_DIR`) in the handoff payload — never a string still containing `$GRIMNIR_WORKSPACE` or `~`. All output saved to `$PROJECT_DIR/`.
