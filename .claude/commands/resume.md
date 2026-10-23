Resume a paused or interrupted engagement for $ARGUMENTS

Reads checkpoint data from state.json and intel from intel.jsonl to build a context-aware handoff that lets agents pick up exactly where they left off.

## Steps

1. **Identify the project** — use `$ARGUMENTS` as project name, or detect from current context:
   ```bash
   PROJECT_DIR="${GRIMNIR_WORKSPACE:-$HOME/workspace}/$PROJECT_NAME"
   ```

2. **Verify state exists**:
   ```bash
   test -f "$PROJECT_DIR/state.json" || echo "ERROR: No state.json — this engagement has no state tracking. Use /engage to start fresh."
   ```

3. **Read engagement state**:
   ```bash
   bash scripts/state.sh summary --project-dir "$PROJECT_DIR"
   ```

4. **Determine which agents need resuming** — check each agent's status:
   ```bash
   # Get per-agent status
   bash scripts/state.sh get --project-dir "$PROJECT_DIR" --field '.agents | to_entries[] | select(.value.status != "completed" and .value.status != "not_started") | {agent: .key, phase: .value.phase, status: .value.status, progress: .value.progress, next_action: .value.next_action}'
   ```

   Resume logic:
   - `in_progress` → resume from checkpoint
   - `blocked` → show blocker, ask operator how to proceed
   - `not_started` → skip (not yet assigned) unless operator requests
   - `completed` → skip

5. **Load checkpoint data** for each resuming agent:
   ```bash
   # Example for specter
   bash scripts/state.sh get --project-dir "$PROJECT_DIR" --field '.checkpoints.specter'
   ```

   Key fields to extract:
   - `last_completed_action` — what was done last
   - `completed_tests[]` — categories already tested (e.g., API1, API2)
   - `pending_tests[]` — categories still to test (e.g., API3, API4)
   - `discovered_targets[]` — new targets found during recon

6. **Check intel queue** for unprocessed items routed to the resuming agent:
   ```bash
   bash scripts/intel.sh route --project-dir "$PROJECT_DIR" --for-agent specter
   ```

7. **Build resume handoff payload** — extend the standard handoff with checkpoint context:
   ```json
   {
     "engagement_id": "ENG-...",
     "project_dir": "/home/you/workspace/project-name",
     "target": { ... },
     "scope": { ... },
     "resume_from_checkpoint": true,
     "checkpoint": {
       "last_completed_action": "Completed BOLA testing on /api/v1/users",
       "completed_tests": ["API1", "API2"],
       "pending_tests": ["API3", "API4", "API5", "API6", "API7", "API8", "API9", "API10"],
       "discovered_targets": ["https://target.com/api/v2/admin"]
     },
     "unprocessed_intel": [
       { "type": "endpoint", "url": "...", "source_agent": "hunter" }
     ],
     "resume_intent": "continue",
     "authorization": "confirmed"
   }
   ```

8. **Delegate to agent(s)** with the resume payload

9. **Log resume event** in phase history:
   ```bash
   bash scripts/state.sh update --project-dir "$PROJECT_DIR" --agent specter \
     --status in_progress --next-action "Resumed from checkpoint"
   ```

## Resume Modes

If `$ARGUMENTS` includes a specific agent name, resume only that agent:
- `/resume acme-corp` — resume all in-progress agents
- `/resume acme-corp specter` — resume only Specter
- `/resume acme-corp hunter` — resume only Hunter

## Display Format

Show the operator what's being resumed before delegating:

```
Resuming engagement: acme-corp
Directory: /home/you/workspace/acme-corp

Specter (API/Web):
  Phase: test | Progress: 60%
  Last action: Completed BOLA testing on /api/v1/users
  Completed: API1, API2 (2/10)
  Pending: API3, API4, API5, API6, API7, API8, API9, API10
  Intel queue: 3 items from Hunter

Resuming Specter with continue intent...
```
