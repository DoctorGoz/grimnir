Situation report — strategic engagement overview across all agents

## Steps
1. Identify the project directory `$PROJECT_DIR` for the current or specified engagement
2. **If `state.json` exists**, use the structured state system:
   ```bash
   bash scripts/state.sh summary --project-dir "$PROJECT_DIR"
   ```
   Then show intel routing queue and unprocessed items:
   ```bash
   bash scripts/intel.sh summary --project-dir "$PROJECT_DIR"
   bash scripts/intel.sh route --project-dir "$PROJECT_DIR"
   ```
   Then run the coverage reconciler and surface any high-value recon that never reached a terminal state:
   ```bash
   python3 scripts/coverage.py --project-dir "$PROJECT_DIR"
   ```
   Read out the **REACHABLE + UNTOUCHED** list explicitly — those are in-scope assets or high-value intel items that recon found but no agent has tested, consciously skipped, or hit a gate on. They are the highest-signal "what next" candidates and the whole point of the situation report (Rule 25).
   Then check for proof that is already on disk but not yet promoted:
   ```bash
   bash scripts/validate-finding.sh --project-dir "$PROJECT_DIR" --scan
   ```
   Anything listed here is a finished lane that has not been filed. A confirmed artifact
   sitting beside a `theoretical` finding is the cheapest win available and the easiest
   to lose -- duplicates are decided in hours (hunting Rule 29). Promote each with
   `--from-evidence` before opening anything new. If a bare legacy id reports AMBIGUOUS,
   two findings share it; read the artifact's reproducer to see which one it belongs to.


3. **If `state.json` does NOT exist** (legacy engagement), fall back to file counting:
   - Read `$PROJECT_DIR/scope.md` for engagement context
   - Read `$PROJECT_DIR/classification.md` for target type
   - Count findings in `$PROJECT_DIR/specter/findings/`, `$PROJECT_DIR/artemis/findings/`, and `$PROJECT_DIR/hunter/findings/`
   - Check for `$PROJECT_DIR/report.md` (completed?)

4. Provide strategic analysis:
   - Which agents are blocked or behind schedule?
   - Are there high-value intel items waiting to be routed?
   - Are there cross-domain attack chains emerging from the findings?
   - What's the recommended next action?

5. Display comprehensive status with recommendations for next steps
